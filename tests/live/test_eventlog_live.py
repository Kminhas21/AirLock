"""The auditor's workflows (L1-L3) and policy-test (A1) on a log written by a REAL session: real hub, real proxy, the real filesystem server, a
scripted human, then the REAL `python -m eventlog_cli` exactly as an operator runs it. One module-scoped story, each test one step of it:
  verify / show / export agree with what the human did -> policy-test of a candidate policy against those decisions -> replay through the monitor
  -> rotate without the key is refused and moves nothing -> rotate -> verify --previous -> the hub keeps working on the rotated log
  -> a tampered copy of the archive and a missing archive are both detected."""
import shutil
import sqlite3

import pytest

from tests.harness import Agent, Backend, Operator
from tests.live import livelib
from tests.reality_fixtures import realdeps  # noqa: F401  (fixture)

pytestmark = pytest.mark.reality

SID = "audit-live"
CONTENT = "Q3 revenue summary: confidential pricing sheet for dana.whitlock@acme-corp.example"


@pytest.fixture(scope="module")
def story(realdeps, tmp_path_factory):
    """A real session: list, write (DENIED by the human), the same content to another file (approved), read it back."""
    import asyncio
    w = tmp_path_factory.mktemp("audit")
    db, allowed = w / "events.db", w / "allowed"
    allowed.mkdir()
    env = {"SENTINEL_EVENT_LOG": str(db), "SENTINEL_LOG_KEY": livelib.LOG_KEY}

    async def session():
        hub = Backend(w / "hub1.log", env)
        writes = []

        def decide(p):
            if p["tool"] == "write_file":
                writes.append(p)
                return "deny" if len(writes) == 1 else "approve"
            return "approve"
        op = await Operator.connect(hub, decide)
        agent = await Agent.start(hub, SID, {"fs": {"command": realdeps["filesystem"], "args": [str(allowed)]}}, w)
        try:
            r = [await agent.call("list_directory", {"path": str(allowed)}),
                 await agent.call("write_file", {"path": str(allowed / "q3-report.txt"), "content": CONTENT}),
                 await agent.call("write_file", {"path": str(allowed / "q3-copy.txt"), "content": CONTENT}),
                 await agent.call("read_file", {"path": str(allowed / "q3-copy.txt")})]
        finally:
            await agent.stop()
            await op.close()
            hub.stop()
        return r
    results = asyncio.run(session())
    return {"w": w, "db": db, "env": env, "allowed": allowed, "results": results, "realdeps": realdeps}


def test_L1_verify_show_and_export_agree_with_what_the_human_did(story):
    res = story["results"]
    assert not res[0]["is_error"] and res[1]["is_error"] and not res[2]["is_error"] and CONTENT in res[3]["text"]
    assert not (story["allowed"] / "q3-report.txt").exists() and (story["allowed"] / "q3-copy.txt").exists()
    code, out = livelib.cli("verify", str(story["db"]))
    assert code == 0 and "keyed" in out.splitlines()[-1] and out.splitlines()[-1].startswith("OK:"), out
    evs = livelib.events(story["db"], SID)
    props, decs = livelib.proposals(evs), livelib.decisions(evs)
    assert [p["tool"] for p in props.values()] == ["list_directory", "write_file", "write_file", "read_file"]
    assert [(decs[c]["decision"], decs[c]["actor"]) for c in props] == [("approve", "human"), ("deny", "human"), ("approve", "human"), ("approve", "human")]
    denied = list(props)[1]
    assert not any(e["kind"] == "call_result" and e["call_id"] == denied for e in evs)           # the denied write never reached the server
    code, out = livelib.cli("show", str(story["db"]), "--session", SID)
    assert code == 0 and "fs.write_file" in out and "DENY (reason human, by human)" in out and "SESSION END" in out, out


def test_A1_policy_test_compares_a_candidate_policy_with_the_logged_human_decisions(story):
    pol = story["w"] / "candidate.json"
    pol.write_text('{"version": 1, "default": "ask", "rules": [{"id": "deny-writes", "verdict": "deny", "when": {"tool": "write_file"}}]}')
    out = livelib.cli_json("policy-test", str(story["db"]), str(pol), "--session", SID)
    assert out["proposals"] == 4 and out["rule_hits"].get("deny-writes") == 2
    c = out["comparison"]
    assert c["human_decided"] == 4 and c["agree"] == 1 and c["policy_would_deny_an_approved_call"] == 1 and c["policy_would_ask"] == 2
    code, out = livelib.cli("policy-test", str(story["db"]), str(story["w"] / "no-such-policy.json"))
    assert code != 0


def test_L2_replay_re_runs_the_logged_session_through_the_monitor(story):
    rep = livelib.cli_json("replay", str(story["db"]), "--session", SID, "--monitor", "action_sim")
    assert rep["mode"] == "action_sim" and rep["summary"]["proposals"] == 4
    assert [(c["tool"], c["decision"]) for c in rep["calls"]] == [("list_directory", "approve"), ("write_file", "deny"), ("write_file", "approve"), ("read_file", "approve")]
    assert any(a["trigger"] == "denied_effect_match" for a in rep["calls"][2]["alerts"])        # the copy of the denied effect is flagged on replay
    assert livelib.run_cli("replay", str(story["db"]), "--session", "no-such-session").returncode != 0


def test_L3_rotate_needs_the_key_then_links_the_logs_and_the_hub_keeps_working(story):
    import asyncio
    w, db = story["w"], story["db"]
    before = sorted(p.name for p in w.glob("events*"))
    code, out = livelib.cli("rotate", str(db), key=None)
    assert code != 0 and "REFUSED" in out, out
    assert not list(w.glob("events-*.db")) and db.exists()                                     # refused: nothing moved
    code, out = livelib.cli("rotate", str(db))
    assert code == 0 and "rotated" in out, out
    (archive,) = list(w.glob("events-*.db"))
    assert sorted(p.name for p in w.glob("events*")) != before
    code, out = livelib.cli("verify", str(db))
    assert code == 0 and "--previous" in out, out                                               # the new log says where its history is
    code, out = livelib.cli("verify", str(db), "--previous", str(archive))
    assert code == 0 and "head matches" in out, out

    async def after():
        hub = Backend(w / "hub2.log", story["env"])
        op = await Operator.connect(hub, lambda p: "approve")
        agent = await Agent.start(hub, "after-rotation", {"fs": {"command": story["realdeps"]["filesystem"], "args": [str(story["allowed"])]}}, w)
        try:
            return await agent.call("list_directory", {"path": str(story["allowed"])})
        finally:
            await agent.stop()
            await op.close()
            hub.stop()
    assert not asyncio.run(after())["is_error"]
    kinds = [e["kind"] for e in livelib.events(db, "after-rotation")]
    assert "call_proposed" in kinds and "decision" in kinds and "call_result" in kinds
    code, out = livelib.cli("verify", str(db), "--previous", str(archive))
    assert code == 0, out                                                                       # the link holds after the hub appended more

    evil = w / "archive-tampered.db"
    shutil.copy(archive, evil)
    shutil.copy(str(archive) + ".anchor", str(evil) + ".anchor")
    c = sqlite3.connect(evil)
    n = c.execute("update events set payload=replace(payload,'\"deny\"','\"approve\"') where kind='decision'").rowcount
    c.commit()
    c.close()
    assert n >= 1                                                                               # a recorded denial is rewritten as an approval
    code, out = livelib.cli("verify", str(db), "--previous", str(evil))
    assert code != 0 and "does not verify" in out, out
    code, out = livelib.cli("verify", str(db), "--previous", str(w / "no-such-archive.db"))
    assert code != 0 and "no such file" in out, out
    code, out = livelib.cli("verify", str(db), "--previous", str(archive))
    assert code == 0, out                                                                       # the real archive is untouched by all that
