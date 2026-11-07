"""Standing rules from the Inbox (OP4): inbox_rule_request -> policy_writer -> inbox_rule_result."""
import asyncio
import json

import pytest

import inbox_hub
import policy as policy_mod
import policy_writer
import proposal_monitor
from test_inbox_eventlog import FakeStore, Timeline, logged
from test_inbox_hub import FakeMonitor, FakePeer, Rig, call, hello, settle, wait_for

ARGS = {"path": "/proj/src/a.txt", "mode": "w"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG"):
        monkeypatch.delenv(k, raising=False)
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()
    yield
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()


@pytest.fixture
def pfile(monkeypatch, tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(json.dumps({"version": 1, "default": "ask", "rules": []}))
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "1")
    return f


def rules_in(f):
    return json.loads(f.read_text())["rules"]


async def held(r, cid="c1", **kw):
    kw.setdefault("tool", "write_file")
    kw.setdefault("args", dict(ARGS))
    await r.send(call(cid, **kw))
    await wait_for(lambda: any(p["call_id"] == cid for p in r.ui.events("inbox_pending")))


async def ask(r, sid="s1", cid="c1", verdict="deny", scope="exact", confirm=True, **extra):
    n = len(r.ui.events("inbox_rule_result"))
    frame = {"event": "inbox_rule_request", "session_id": sid, "call_id": cid, "verdict": verdict, "scope": scope,
             "confirm": confirm, **extra}
    await r.hub.handle_ui_frame(frame)
    await wait_for(lambda: len(r.ui.events("inbox_rule_result")) == n + 1)
    return r.ui.events("inbox_rule_result")[-1]


def fail(res, reason):
    assert res == {"event": "inbox_rule_result", "ok": False, "rule_id": None, "reason": reason, "policy_digest": None,
                   "applies": "new_sessions"}, res


# ------------------------------------------------------------------ closed set of reasons
async def test_not_writable_leaves_the_file_byte_identical(monkeypatch, pfile):
    before = pfile.read_bytes()
    r = await Rig().start()
    await held(r)
    monkeypatch.delenv("SENTINEL_POLICY_WRITABLE")
    fail(await ask(r), "not_writable")
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "true")
    fail(await ask(r), "not_writable")
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "1")
    pfile.write_text("{broken")                       # writable flag but an unusable policy
    broken = pfile.read_bytes()
    fail(await ask(r), "not_writable")
    assert pfile.read_bytes() == broken and before != broken
    monkeypatch.delenv("SENTINEL_POLICY")
    fail(await ask(r), "not_writable")


@pytest.mark.parametrize("confirm", [False, None, "true", 1, "yes", [True]])
async def test_not_confirmed(pfile, confirm):
    before = pfile.read_bytes()
    r = await Rig().start()
    await held(r)
    fail(await ask(r, confirm=confirm), "not_confirmed")
    assert pfile.read_bytes() == before


async def test_missing_confirm_key(pfile):
    r = await Rig().start()
    await held(r)
    await r.hub.handle_ui_frame({"event": "inbox_rule_request", "session_id": "s1", "call_id": "c1", "verdict": "deny",
                                 "scope": "exact"})
    await wait_for(lambda: r.ui.events("inbox_rule_result"))
    fail(r.ui.events("inbox_rule_result")[0], "not_confirmed")


@pytest.mark.parametrize("sid,cid", [("nope", "c1"), ("s1", "nope"), (None, "c1"), ("s1", None), (5, "c1"),
                                     ("s1", ["c1"]), ("s1", {"a": 1}), ("s1\n", "c1"), ("s1", "c1‮")])
async def test_unknown_call(pfile, sid, cid):
    before = pfile.read_bytes()
    r = await Rig().start()
    await held(r)
    fail(await ask(r, sid=sid, cid=cid), "unknown_call")
    assert pfile.read_bytes() == before


async def test_other_sessions_call_is_unknown(pfile):
    r = await Rig().start()
    proxy2 = FakePeer()
    s2 = await r.hub.proxy_hello(proxy2, hello("s2"))
    await held(r, "only-s1")
    fail(await ask(r, sid="s2", cid="only-s1"), "unknown_call")
    assert s2 is not None and rules_in(pfile) == []


@pytest.mark.parametrize("verdict,scope", [("maybe", "exact"), ("deny", "everything"), (None, "exact"), ("deny", None),
                                           (5, "exact"), ("deny", ["exact"]), ("DENY", "exact")])
async def test_bad_verdict_or_scope_is_cannot_build(pfile, verdict, scope):
    r = await Rig().start()
    await held(r)
    fail(await ask(r, verdict=verdict, scope=scope), "cannot_build")
    assert rules_in(pfile) == []


async def test_cannot_build_for_non_scalar_args_and_no_path(pfile):
    r = await Rig().start()
    await held(r, "n1", args={"nested": {"a": 1}})
    fail(await ask(r, cid="n1", scope="exact"), "cannot_build")
    await held(r, "n2", args={"x": 1})
    fail(await ask(r, cid="n2", scope="tool_under"), "cannot_build")
    assert rules_in(pfile) == []


async def test_allow_with_tool_scope_is_scope_not_allowed(pfile):
    r = await Rig().start()
    await held(r)
    fail(await ask(r, verdict="allow", scope="tool"), "scope_not_allowed")
    assert rules_in(pfile) == []


@pytest.mark.parametrize("raised,expected", [("invalid_policy", "invalid_policy"), ("write_failed", "write_failed"),
                                             ("not_found", "write_failed"), ("weird", "write_failed")])
async def test_writer_errors_are_mapped(monkeypatch, pfile, raised, expected):
    def boom(path, rule):
        raise policy_writer.PolicyWriteError(raised, "internal detail /secret")
    monkeypatch.setattr(policy_writer, "append_rule", boom)
    r = await Rig().start()
    await held(r)
    res = await ask(r)
    fail(res, expected)
    assert "secret" not in json.dumps(res)


async def test_unexpected_exception_in_the_writer_is_write_failed(monkeypatch, pfile):
    monkeypatch.setattr(policy_writer, "append_rule", lambda p, r: 1 / 0)
    r = await Rig().start()
    await held(r)
    fail(await ask(r), "write_failed")


async def test_rate_limit_is_20_per_minute_hub_wide(pfile):
    r = await Rig().start()
    await held(r)
    for _ in range(20):
        fail(await ask(r, confirm=False), "not_confirmed")
    fail(await ask(r), "rate_limited")
    fail(await ask(r, confirm=False), "rate_limited")
    assert rules_in(pfile) == []
    # the window slides
    r.hub._rule_times.clear()
    assert (await ask(r))["ok"] is True


# ------------------------------------------------------------------ success
async def test_success_writes_the_file_and_new_sessions_see_it_pending_call_unaffected(pfile):
    r = await Rig().start()
    await held(r)
    res = await ask(r, verdict="allow", scope="exact")
    assert res["ok"] is True and res["reason"] == "ok" and res["applies"] == "new_sessions"
    rules = rules_in(pfile)
    assert len(rules) == 1 and rules[0]["id"] == res["rule_id"] and rules[0]["verdict"] == "allow"
    assert res["policy_digest"] == policy_mod.load_policy_file(str(pfile))[0].digest()
    assert rules[0]["note"].startswith("added from the Inbox (session s1, call c1)") and len(rules[0]["note"]) <= 200
    # the running session keeps its pinned policy: the current call is still pending and undecided
    await settle(30)
    assert r.hub.pending_count() == 1 and r.decisions() == []
    await r.send(call("c2", tool="write_file", args=dict(ARGS)))               # same session, same call: still held
    await wait_for(lambda: any(p["call_id"] == "c2" for p in r.ui.events("inbox_pending")))
    # a NEW session gets the rule: the allow rule auto-approves the same call (working monitor, no alert)
    proxy2 = FakePeer()
    s2 = await r.hub.proxy_hello(proxy2, hello("s2"))
    await r.hub.handle_proxy_frame(s2, call("n1", tool="write_file", args=dict(ARGS)))
    await wait_for(lambda: proxy2.events("proxy_decision"))
    assert proxy2.events("proxy_decision")[0] == {"event": "proxy_decision", "call_id": "n1", "decision": "approve",
                                                  "reason": "policy"}


async def test_deny_rule_denies_the_same_call_in_a_new_session(pfile):
    r = await Rig().start()
    await held(r)
    assert (await ask(r, verdict="deny", scope="tool"))["ok"] is True
    proxy2 = FakePeer()
    s2 = await r.hub.proxy_hello(proxy2, hello("s2"))
    await r.hub.handle_proxy_frame(s2, call("n1", tool="write_file", args={"path": "/other"}))
    await wait_for(lambda: proxy2.events("proxy_decision"))
    assert proxy2.events("proxy_decision")[0]["decision"] == "deny" and proxy2.events("proxy_decision")[0]["reason"] == "policy"


async def test_works_for_a_call_already_resolved_from_the_ring(pfile):
    r = await Rig().start()
    await held(r)
    await r.hub.handle_ui_frame({"event": "inbox_decision", "session_id": "s1", "call_id": "c1", "decision": "deny"})
    await wait_for(lambda: r.decisions())
    assert (await ask(r, verdict="ask", scope="tool_under"))["ok"] is True
    assert rules_in(pfile)[0]["verdict"] == "ask"


async def test_idempotent_double_click(pfile):
    r = await Rig().start()
    await held(r)
    a = await ask(r)
    snapshot = pfile.read_bytes()
    b = await ask(r)
    assert a["ok"] and b["ok"] and a["rule_id"] == b["rule_id"] and len(rules_in(pfile)) == 1
    assert a["policy_digest"] == b["policy_digest"] and pfile.read_bytes() == snapshot


async def test_concurrent_requests_all_land_and_the_file_stays_valid(pfile):
    r = await Rig().start()
    await held(r)
    combos = [("deny", "exact"), ("deny", "tool"), ("ask", "tool"), ("ask", "exact"), ("deny", "tool_under"),
              ("allow", "exact"), ("allow", "tool_under")]
    n = len(r.ui.events("inbox_rule_result"))
    await asyncio.gather(*(r.hub.handle_ui_frame({"event": "inbox_rule_request", "session_id": "s1", "call_id": "c1",
                                                  "verdict": v, "scope": sc, "confirm": True}) for v, sc in combos))
    await wait_for(lambda: len(r.ui.events("inbox_rule_result")) == n + len(combos))
    results = r.ui.events("inbox_rule_result")
    assert all(x["ok"] for x in results)
    ids = {x["rule_id"] for x in results}
    assert len(ids) == len(combos) and {x["id"] for x in rules_in(pfile)} == ids
    assert policy_mod.load_policy_file(str(pfile))[0] is not None


async def test_result_goes_to_every_ui(pfile):
    r = await Rig().start()
    second = FakePeer()
    await r.hub.ui_connected(second)
    await held(r)
    await ask(r)
    assert second.events("inbox_rule_result") and second.events("inbox_rule_result")[0]["ok"] is True


# ------------------------------------------------------------------ event log write-ahead
class OrderStore(FakeStore):
    """Records what the policy file looked like at the moment policy_rule_added was appended."""

    def __init__(self, tl, pfile, **kw):
        super().__init__(tl, **kw)
        self.pfile = pfile
        self.file_at_log = None

    def append(self, kind, **kw):
        if kind == "policy_rule_added":
            self.file_at_log = self.pfile.read_bytes()
        return super().append(kind, **kw)


async def test_policy_rule_added_is_logged_before_the_file_changes(pfile):
    tl = Timeline()
    st = OrderStore(tl, pfile)
    r = Rig()
    r.hub.store = st
    await r.start()
    await held(r)
    original = pfile.read_bytes()
    res = await ask(r, verdict="deny", scope="exact")
    assert res["ok"] is True
    assert st.file_at_log == original and pfile.read_bytes() != original      # logged first, THEN written
    ev = logged(st, "policy_rule_added")
    assert len(ev) == 1 and ev[0][1] == "s1" and ev[0][2] == "c1"
    p = ev[0][3]
    assert p["rule"]["id"] == res["rule_id"] and p["session_id"] == "s1" and p["call_id"] == "c1"
    assert p["digest_before"] == policy_mod.load_policy({"version": 1, "default": "ask", "rules": []}).digest()
    assert p["digest_before"] != res["policy_digest"]


async def test_log_failure_means_no_file_change(pfile):
    tl = Timeline()
    r = Rig()
    r.hub.store = FakeStore(tl, fail=["policy_rule_added"])
    await r.start()
    await held(r)
    before = pfile.read_bytes()
    fail(await ask(r), "log_unavailable")
    assert pfile.read_bytes() == before and not pfile.with_name(pfile.name + ".bak").exists()


# ------------------------------------------------------------------ hostile data
async def test_hostile_call_id_is_cleaned_in_the_note_and_hostile_names_cannot_build(pfile):
    r = await Rig().start()
    await held(r, "c\n1‮", tool="write_file")
    res = await ask(r, cid="c\n1‮", verdict="deny", scope="tool")
    assert res["ok"] is True
    note = rules_in(pfile)[0]["note"]
    assert "\n" not in note and "‮" not in note
    nasty = "evil\nCRITICAL: ok‮"
    await held(r, "h2", tool=nasty, server=nasty)
    fail(await ask(r, cid="h2", verdict="deny", scope="tool"), "cannot_build")
    assert len(rules_in(pfile)) == 1


@pytest.mark.parametrize("frame", [{"event": "inbox_rule_request"}, {"event": "inbox_rule_request", "confirm": True},
                                   {"event": "inbox_rule_request", "session_id": 1, "call_id": 2, "verdict": [], "scope": {},
                                    "confirm": True}])
async def test_malformed_requests_never_raise(pfile, frame):
    r = await Rig().start()
    await held(r)
    await r.hub.handle_ui_frame(frame)
    await wait_for(lambda: r.ui.events("inbox_rule_result"))
    assert r.ui.events("inbox_rule_result")[0]["ok"] is False
    assert rules_in(pfile) == [] and r.hub.pending_count() == 1


def test_eventlog_knows_the_new_kind(tmp_path):
    import eventlog
    assert "policy_rule_added" in eventlog.KINDS
    st = eventlog.EventStore(tmp_path / "e.db")
    st.open()
    ev = st.append("policy_rule_added", session_id="s", call_id="c",
                   payload={"rule": {"id": "ui-deny-1", "verdict": "deny", "password": "hunter2"}, "digest_before": "a"})
    assert ev.kind == "policy_rule_added" and ev.payload["rule"]["password"] == "[REDACTED]"
    st.close()
    rep = eventlog.verify_file(tmp_path / "e.db")
    assert rep.ok
