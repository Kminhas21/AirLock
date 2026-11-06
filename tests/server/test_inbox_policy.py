"""Policy engine integration in the InboxHub (PE3): docs/plans/POLICY-ENGINE.md "Hub integration"."""
import asyncio
import json

import pytest

import inbox_hub
import policy as policy_mod
import proposal_monitor
from proposal_monitor import SessionMonitor
from test_inbox_hub import ALERT, FakeMonitor, FakePeer, Rig, call, hello, settle, wait_for


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("SENTINEL_POLICY", raising=False)
    monkeypatch.delenv("SENTINEL_REGISTRY", raising=False)
    policy_mod._reset_policy_cache()
    inbox_hub._logged_policy_problems.clear()
    proposal_monitor._reset_errors()
    yield
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()


def write_policy(tmp_path, rules, default="ask", name="policy.json"):
    f = tmp_path / name
    f.write_text(json.dumps({"version": 1, "default": default, "rules": rules}))
    return f


def rule(rid, verdict, **when):
    r = {"id": rid, "verdict": verdict}
    if when:
        r["when"] = when
    return r


RULES = [rule("no-rm", "deny", tool=["delete_file"]),
         rule("reads", "allow", tool=["read_file"]),
         rule("writes", "ask", tool=["write_file"])]


def use(monkeypatch, tmp_path, rules=RULES, default="ask"):
    f = write_policy(tmp_path, rules, default)
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    return f, policy_mod.load_policy_file(str(f))[0]


async def test_deny_rule_replies_policy_registers_denial_and_never_holds(monkeypatch, tmp_path):
    _, pol = use(monkeypatch, tmp_path)
    r = await Rig().start()
    await r.send(call(tool="delete_file"))
    await wait_for(lambda: r.decisions())
    assert r.decisions() == [{"event": "proxy_decision", "call_id": "c1", "decision": "deny", "reason": "policy"}]
    assert r.monitor.decisions == [("delete_file", {"p": 1}, "deny")]       # the monitor learned the denial
    assert not r.ui.events("inbox_pending")
    assert r.ui.events("inbox_resolved")[0] == {"event": "inbox_resolved", "session_id": "s1", "call_id": "c1",
                                                "decision": "deny", "reason": "policy", "rule_id": "no-rm",
                                                "policy_digest": pol.digest()}


async def test_allow_rule_with_working_monitor_is_approved_without_a_card(monkeypatch, tmp_path):
    _, pol = use(monkeypatch, tmp_path)
    r = await Rig().start()
    await r.send(call(tool="read_file"))          # auto flag False: the proxy did not allow-list it
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0] == {"event": "proxy_decision", "call_id": "c1", "decision": "approve", "reason": "policy"}
    assert r.monitor.decisions == [("read_file", {"p": 1}, "approve")]
    assert not r.ui.events("inbox_pending")
    res = r.ui.events("inbox_resolved")[0]
    assert (res["decision"], res["reason"], res["rule_id"], res["policy_digest"]) == ("approve", "policy", "reads", pol.digest())


async def test_allow_with_alert_is_held_with_rule_id(monkeypatch, tmp_path):
    _, pol = use(monkeypatch, tmp_path)
    r = await Rig(FakeMonitor([ALERT])).start()
    await r.send(call(tool="read_file"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []
    p = r.ui.events("inbox_pending")[0]
    assert p["alerts"] == [ALERT] and p["rule_id"] == "reads" and p["policy_digest"] == pol.digest()


async def test_allow_with_degraded_monitor_is_held(monkeypatch, tmp_path):
    use(monkeypatch, tmp_path)
    r = await Rig(SessionMonitor("rules")).start()
    await r.send(call(tool="read_file"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []
    assert r.ui.events("inbox_pending")[0]["rule_id"] == "reads"


async def test_ask_rule_is_held_with_rule_id_and_human_resolution_carries_it(monkeypatch, tmp_path):
    _, pol = use(monkeypatch, tmp_path)
    r = await Rig().start()
    await r.send(call(tool="write_file"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]
    assert p["rule_id"] == "writes" and p["policy_digest"] == pol.digest()
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["reason"] == "human"
    await wait_for(lambda: r.ui.events("inbox_resolved"))
    res = r.ui.events("inbox_resolved")[0]
    assert res["reason"] == "human" and res["rule_id"] == "writes" and res["policy_digest"] == pol.digest()


@pytest.mark.parametrize("default,expect_hold", [("ask", True), ("allow", False), ("deny", False)])
async def test_default_verdict(monkeypatch, tmp_path, default, expect_hold):
    use(monkeypatch, tmp_path, rules=[], default=default)
    r = await Rig().start()
    await r.send(call(tool="anything"))
    if expect_hold:
        await wait_for(lambda: r.ui.events("inbox_pending"))
        assert r.ui.events("inbox_pending")[0]["rule_id"] is None and r.decisions() == []
    else:
        await wait_for(lambda: r.decisions())
        assert r.decisions()[0]["decision"] == ("approve" if default == "allow" else "deny")
        assert r.decisions()[0]["reason"] == "policy"
        assert r.ui.events("inbox_resolved")[0]["rule_id"] is None


@pytest.mark.parametrize("setup", ["missing", "invalid", "toobig"])
async def test_broken_policy_asks_for_everything_even_auto(monkeypatch, tmp_path, setup, caplog):
    f = tmp_path / "p.json"
    if setup == "invalid":
        f.write_text("{not json")
    elif setup == "toobig":
        f.write_text(" " * 3_000_000)
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    r = await Rig().start()
    for i, tool in enumerate(["read_file", "delete_file"]):
        await r.send(call(f"c{i}", tool=tool, auto=True))
    await wait_for(lambda: len(r.ui.events("inbox_pending")) == 2)
    assert r.decisions() == []
    for p in r.ui.events("inbox_pending"):
        assert p["rule_id"] is None and p["policy_digest"] is None
    assert sum(1 for rec in caplog.records if rec.levelname == "ERROR" and "SENTINEL_POLICY" in rec.getMessage()) == 1


async def test_proxy_auto_flag_ignored_with_usable_policy(monkeypatch, tmp_path):
    use(monkeypatch, tmp_path)
    r = await Rig().start()
    await r.send(call(tool="write_file", auto=True))      # proxy says auto; the policy says ask
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []


async def test_no_policy_env_is_legacy(tmp_path):
    r = await Rig().start()
    await r.send(call(tool="read_file", auto=True))
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["reason"] == "auto"
    r2 = Rig()
    await r2.start()
    await r2.send(call(tool="x"))
    await wait_for(lambda: r2.ui.events("inbox_pending"))
    assert "rule_id" not in r2.ui.events("inbox_pending")[0] and "policy_digest" not in r2.ui.events("inbox_pending")[0]


async def test_session_keeps_its_policy_when_the_file_changes(monkeypatch, tmp_path):
    f, pol1 = use(monkeypatch, tmp_path)
    r = await Rig().start()
    write_policy(tmp_path, [rule("reads2", "deny", tool=["read_file"])])
    r2 = Rig()
    r2.hub = r.hub
    # the first session still allows read_file under the OLD policy
    await r.send(call(tool="read_file"))
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "approve"
    assert r.ui.events("inbox_resolved")[0]["policy_digest"] == pol1.digest()
    # a NEW session gets the new policy
    proxy2 = FakePeer()
    s2 = await r.hub.proxy_hello(proxy2, hello("s2"))
    await r.hub.handle_proxy_frame(s2, call("n1", tool="read_file"))
    await wait_for(lambda: proxy2.events("proxy_decision"))
    assert proxy2.events("proxy_decision")[0]["decision"] == "deny"
    new = [e for e in r.ui.events("inbox_resolved") if e["session_id"] == "s2"][0]
    assert new["rule_id"] == "reads2" and new["policy_digest"] != pol1.digest()


async def test_policy_evaluate_raising_means_ask(monkeypatch, tmp_path):
    use(monkeypatch, tmp_path)
    r = await Rig().start()

    def boom(*a, **k):
        raise RuntimeError("engine blew up")
    monkeypatch.setattr(type(r.session.policy), "evaluate", boom)
    await r.send(call(tool="read_file", auto=True))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []
    assert r.ui.events("inbox_pending")[0]["rule_id"] is None


async def test_snapshot_carries_policy_fields(monkeypatch, tmp_path):
    _, pol = use(monkeypatch, tmp_path)
    r = await Rig().start()
    await r.send(call(tool="write_file"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    late = FakePeer()
    await r.hub.ui_connected(late)
    item = late.sent[0]["sessions"][0]["pending"][0]
    assert item["rule_id"] == "writes" and item["policy_digest"] == pol.digest()


async def test_hostile_rule_id_is_rejected_by_the_engine_so_policy_is_broken_and_asks(monkeypatch, tmp_path):
    nasty = "r‮<b>x</b>"
    use(monkeypatch, tmp_path, rules=[rule(nasty, "ask", tool=["t"])])
    r = await Rig().start()
    await r.send(call(tool="t"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]       # the engine refuses such an id: broken policy, ask, no id leaks
    assert p["rule_id"] is None and p["policy_digest"] is None


# ------------------------------------------------------------------ /health
import httpx  # noqa: E402

import health_view  # noqa: E402


def test_policy_view_public_and_detail():
    pol = policy_mod.load_policy({"version": 1, "default": "ask", "rules": [rule("a", "ask", tool=["t"])]})
    assert health_view.policy_view("/etc/p.json", pol, False) == {"digest": pol.digest(), "rules": 1, "usable": True}
    assert health_view.policy_view("/etc/p.json", pol, True) == {"path": "/etc/p.json", "digest": pol.digest(),
                                                                 "rules": 1, "usable": True}
    assert health_view.policy_view("/x", None, False) == {"digest": None, "rules": 0, "usable": False}


async def _health(monkeypatch, params=None):
    import live_drift
    import main
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    monkeypatch.setenv("SENTINEL_WS_TOKEN", "tk")
    live_drift._reset_embedder_cache()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url="http://t") as c:
        return (await c.get("/health", params=params)).json()


async def test_health_policy_views(monkeypatch, tmp_path):
    f, pol = use(monkeypatch, tmp_path)
    pub = await _health(monkeypatch)
    assert pub["policy"] == {"digest": pol.digest(), "rules": 3, "usable": True}
    det = await _health(monkeypatch, {"token": "tk"})
    assert det["policy"]["path"] == str(f) and det["policy"]["digest"] == pol.digest()
    monkeypatch.setenv("SENTINEL_POLICY", str(tmp_path / "nope.json"))
    assert (await _health(monkeypatch))["policy"] == {"digest": None, "rules": 0, "usable": False}
    monkeypatch.delenv("SENTINEL_POLICY")
    assert "policy" not in await _health(monkeypatch)
