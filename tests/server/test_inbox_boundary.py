"""Enforcement boundary in the hub (EB3): proxy_hello.boundary, proxy_call.secrets_used."""
import json

import pytest

import inbox_hub
import policy as policy_mod
import proposal_monitor
from inbox_hub import validate_boundary, validate_secrets_used
from test_inbox_eventlog import FakeStore, Timeline, logged
from test_inbox_hub import FakePeer, Rig, call, hello, settle, wait_for

GOOD = {"fs": {"lifecycle": "per_call", "layers": ["env", "rlimit", "no_new_privs", "netns", "landlock_fs"],
               "missing": [], "network": "none", "secrets": ["API_TOKEN", "DB_PASSWORD"]},
        "git": {"lifecycle": "session", "layers": ["env"], "missing": ["landlock_fs"], "network": "host", "secrets": []}}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG"):
        monkeypatch.delenv(k, raising=False)
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()
    yield
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()


# ------------------------------------------------------------------ validation (pure)
def test_valid_boundary_is_kept_in_the_normalised_shape():
    assert validate_boundary(GOOD) == GOOD
    assert validate_boundary({}) == {}
    out = validate_boundary({"fs": {"layers": ["env", "env"], "secrets": ["A", "A"]}})
    assert out == {"fs": {"lifecycle": None, "layers": ["env"], "missing": [], "network": None, "secrets": ["A"]}}


def bad_boundaries():
    yield "str"
    yield ["fs"]
    yield 5
    yield {i: {} for i in range(3)} if False else {"s%d" % i: {} for i in range(51)}          # too many servers
    yield {"": {}}
    yield {"x" * 201: {}}
    yield {"fs": "none"}
    yield {"fs": {"unknown_key": 1}}
    yield {"fs": {"lifecycle": "forever"}}
    yield {"fs": {"lifecycle": ["session"]}}
    yield {"fs": {"network": "internet"}}
    yield {"fs": {"network": 5}}
    yield {"fs": {"layers": ["seccomp"]}}
    yield {"fs": {"layers": "env"}}
    yield {"fs": {"layers": ["env"] * 7}}
    yield {"fs": {"missing": ["nope"]}}
    yield {"fs": {"secrets": ["lowercase"]}}
    yield {"fs": {"secrets": ["API_TOKEN=hunter2"]}}
    yield {"fs": {"secrets": {"API_TOKEN": "hunter2"}}}
    yield {"fs": {"secrets": ["A%d" % i for i in range(21)]}}
    yield {"fs": {"secrets": ["X" * 65]}}
    yield {"fs": {"secrets": [5]}}
    yield {"fs": {"secrets": ["OK\n"]}}
    yield {"ok": {}, "bad": {"network": "x"}}                                                    # one bad server voids all


@pytest.mark.parametrize("bad", list(bad_boundaries()))
def test_invalid_boundary_is_treated_as_absent(bad):
    assert validate_boundary(bad) is None


@pytest.mark.parametrize("v,expected", [
    (["API_TOKEN"], ["API_TOKEN"]), ([], []), (None, []), ("API_TOKEN", []), ({"API_TOKEN": "hunter2"}, []),
    (["api_token"], []), (["A", 5], []), (["hunter2"], []), (["A=hunter2"], []), (["A\nB"], []),
    ([f"N{i}" for i in range(21)], []), ([f"N{i}" for i in range(20)], [f"N{i}" for i in range(20)]),
    (["X" * 65], []), (["A", "A", "B"], ["A", "B"]), (5, []), ([["A"]], [])])
def test_secrets_used_validation(v, expected):
    assert validate_secrets_used(v) == expected


# ------------------------------------------------------------------ hello: stored, logged, in the snapshot
async def test_boundary_is_stored_logged_and_in_the_snapshot():
    tl = Timeline()
    st = FakeStore(tl)
    r = Rig()
    r.hub.store = st
    r.session = await r.hub.proxy_hello(r.proxy, hello(boundary=GOOD))
    assert r.session.boundary == GOOD
    assert logged(st, "proxy_hello")[0][3]["boundary"] == GOOD
    late = FakePeer()
    await r.hub.ui_connected(late)
    assert late.sent[0]["sessions"][0]["boundary"] == GOOD


@pytest.mark.parametrize("bad", ["x", {"fs": {"network": "weird"}}, {"fs": {"secrets": ["lower"]}}, 5])
async def test_invalid_boundary_is_never_fatal(bad):
    tl = Timeline()
    st = FakeStore(tl)
    r = Rig()
    r.hub.store = st
    r.session = await r.hub.proxy_hello(r.proxy, hello(boundary=bad))
    assert r.session is not None and r.session.boundary is None
    assert r.proxy.sent[0]["event"] == "hello_ack"
    assert logged(st, "proxy_hello")[0][3]["boundary"] is None
    ui = FakePeer()
    await r.hub.ui_connected(ui)
    assert ui.sent[0]["sessions"][0]["boundary"] is None


async def test_hello_without_boundary_keeps_working():
    r = await Rig().start()
    assert r.session.boundary is None


# ------------------------------------------------------------------ calls
async def held(r, cid="c1", **kw):
    await r.send(call(cid, **kw))
    await wait_for(lambda: any(p["call_id"] == cid for p in r.ui.events("inbox_pending")))
    return [p for p in r.ui.events("inbox_pending") if p["call_id"] == cid][0]


async def test_secrets_used_is_carried_in_pending_snapshot_and_log():
    tl = Timeline()
    st = FakeStore(tl)
    r = Rig()
    r.hub.store = st
    await r.start()
    p = await held(r, secrets_used=["API_TOKEN", "DB_PASSWORD"])
    assert p["secrets_used"] == ["API_TOKEN", "DB_PASSWORD"]
    assert logged(st, "call_proposed")[0][3]["secrets_used"] == ["API_TOKEN", "DB_PASSWORD"]
    late = FakePeer()
    await r.hub.ui_connected(late)
    assert late.sent[0]["sessions"][0]["pending"][0]["secrets_used"] == ["API_TOKEN", "DB_PASSWORD"]
    q = await held(r, "c2")
    assert q["secrets_used"] == [] and logged(st, "call_proposed")[1][3]["secrets_used"] == []


async def test_legacy_auto_flag_is_ignored_when_the_call_receives_credentials():
    r = await Rig().start()
    await r.send(call("a", auto=True, tool="read_file"))                     # no secrets: auto-approved as before
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["reason"] == "auto"
    p = await held(r, "b", auto=True, tool="read_file", secrets_used=["API_TOKEN"])
    assert p["auto"] is True and len(r.decisions()) == 1                      # held for the human
    await r.decide("b", "approve")
    await wait_for(lambda: len(r.decisions()) == 2)
    assert r.decisions()[1]["reason"] == "human"


@pytest.mark.parametrize("bad", ["hunter2", {"API_TOKEN": "hunter2"}, ["hunter2"], ["A=hunter2"], 5,
                                 [f"N{i}" for i in range(500)]])
async def test_hostile_secrets_used_never_stores_values_and_is_treated_as_absent(bad):
    tl = Timeline()
    st = FakeStore(tl)
    r = Rig()
    r.hub.store = st
    await r.start()
    p = await held(r, secrets_used=bad)
    assert p["secrets_used"] == []
    blob = json.dumps([p, logged(st, "call_proposed")])
    assert "hunter2" not in blob and "N499" not in blob


# ------------------------------------------------------------------ policy
def use(monkeypatch, tmp_path, rules, default="ask"):
    f = tmp_path / "p.json"
    f.write_text(json.dumps({"version": 1, "default": default, "rules": rules}))
    monkeypatch.setenv("SENTINEL_POLICY", str(f))


async def test_policy_allow_without_secrets_true_holds_a_credentialed_call(monkeypatch, tmp_path):
    use(monkeypatch, tmp_path, [{"id": "reads", "verdict": "allow", "when": {"tool": ["read_file"]}}])
    r = await Rig().start()
    await r.send(call("plain", tool="read_file"))
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["reason"] == "policy" and r.decisions()[0]["decision"] == "approve"
    p = await held(r, "creds", tool="read_file", secrets_used=["API_TOKEN"])
    assert p["rule_id"] == "reads" and len(r.decisions()) == 1


async def test_policy_allow_with_secrets_true_approves_the_credentialed_call(monkeypatch, tmp_path):
    use(monkeypatch, tmp_path, [{"id": "creds-ok", "verdict": "allow", "when": {"tool": ["read_file"], "secrets": True}}])
    r = await Rig().start()
    await r.send(call("creds", tool="read_file", secrets_used=["API_TOKEN"]))
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0] == {"event": "proxy_decision", "call_id": "creds", "decision": "approve", "reason": "policy"}
    assert r.ui.events("inbox_resolved")[0]["rule_id"] == "creds-ok"


async def test_policy_deny_still_denies_a_credentialed_call(monkeypatch, tmp_path):
    use(monkeypatch, tmp_path, [{"id": "no", "verdict": "deny", "when": {"tool": ["rm"]}},
                                {"id": "all", "verdict": "allow", "when": {"secrets": True, "tool": ["rm"]}}])
    r = await Rig().start()
    await r.send(call("x", tool="rm", secrets_used=["API_TOKEN"]))
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "deny" and r.decisions()[0]["reason"] == "policy"


async def test_policy_default_allow_does_not_cover_credentials(monkeypatch, tmp_path):
    use(monkeypatch, tmp_path, [], default="allow")
    r = await Rig().start()
    await held(r, "c", secrets_used=["API_TOKEN"])
    assert r.decisions() == []
