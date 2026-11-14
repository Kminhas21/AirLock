"""Hub side of symlink resolution (B4): the proxy sends `resolved` (each entry one interpretation of the call with symlinked path values
replaced by their real targets); the hub evaluates the policy on the written AND the resolved forms and takes the stricter verdict."""
import pytest

import inbox_hub
import policy as P
import proposal_monitor
from test_inbox_eventlog import FakeStore, Timeline, logged, make
from test_inbox_hub import Rig, call, wait_for


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:starter")
    P._reset_policy_cache()
    inbox_hub._logged_policy_problems.clear()
    proposal_monitor._reset_errors()
    yield
    P._reset_policy_cache()
    proposal_monitor._reset_errors()


def read(cid, path, **kw):
    return call(cid, tool="read_text_file", args={"path": path}, **kw)


async def test_a_read_through_a_symlink_to_a_secret_is_held():
    r = await Rig().start()
    await r.send(read("c1", "/w/notes.txt", resolved=[{"path": "/w/.env"}]))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]
    assert p["rule_id"] == "ask-sensitive-path" and r.decisions() == []
    assert p["resolved"] == [{"path": "/w/.env"}]                  # the human sees what the link really names


async def test_a_plain_read_is_still_allowed_and_an_old_proxy_keeps_todays_behaviour():
    r = await Rig().start()
    await r.send(read("c1", "/w/a.txt", resolved=[{"path": "/real/w/a.txt"}]))
    await r.send(read("c2", "/w/b.txt"))
    await wait_for(lambda: len(r.decisions()) == 2)
    assert [d["decision"] for d in r.decisions()] == ["approve", "approve"]
    assert "resolved" not in r.ui.events("inbox_resolved")[0]


@pytest.mark.parametrize("bad", ["x", 5, {"path": "/w/.env"}, [{"nope": "/x"}], [{"path": 7}], [{"path": "/x"}] * 9])
async def test_a_malformed_resolution_holds_the_call_and_never_crashes(bad):
    r = await Rig().start()
    await r.send(read("c1", "/w/a.txt", resolved=bad))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []
    assert r.session is not None and not r.proxy.closed


async def test_an_incomplete_resolution_holds_the_call():
    r = await Rig().start()
    await r.send(read("c1", "/w/a.txt", resolved=[], resolved_incomplete=True))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []


async def test_the_resolved_form_is_in_the_write_ahead_log():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(read("c1", "/w/notes.txt", resolved=[{"path": "/w/.env"}]))
    await r.send(read("c2", "/w/a.txt"))
    await r.send(read("c3", "/w/b.txt", resolved="junk"))
    await wait_for(lambda: len(logged(st, "call_proposed")) == 3)
    props = {e[2]: e[3] for e in logged(st, "call_proposed")}
    assert props["c1"]["resolved"] == [{"path": "/w/.env"}] and props["c1"]["args"] == {"path": "/w/notes.txt"}
    assert props["c1"]["policy"]["verdict"] == "ask"
    assert "resolved" not in props["c2"] and "resolved_invalid" not in props["c2"]
    assert props["c3"]["resolved_invalid"] is True and "resolved" not in props["c3"]
