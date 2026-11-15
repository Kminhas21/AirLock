"""Hub side of kernel confinement (DECISIONS D31). The proxy says whether a call can be confined (`proxy_call.confinable`, exactly true) and
where a symlinked path value leads (`links`, display only); the hub judges the WRITTEN text, floors path allows it cannot have enforced, and
sends the deciding rule's `confine` map with a policy approval. Prediction is gone: `resolved` from an old proxy is ignored."""
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


async def test_a_confinable_read_is_approved_with_the_rules_confine_map():
    r = await Rig().start()
    await r.send(read("c1", "/w/a.txt", confinable=True))
    await wait_for(lambda: r.decisions())
    d = r.decisions()[0]
    assert (d["decision"], d["reason"], d["confine"]) == ("approve", "policy", {"path": "read"})


async def test_a_non_path_allow_carries_no_confine_map():
    r = await Rig().start()
    await r.send(call("c1", tool="get_current_time", args={"timezone": "UTC"}))      # no `confinable`: not needed without paths
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "approve" and "confine" not in r.decisions()[0]


@pytest.mark.parametrize("confinable", [False, None, "true", 1, "yes"])
async def test_an_unconfinable_or_old_proxy_path_read_is_held(confinable):
    r = await Rig().start()
    kw = {} if confinable is None else {"confinable": confinable}
    await r.send(read("c1", "/w/a.txt", **kw))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]
    assert p["rule_id"] == "allow-read-file" and r.decisions() == []


async def test_a_sensitive_name_is_still_asked_on_a_confinable_server():
    r = await Rig().start()
    await r.send(read("c1", "/w/.env", confinable=True))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.ui.events("inbox_pending")[0]["rule_id"] == "ask-sensitive-path" and r.decisions() == []


async def test_links_are_shown_on_the_card_and_never_change_a_verdict():
    r = await Rig().start()
    await r.send(read("c1", "/w/notes.txt", confinable=False, links={"path": "/w/.env"}))
    await r.send(read("c2", "/w/a.txt", confinable=True, links={"path": "/w/.env"}))
    await wait_for(lambda: r.ui.events("inbox_pending") and r.decisions())
    p = r.ui.events("inbox_pending")[0]
    assert p["call_id"] == "c1" and p["links"] == {"path": "/w/.env"} and p["rule_id"] == "allow-read-file"
    assert r.decisions()[0]["call_id"] == "c2" and r.decisions()[0]["decision"] == "approve"


@pytest.mark.parametrize("bad", ["x", 5, ["/w/.env"], {"path": 7}, {"": "/x"}, {f"k{i}": "/x" for i in range(65)}, {"path": "/x" * 3000}])
async def test_malformed_links_are_dropped_and_never_crash(bad):
    r = await Rig().start()
    await r.send(read("c1", "/w/notes.txt", links=bad))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert "links" not in r.ui.events("inbox_pending")[0] and not r.proxy.closed


async def test_an_old_proxys_resolved_field_is_ignored():
    r = await Rig().start()
    await r.send(read("c1", "/w/a.txt", confinable=True, resolved=[{"path": "/w/.env"}], resolved_incomplete=True))
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "approve"


async def test_a_human_approval_carries_no_confine_map():
    r = await Rig().start()
    await r.send(read("c1", "/w/a.txt"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["reason"] == "human" and "confine" not in r.decisions()[0]


async def test_confinable_and_links_are_in_the_write_ahead_log_and_resolved_is_not():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(read("c1", "/w/notes.txt", confinable=False, links={"path": "/w/.env"}, resolved=[{"path": "/w/.env"}]))
    await r.send(read("c2", "/w/a.txt", confinable=True))
    await wait_for(lambda: len(logged(st, "call_proposed")) == 2)
    props = {e[2]: e[3] for e in logged(st, "call_proposed")}
    assert props["c1"]["confinable"] is False and props["c1"]["links"] == {"path": "/w/.env"}
    assert props["c1"]["policy"]["verdict"] == "ask" and "resolved" not in props["c1"]
    assert props["c2"]["confinable"] is True and "links" not in props["c2"] and props["c2"]["policy"]["verdict"] == "allow"


async def test_the_lexical_resolution_travels_with_the_links_to_the_card_and_the_log():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(read("c1", "far/../b", confinable=False, links={"path": "/t/b"}, links_lexical={"path": "/w/b"}))
    await wait_for(lambda: r.ui.events("inbox_pending") and logged(st, "call_proposed"))
    p = r.ui.events("inbox_pending")[0]
    assert p["links"] == {"path": "/t/b"} and p["links_lexical"] == {"path": "/w/b"}
    assert logged(st, "call_proposed")[0][3]["links_lexical"] == {"path": "/w/b"}


@pytest.mark.parametrize("bad", ["x", 5, ["/w/b"], {"path": 7}, {"": "/x"}, {f"k{i}": "/x" for i in range(65)}])
async def test_malformed_lexical_links_are_dropped_and_never_crash(bad):
    r = await Rig().start()
    await r.send(read("c1", "far/../b", links={"path": "/t/b"}, links_lexical=bad))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]
    assert p["links"] == {"path": "/t/b"} and "links_lexical" not in p and not r.proxy.closed
