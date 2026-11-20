"""Hub side of the `write` right (DECISIONS D32). The proxy says whether THIS write is one it can confine and keep a before-image of
(`proxy_call.write_confinable`, exactly true; `write_why` says why not, from a closed set), the hub judges the WRITTEN text with the starter's
write rules, floors what the proxy cannot enforce (`write_unsupported`), sends `confine: {"path": "write"}` with a policy approval, shows a write
call distinctly on the card, and logs what the proxy reports was written (`writes` in `call_result`). Confinable can only make a decision stricter."""
import pytest

import inbox_hub
import policy as P
import proposal_monitor
from test_inbox_eventlog import FakeStore, Timeline, logged, make
from test_inbox_hub import Rig, call, settle, wait_for


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG", "SENTINEL_LOG_RESULTS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:starter")
    P._reset_policy_cache()
    inbox_hub._logged_policy_problems.clear()
    proposal_monitor._reset_errors()
    yield
    P._reset_policy_cache()
    proposal_monitor._reset_errors()


def write(cid, path="/w/notes.md", tool="write_file", **kw):
    args = {"path": path, "content": "hello\n"} if tool == "write_file" else {"path": path, "edits": [{"oldText": "a", "newText": "b"}]}
    return call(cid, tool=tool, args=args, **kw)


# --------------------------------------------------------------------------- the decision


@pytest.mark.parametrize("tool", ["write_file", "edit_file"])
async def test_a_confinable_doc_write_is_approved_with_a_write_confine_map(tool):
    r = await Rig().start()
    await r.send(write("c1", tool=tool, confinable=True, write_confinable=True))
    await wait_for(lambda: r.decisions())
    d = r.decisions()[0]
    assert (d["decision"], d["reason"], d["confine"]) == ("approve", "policy", {"path": "write"})
    assert r.ui.events("inbox_pending") == []


@pytest.mark.parametrize("wc", [None, False, "true", 1, "yes", [], {}])
async def test_a_write_the_proxy_does_not_vouch_for_is_held_for_a_human(wc):
    r = await Rig().start()
    kw = {} if wc is None else {"write_confinable": wc}
    await r.send(write("c1", confinable=True, **kw))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == [] and r.ui.events("inbox_pending")[0]["rule_id"] == "allow-write-docs"


async def test_an_unconfinable_server_holds_the_write_even_if_it_says_the_write_is_confinable():
    r = await Rig().start()
    await r.send(write("c1", confinable=False, write_confinable=True))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []


async def test_an_old_proxy_that_knows_nothing_of_writes_holds_every_write():
    r = await Rig().start()
    await r.send(write("c1", confinable=True))                       # a D31 proxy: confinable, no write_confinable
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []


async def test_a_write_a_source_file_or_a_sensitive_path_is_held_whatever_the_proxy_says():
    r = await Rig().start()
    for i, path in enumerate(["/w/a.py", "/w/.github/notes.md", "/w/CLAUDE.md", "/w/.git/hooks/pre-commit.md", "/w/.env.md", "/w/x.json"]):
        await r.send(write(f"c{i}", path, confinable=True, write_confinable=True))
    await wait_for(lambda: len(r.ui.events("inbox_pending")) == 6)
    assert r.decisions() == []


async def test_a_human_approved_write_carries_no_confine_map_and_stays_unconfined_as_before():
    r = await Rig().start()
    await r.send(write("c1", "/w/new.md", confinable=True, write_confinable=False))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    await r.decide("c1", "approve")
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["reason"] == "human" and "confine" not in r.decisions()[0]


async def test_the_write_confinable_field_never_widens_a_read_or_a_non_write_decision():
    r = await Rig().start()
    await r.send(call("c1", tool="read_text_file", args={"path": "/w/a.md"}, confinable=False, write_confinable=True))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []


# --------------------------------------------------------------------------- the card says it is a write, and why it was held


async def test_a_held_write_shows_what_the_proxy_found():
    r = await Rig().start()
    await r.send(write("c1", "/w/new.md", confinable=True, write_confinable=False, write_why="new_file"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]
    assert p["write"] == {"confinable": False, "why": "new_file"}


@pytest.mark.parametrize("why", ["unsupported", "bad_path", "outside_write_dir", "new_file", "symlink", "not_regular", "hard_link", "executable",
                                 "too_large", "no_before_image", "edits_too_large"])
async def test_every_reason_of_the_closed_set_reaches_the_card(why):
    r = await Rig().start()
    await r.send(write("c1", confinable=True, write_confinable=False, write_why=why))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.ui.events("inbox_pending")[0]["write"] == {"confinable": False, "why": why}


@pytest.mark.parametrize("why", ["", "because", 5, None, ["new_file"], "new_file\n<script>", "x" * 1000, "NEW_FILE"])
async def test_a_reason_outside_the_closed_set_is_dropped_not_shown(why):
    r = await Rig().start()
    await r.send(write("c1", confinable=True, write_confinable=False, write_why=why))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]
    assert p["write"] == {"confinable": False} and not r.proxy.closed


async def test_a_call_without_any_write_field_has_no_write_on_its_card():
    r = await Rig().start()
    await r.send(call("c1", tool="write_file", args={"path": "/w/a.md", "content": "x"}, confinable=True))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert "write" not in r.ui.events("inbox_pending")[0]


def test_the_closed_set_of_reasons_is_the_proxys():
    from sentinel_proxy import confine
    assert inbox_hub.WRITE_WHYS == confine.WRITE_WHYS


# --------------------------------------------------------------------------- the log


async def test_write_confinable_and_its_reason_are_in_the_write_ahead_log_only_when_sent():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(write("c1", confinable=True, write_confinable=False, write_why="hard_link"))
    await r.send(write("c2", confinable=True, write_confinable=True))
    await r.send(call("c3", tool="read_text_file", args={"path": "/w/a.md"}, confinable=True))
    await wait_for(lambda: len(logged(st, "call_proposed")) == 3)
    props = {e[2]: e[3] for e in logged(st, "call_proposed")}
    assert props["c1"]["write_confinable"] is False and props["c1"]["write_why"] == "hard_link"
    assert props["c2"]["write_confinable"] is True and "write_why" not in props["c2"]
    assert "write_confinable" not in props["c3"]


GOOD = {"path": "/w/notes.md", "dev": 2049, "ino": 1234, "size_before": 6, "sha256_before": "a" * 64, "size_after": 12, "sha256_after": "b" * 64,
        "replaced": False, "undo": "/state/undo/c1/0"}


async def result(r, cid="c1", **extra):
    await r.send({"event": "proxy_result", "call_id": cid, "status": "ok", "summary": "done", **extra})


async def test_the_writes_the_proxy_reports_are_logged_with_the_result_and_shown_to_the_ui():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(write("c1", confinable=True, write_confinable=True))
    await wait_for(lambda: r.decisions())
    await result(r, writes=[GOOD])
    await wait_for(lambda: logged(st, "call_result"))
    rec = logged(st, "call_result")[0][3]
    assert rec["status"] == "ok" and rec["writes"] == [GOOD]
    assert "summary" not in rec                                       # the tool output is still not logged by default
    ui = r.ui.events("inbox_result")[0]
    assert ui["writes"] == [GOOD]


async def test_a_result_without_writes_is_logged_exactly_as_before():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(write("c1", confinable=True, write_confinable=True))
    await wait_for(lambda: r.decisions())
    await result(r)
    await wait_for(lambda: logged(st, "call_result"))
    assert "writes" not in logged(st, "call_result")[0][3] and "writes" not in r.ui.events("inbox_result")[0]


@pytest.mark.parametrize("bad", [
    "x", 5, {}, [None], [[]], [{}], [{**GOOD, "dev": "2049"}], [{**GOOD, "ino": True}], [{**GOOD, "sha256_before": "z" * 64}],
    [{**GOOD, "sha256_before": "a" * 63}], [{**GOOD, "sha256_before": None}], [{**GOOD, "size_before": -1}], [{**GOOD, "size_after": "12"}],
    [{**GOOD, "replaced": 0}], [{**GOOD, "undo": 5}], [{**GOOD, "path": ""}], [{**GOOD, "extra": 1}], [{k: v for k, v in GOOD.items() if k != "undo"}],
    [GOOD] * 65, [{**GOOD, "path": "/x" * 3000}],
])
async def test_malformed_writes_are_dropped_and_the_result_still_flows(bad):
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(write("c1", confinable=True, write_confinable=True))
    await wait_for(lambda: r.decisions())
    await result(r, writes=bad)
    await wait_for(lambda: logged(st, "call_result"))
    assert "writes" not in logged(st, "call_result")[0][3] and "writes" not in r.ui.events("inbox_result")[0] and not r.proxy.closed


async def test_a_write_that_was_replaced_or_left_no_hash_after_is_valid():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(write("c1", confinable=True, write_confinable=True))
    await wait_for(lambda: r.decisions())
    gone = {**GOOD, "size_after": None, "sha256_after": None, "replaced": True}
    await result(r, writes=[gone])
    await wait_for(lambda: logged(st, "call_result"))
    assert logged(st, "call_result")[0][3]["writes"] == [gone]


async def test_a_path_with_control_characters_is_cleaned_in_what_the_ui_sees():
    tl = Timeline()
    st = FakeStore(tl)
    r = await make(tl, st).start()
    await r.send(write("c1", confinable=True, write_confinable=True))
    await wait_for(lambda: r.decisions())
    await result(r, writes=[{**GOOD, "path": "/w/a‮\n.md"}])
    await wait_for(lambda: r.ui.events("inbox_result"))
    shown = r.ui.events("inbox_result")[0]["writes"][0]["path"]
    assert "\n" not in shown and "‮" not in shown
