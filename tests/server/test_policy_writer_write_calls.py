"""What "Always allow" does on a call that WRITES (phase 1 of the "narrow write right" plan): the definition, pinned.

DEFINITION (today): a standing allow is built from the call's WRITTEN arguments. It lists every argument in `arg_keys`, and `confine` maps
each string argument in a path slot to `read` (`list` for a directory-listing tool). It NEVER carries a `write` right, so whatever the tool
is called, the worker the proxy starts for a later matching call holds READ_FILE on the named file and nothing that writes: an "Always allow"
on `write_file` cannot become an auto-allowed write, the write just fails with EACCES (tests/proxy/test_confined_call_failures.py runs it).
When a `write` right is added, this stays true until a rule says otherwise: `policy_writer` must keep refusing to emit it.

A call whose path-like argument is not a confine slot (Desktop Commander's `edit_block` uses `file_path`) cannot get an Always-allow:
`build_rule` refuses it (cannot_build), because `confine: {}` would run it in the session process, NOT in a confined worker."""
import itertools
import json

import pytest

import policy as P
import proposal_monitor
from policy_writer import build_rule
from sentinel_proxy import confine as pc
from sentinel_proxy import sandbox
from test_inbox_hub import Rig, call, wait_for

WRITE_BITS = (sandbox.FS_WRITE_FILE | sandbox.FS_TRUNCATE | sandbox.FS_MAKE_REG | sandbox.FS_MAKE_DIR | sandbox.FS_MAKE_SYM |
              sandbox.FS_REMOVE_FILE | sandbox.FS_REMOVE_DIR | sandbox.FS_REFER)

WRITE_CALLS = [
    ("write_file", {"path": "/proj/docs/notes.md", "content": "hello"}),
    ("edit_file", {"path": "/proj/docs/notes.md", "edits": [{"oldText": "a", "newText": "b"}], "dryRun": False}),
    ("move_file", {"source": "/proj/a.txt", "destination": "/proj/b.txt"}),
    ("create_directory", {"path": "/proj/newdir"}),
    ("write_pdf", {"path": "/proj/out.pdf", "content": "x"}),
    ("append_file", {"path": "/proj/log.txt", "content": "x"}),
    ("delete_file", {"path": "/proj/a.txt"}),
]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG"):
        monkeypatch.delenv(k, raising=False)
    P._reset_policy_cache()
    proposal_monitor._reset_errors()
    yield
    P._reset_policy_cache()
    proposal_monitor._reset_errors()


def policy_of(*rules):
    return P.Policy({"version": 1, "default": "ask", "rules": list(rules)})


# --------------------------------------------------------------------------- the rule built from a write call


@pytest.mark.parametrize("scope", ["exact", "tool_under"])
@pytest.mark.parametrize("tool, args", WRITE_CALLS)
def test_an_always_allow_on_a_write_call_confines_its_paths_to_read_never_write(tool, args, scope):
    try:
        rule = build_rule("allow", scope, "fs", tool, args)
    except ValueError as e:                                # tool_under needs a path key it can take the parent of; the cases that cannot are refused
        assert str(e) == "cannot_build"
        return
    assert rule["verdict"] == "allow" and rule["when"]["arg_keys"] == sorted(args)
    assert rule["confine"] and set(rule["confine"].values()) == {"read"}
    assert set(rule["confine"]) <= set(args) and all(isinstance(args[k], str) for k in rule["confine"])
    assert "write" not in json.dumps(rule["confine"]) and "write" not in " ".join(rule["confine"].values())
    policy_of(rule)                                         # and the real validator accepts it


def test_exact_always_allow_on_write_file_pins_path_and_content_and_confines_only_the_path():
    args = {"path": "/proj/docs/notes.md", "content": "hello"}
    rule = build_rule("allow", "exact", "fs", "write_file", args)
    assert rule["when"]["arg_keys"] == ["content", "path"] and rule["confine"] == {"path": "read"}
    assert {c["path"]: c["value"] for c in rule["when"]["args"]} == args
    d = policy_of(rule).evaluate_call("fs", "write_file", args, confinable=True)
    assert (d.verdict, d.confine) == ("allow", {"path": "read"})
    other = policy_of(rule).evaluate_call("fs", "write_file", {**args, "content": "other"}, confinable=True)
    assert other.verdict == "ask"                           # exact: another content is another call


def test_tool_under_always_allow_matches_any_content_under_the_directory_but_still_only_with_read():
    rule = build_rule("allow", "tool_under", "fs", "write_file", {"path": "/proj/docs/notes.md", "content": "x"})
    pol = policy_of(rule)
    d = pol.evaluate_call("fs", "write_file", {"path": "/proj/docs/other.md", "content": "anything at all"}, confinable=True)
    assert (d.verdict, d.confine) == ("allow", {"path": "read"})
    assert pol.evaluate_call("fs", "write_file", {"path": "/elsewhere/x.md", "content": "x"}, confinable=True).verdict == "ask"
    assert pol.evaluate_call("fs", "write_file", {"path": "/proj/docs/x.md", "content": "x", "mode": "w"}, confinable=True).verdict == "ask"  # extra key


@pytest.mark.parametrize("tool, args", WRITE_CALLS)
def test_the_grants_such_a_rule_produces_carry_no_write_bit(tool, args):
    """From rule to grant, pure: the right the proxy hands the worker is `read`, whose access bits contain nothing that writes."""
    try:
        rule = build_rule("allow", "exact", "fs", tool, args)
    except ValueError:                                         # a list value (edit_file's `edits`) cannot be pinned exactly: tool_under
        rule = build_rule("allow", "tool_under", "fs", tool, args)
    d = policy_of(rule).evaluate_call("fs", tool, args, confinable=True)
    assert d.verdict == "allow" and d.confine == rule["confine"]

    class SC:                                                 # a sandboxed server whose directory argument is /proj
        args, cwd = ["/proj"], None
    specs = pc.grant_specs(args, d.confine, SC())
    assert specs and {right for _b, _v, right in specs} == {"read"}
    for _b, _v, right in specs:
        assert sandbox.GRANT_RIGHTS[right] & WRITE_BITS == 0
        assert sandbox.rule_access(sandbox.GRANT_RIGHTS[right], 7, is_dir=False) & WRITE_BITS == 0
    sandbox.validate_spec(pc.confined_spec({"read": [], "write": [], "runtime": [], "network": "none", "env_allow": [], "rlimits": {},
                                            "require": True}, specs), internal=True)         # a valid worker spec: it will start, and not write


def test_deny_and_ask_rules_built_from_a_write_call_have_no_confine():
    for verdict in ("deny", "ask"):
        assert "confine" not in build_rule(verdict, "exact", "fs", "write_file", {"path": "/proj/a.md", "content": "x"})


def test_the_writer_never_emits_a_write_right_for_any_combination_of_tool_and_arguments():
    """A small exhaustive sweep: every right in any built rule is `read` or `list`, and only on keys the rule lists in arg_keys."""
    keys = ["path", "paths", "source", "destination", "directory", "file", "target", "file_path", "filename", "content", "mode", "edits"]
    tools = ["write_file", "edit_file", "write", "create", "put", "save", "write_file_atomic", "list_directory", "directory_tree"]
    built = 0
    for tool, ks in itertools.product(tools, itertools.chain.from_iterable(itertools.combinations(keys, n) for n in (1, 2, 3))):
        args = {k: "/proj/a/b.txt" for k in ks}
        for verdict, scope in (("allow", "exact"), ("allow", "tool_under")):
            try:
                rule = build_rule(verdict, scope, "fs", tool, args)
            except ValueError:
                continue
            built += 1
            assert set(rule["confine"].values()) <= {"read", "list"}, (tool, ks, rule["confine"])
            assert set(rule["confine"]) <= set(rule["when"]["arg_keys"])
    assert built > 1000


def test_the_only_rights_policy_accepts_in_a_confine_map_are_the_ones_the_writer_emits():
    assert P.CONFINE_RIGHTS == ("read", "list")
    for right in ("read", "list"):
        policy_of({"id": "x", "verdict": "allow", "when": {"tool": "t", "arg_keys": ["path"]}, "confine": {"path": right}})


# --------------------------------------------------------------------------- the gap


def test_an_always_allow_on_a_custom_path_key_cannot_be_built():
    """FIXED: `file_path` (Desktop Commander edit_block) is path-like but not a confine slot. A rule with `confine: {}` would auto-allow the
    call with no confine map and the proxy would run it in the session process, so `build_rule` refuses it (the card has no Always-allow)."""
    args = {"file_path": "/proj/src/app.py", "old_string": "a", "new_string": "b"}
    for scope in ("exact", "tool_under"):
        with pytest.raises(ValueError, match="cannot_build"):
            build_rule("allow", scope, "dc", "edit_block", args)
    for k in ("filepath", "src", "dest", "uri", "some_path", "out_dir", "target_file"):          # the lint's notion of path-like
        with pytest.raises(ValueError, match="cannot_build"):
            build_rule("allow", "exact", "dc", "t", {k: "x"})
    build_rule("allow", "exact", "dc", "t", {"old_string": "a"})                                 # a non-path call still builds
    build_rule("deny", "exact", "dc", "edit_block", args)                                         # only an allow is a problem


def test_a_tool_under_always_allow_on_a_custom_path_key_cannot_be_built_at_all():
    with pytest.raises(ValueError, match="cannot_build"):
        build_rule("allow", "tool_under", "dc", "edit_block", {"file_path": "/proj/src/app.py", "old_string": "a", "new_string": "b"})


# --------------------------------------------------------------------------- through the hub (the card's button)


@pytest.fixture
def pfile(monkeypatch, tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(json.dumps({"version": 1, "default": "ask", "rules": []}))
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "1")
    return f


async def always_allow(r, scope="exact"):
    await r.hub.handle_ui_frame({"event": "inbox_rule_request", "session_id": "s1", "call_id": "c1", "verdict": "allow", "scope": scope,
                                 "confirm": True})
    await wait_for(lambda: r.ui.events("inbox_rule_result"))
    return r.ui.events("inbox_rule_result")[-1]


@pytest.mark.parametrize("scope", ["exact", "tool_under"])
async def test_always_allow_on_a_held_write_file_card_writes_a_read_only_confined_rule(pfile, scope):
    r = await Rig().start()
    await r.send(call("c1", tool="write_file", args={"path": "/proj/docs/notes.md", "content": "hello"}))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    res = await always_allow(r, scope)
    assert res["ok"] is True and res["applies"] == "new_sessions"
    [rule] = json.loads(pfile.read_text())["rules"]
    assert rule["confine"] == {"path": "read"} and rule["verdict"] == "allow" and "write" not in json.dumps(rule["confine"])
    # a NEW session decides the same call by that rule, and the decision it sends carries a read-only confine map
    P._reset_policy_cache()
    r2 = await Rig().start()
    await r2.send(call("n1", tool="write_file", args={"path": "/proj/docs/notes.md", "content": "hello"}, confinable=True))
    await wait_for(lambda: r2.decisions())
    d = r2.decisions()[0]
    assert (d["decision"], d["reason"], d["confine"]) == ("approve", "policy", {"path": "read"})


@pytest.mark.parametrize("scope", ["exact", "tool_under"])
async def test_always_allow_on_an_edit_block_card_is_refused_cannot_build_and_writes_nothing(pfile, scope):
    r = await Rig().start()
    await r.send(call("c1", tool="edit_block", args={"file_path": "/proj/src/app.py", "old_string": "a", "new_string": "b"}))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    before = pfile.read_text()
    res = await always_allow(r, scope)
    assert res["ok"] is False and res["reason"] == "cannot_build"
    assert pfile.read_text() == before
