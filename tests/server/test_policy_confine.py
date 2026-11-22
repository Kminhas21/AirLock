"""The `confine` rule key and the confinement floors (DECISIONS D31). An allow rule says which arguments are paths and what the call may do
with them; the proxy then runs the call in a worker the kernel confines to the named objects. Floors (stricter only): an allow without
`confine` asks, a path-slot argument outside `confine` asks, and an unconfinable server (or an old proxy) asks for path allows."""
import pytest

import policy as P

READ = {"id": "r", "verdict": "allow", "when": {"tool": "read_file", "arg_keys": ["path", "head"]}, "confine": {"path": "read"}}
TIME = {"id": "t", "verdict": "allow", "when": {"tool": "now", "arg_keys": ["timezone"]}, "confine": {}}


def pol(*rules, default="ask"):
    return P.Policy({"version": 1, "default": default, "rules": list(rules)})


def errors(*rules):
    with pytest.raises(P.PolicyError) as e:
        pol(*rules)
    return " | ".join(e.value.messages)


# --------------------------------------------------------------------------- validation, digest


def test_confine_is_accepted_on_allow_rules_and_part_of_the_digest():
    a, b = pol(READ), pol({**READ, "confine": {"path": "list"}})
    assert a.rules[0].confine == {"path": "read"} and b.rules[0].confine == {"path": "list"}
    assert a.digest() != b.digest() != pol({k: v for k, v in READ.items() if k != "confine"}).digest()
    assert pol(TIME).rules[0].confine == {}


@pytest.mark.parametrize("confine, msg", [
    ([], "must be an object"),
    ({"path": "append"}, "read"),
    ({"path": True}, "read"),
    ({"other": "read"}, "arg_keys"),
    ({f"k{i}": "read" for i in range(21)}, "at most 20"),
])
def test_bad_confine_maps_are_rejected(confine, msg):
    assert msg in errors({**READ, "confine": confine})


def test_confine_needs_arg_keys_and_an_allow_verdict():
    assert "arg_keys" in errors({"id": "x", "verdict": "allow", "when": {"tool": "t"}, "confine": {}})
    assert "allow" in errors({**READ, "verdict": "ask"})


# --------------------------------------------------------------------------- the floors


def test_a_confined_allow_carries_its_map_and_stays_an_allow_on_a_confinable_server():
    d = pol(READ).evaluate_call("fs", "read_file", {"path": "/w/a.txt"}, confinable=True)
    assert (d.verdict, d.rule_id, d.confine) == ("allow", "r", {"path": "read"})


def test_an_unconfinable_server_asks_for_a_path_allow_but_not_for_a_non_path_allow():
    d = pol(READ).evaluate_call("fs", "read_file", {"path": "/w/a.txt"}, confinable=False)
    assert (d.verdict, d.rule_id, d.reason, d.confine) == ("ask", "r", "unconfinable", None)
    assert pol(TIME).evaluate_call("t", "now", {"timezone": "UTC"}, confinable=False).verdict == "allow"


def test_an_allow_rule_without_confine_asks():
    rule = {k: v for k, v in READ.items() if k != "confine"}
    for confinable in (True, False):
        d = pol(rule).evaluate_call("fs", "read_file", {"path": "/w/a.txt"}, confinable=confinable)
        assert (d.verdict, d.rule_id, d.reason) == ("ask", "r", "unconfined")
    d = pol({"id": "e", "verdict": "allow", "when": {"tool": "echo"}}).evaluate_call("fs", "echo", {"text": "hi"}, confinable=True)
    assert (d.verdict, d.reason) == ("ask", "unconfined")          # no confine at all: even a non-path call asks


def test_a_path_slot_outside_confine_asks():
    rule = {**READ, "when": {"tool": "copy", "arg_keys": ["source", "destination"]}, "confine": {"source": "read"}}
    d = pol(rule).evaluate_call("fs", "copy", {"source": "/a", "destination": "/b"}, confinable=True)
    assert (d.verdict, d.reason) == ("ask", "unconfined")
    assert pol(rule).evaluate_call("fs", "copy", {"source": "/a"}, confinable=True).verdict == "allow"
    # an empty map is an operator's "these are not paths": a path slot in the call still asks
    bad = {**TIME, "when": {"tool": "now", "arg_keys": ["path"]}}
    assert pol(bad).evaluate_call("t", "now", {"path": "/etc"}, confinable=True).verdict == "ask"


def test_a_custom_key_is_a_path_only_when_the_rule_lists_it():
    rule = {"id": "c", "verdict": "allow", "when": {"tool": "open", "arg_keys": ["file_path"]}, "confine": {"file_path": "read"}}
    d = pol(rule).evaluate_call("x", "open", {"file_path": "/w/a"}, confinable=True)
    assert d.verdict == "allow" and d.confine == {"file_path": "read"}
    assert pol(rule).evaluate_call("x", "open", {"file_path": "/w/a"}, confinable=False).verdict == "ask"


def test_a_default_allow_asks_for_a_path_call_only():
    p = pol(default="allow")
    assert p.evaluate_call("fs", "read_file", {"path": "/w/a"}, confinable=True).verdict == "ask"
    assert p.evaluate_call("fs", "echo", {"text": "x"}, confinable=True).verdict == "allow"


def test_floors_never_loosen_deny_or_ask():
    deny = {"id": "d", "verdict": "deny", "when": {"tool": "read_file"}}
    assert pol(READ, deny).evaluate_call("fs", "read_file", {"path": "/a"}, confinable=True).verdict == "deny"
    assert pol(READ).evaluate_call("fs", "read_file", {"path": "/a"}, confinable=True, alerts_present=True).verdict == "ask"
    assert pol(READ).evaluate("fs", "read_file", {"path": "/a"}).confine == {"path": "read"}   # the raw verdict, before any floor


def test_lint_names_the_map_to_add():
    rule = {"id": "nc", "verdict": "allow", "when": {"tool": "read_file", "arg_keys": ["path", "tail"]}}
    w = " | ".join(pol(rule).lint())
    assert "nc" in w and '"confine": {"path": "read"}' in w
    w = " | ".join(pol({"id": "nk", "verdict": "allow", "when": {"tool": "now"}}).lint())
    assert "nk" in w and "arg_keys" in w and "confine" in w
    partial = {**READ, "when": {"tool": "copy", "arg_keys": ["source", "destination"]}, "confine": {"source": "read"}}
    assert "destination" in " | ".join(pol(partial).lint())
    assert not [x for x in pol(READ, TIME).lint() if "confine" in x]


@pytest.mark.parametrize("key", ["file_path", "filepath", "filename", "dir", "src", "dest", "uri", "url", "name", "FilePath", "target_dir",
                                 "output_file", "source_paths", "cwd_path"])
def test_lint_warns_when_an_empty_confine_is_paired_with_a_path_like_argument(key):
    """`confine: {}` asserts that no argument is a path. A custom name like file_path is not in PATH_SLOTS, so the proxy would treat it as
    a non-path and run the call unconfined: the lint says so (a warning, not a rejection: only the operator knows the tool)."""
    rule = {"id": "pl", "verdict": "allow", "when": {"tool": "x", "arg_keys": [key]}, "confine": {}}
    w = [x for x in pol(rule).lint() if "pl" in x and key in x]
    assert w and "confine" in w[0] and "not a path" in w[0], pol(rule).lint()


def test_lint_does_not_warn_for_ordinary_arguments_or_a_confine_entry():
    ok = {"id": "ok", "verdict": "allow", "when": {"tool": "x", "arg_keys": ["query", "names", "timezone", "limit"]}, "confine": {}}
    assert not [x for x in pol(ok).lint() if "not a path" in x]
    mapped = {"id": "m", "verdict": "allow", "when": {"tool": "x", "arg_keys": ["file_path"]}, "confine": {"file_path": "read"}}
    assert not [x for x in pol(mapped).lint() if "not a path" in x]


def test_the_starter_has_no_path_like_argument_under_an_empty_confine():
    import json, pathlib
    starter = P.Policy(json.loads((pathlib.Path(P.__file__).parent / "policies" / "starter.json").read_text()))
    assert not [x for x in starter.lint() if "not a path" in x]
