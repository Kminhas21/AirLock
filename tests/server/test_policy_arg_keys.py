"""`when.arg_keys` (B3): a rule matches only if every top-level argument name of the call is in the list. (The B4 symlink resolution that
lived here is gone: DECISIONS D31, tests/server/test_policy_confine.py.)"""
import pytest

import policy as P
from policy import Policy, PolicyError, load_policy


def pol(rules, default="ask"):
    return load_policy({"version": 1, "default": default, "rules": rules})


def allow_keys(keys, **when):
    return {"id": "a", "verdict": "allow", "when": {"tool": "read_file", "arg_keys": keys, **when}}


# ------------------------------------------------------------------------------------------------------------- matching

def test_allow_matches_only_when_every_key_is_listed():
    p = pol([allow_keys(["path", "head"])])
    assert p.evaluate("s", "read_file", {"path": "/a"}).verdict == "allow"
    assert p.evaluate("s", "read_file", {"path": "/a", "head": 3}).verdict == "allow"
    assert p.evaluate("s", "read_file", {}).verdict == "allow"
    for extra in ({"path": "/a", "isUrl": True}, {"path": "/a", "isUrl": False}, {"path": "/a", "Path": "/b"}, {"x": 1}):
        assert p.evaluate("s", "read_file", extra).verdict == "ask", extra


def test_empty_list_means_no_arguments_at_all():
    p = pol([{"id": "a", "verdict": "allow", "when": {"tool": "read_graph", "arg_keys": []}}])
    assert p.evaluate("s", "read_graph", {}).verdict == "allow"
    assert p.evaluate("s", "read_graph", {"q": "x"}).verdict == "ask"


@pytest.mark.parametrize("args", [None, [], ["path"], "path", 5, True])
def test_args_not_a_mapping_never_match_an_allow_rule_but_do_match_ask_and_deny(args):
    assert pol([allow_keys(["path"])]).evaluate("s", "read_file", args).verdict == "ask"
    for verdict in ("ask", "deny"):
        p = pol([{"id": "r", "verdict": verdict, "when": {"arg_keys": ["path"]}}], default="allow")
        assert p.evaluate("s", "read_file", args).verdict == verdict


def test_ask_rule_with_arg_keys_matches_only_listed_keys():
    p = pol([{"id": "q", "verdict": "ask", "when": {"arg_keys": ["a"]}}], default="allow")
    assert p.evaluate("s", "t", {"a": 1}).verdict == "ask"
    assert p.evaluate("s", "t", {"a": 1, "b": 2}).verdict == "allow"


def test_arg_keys_is_combined_with_the_other_conditions():
    p = pol([allow_keys(["path"], args=[{"path": "path", "op": "glob", "value": "/p/*"}])])
    assert p.evaluate("s", "read_file", {"path": "/p/a"}).verdict == "allow"
    assert p.evaluate("s", "read_file", {"path": "/q/a"}).verdict == "ask"


def test_key_comparison_is_exact():
    p = pol([allow_keys(["path"])])
    for k in ("PATH", "path ", "patħ", "path\x00"):
        assert p.evaluate("s", "read_file", {k: "/a"}).verdict == "ask", k


def test_many_keys_do_not_raise_or_allow():
    p = pol([allow_keys(["path"])])
    args = {f"k{i}": i for i in range(20000)}
    assert p.evaluate("s", "read_file", args).verdict == "ask"


# ----------------------------------------------------------------------------------------------------------- validation

@pytest.mark.parametrize("bad", ["path", None, 5, {"path": 1}, [""], [5], ["a", None], ["a\x00"], ["x" * 201],
                                 [f"k{i}" for i in range(101)]])
def test_bad_arg_keys_are_rejected_with_a_message(bad):
    with pytest.raises(PolicyError) as e:
        pol([allow_keys(bad)])
    assert any("arg_keys" in m for m in e.value.messages), e.value.messages


def test_arg_keys_counts_towards_specificity_and_canonical_form_and_digest():
    a = pol([allow_keys(["path"])])
    b = pol([allow_keys(["path", "head"])])
    c = pol([{"id": "a", "verdict": "allow", "when": {"tool": "read_file"}}])
    assert len({a.digest(), b.digest(), c.digest()}) == 3
    assert P._canon_when(a.rules[0]) != P._canon_when(b.rules[0]) != P._canon_when(c.rules[0])
    same = pol([allow_keys(["head", "path", "path"])])
    assert P._canon_when(same.rules[0]) == P._canon_when(b.rules[0])
    assert a.rules[0].specificity == c.rules[0].specificity + 1


def test_rules_differing_only_in_arg_keys_are_not_reported_as_duplicates():
    p = pol([allow_keys(["path"]), {"id": "b", "verdict": "allow", "when": {"tool": "read_file", "arg_keys": ["path", "head"]}}])
    assert not any("duplicate" in w for w in p.lint())


def test_lint_warns_when_an_args_condition_names_a_key_outside_arg_keys():
    p = pol([allow_keys(["path"], args=[{"path": "paths", "op": "exists"}])])
    assert any("arg_keys" in w and "paths" in w for w in p.lint())
    assert [w for w in pol([allow_keys(["path"], args=[{"path": "path.x", "op": "exists"}])]).lint() if "confine" not in w] == []
    assert not any("arg_keys" in w for w in pol([allow_keys(["path"], args=[{"path": "other", "op": "not_exists"}])]).lint())
