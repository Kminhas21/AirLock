"""`when.arg_keys` (B3): a rule matches only if every top-level argument name of the call is in the list, and the stricter-of
evaluation over symlink-resolved argument forms (B4, server/resolved_args.py)."""
import pytest

import policy as P
import resolved_args as RA
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
    assert pol([allow_keys(["path"], args=[{"path": "path.x", "op": "exists"}])]).lint() == []
    assert not any("arg_keys" in w for w in pol([allow_keys(["path"], args=[{"path": "other", "op": "not_exists"}])]).lint())


# ---------------------------------------------------------------------------------------------------------- stricter-of

def D(v, rid=None):
    return P.Decision(v, rid, (), "x")


def test_stricter_orders_deny_ask_allow_and_keeps_the_first_on_a_tie():
    assert P.stricter(D("allow"), D("ask")).verdict == "ask"
    assert P.stricter(D("ask"), D("allow")).verdict == "ask"
    assert P.stricter(D("ask"), D("deny")).verdict == "deny"
    assert P.stricter(D("allow", "a"), D("allow", "b")).rule_id == "a"
    esc = P.Decision("ask", "allow-x", (), "alert", True)
    assert P.stricter(esc, D("ask", "ask-y")).rule_id == "ask-y"          # the rule that holds the call is named, not the escalated allow
    assert P.stricter(D("ask", "ask-y"), esc).rule_id == "ask-y"


def test_with_an_alert_the_card_names_the_sensitive_rule_of_the_resolved_form():
    v, bad = RA.parse([{"path": "/w/.env"}], {"path": "notes.txt"})
    d = RA.evaluate(STARTER, "fs", "read_text_file", {"path": "notes.txt"}, v, bad, alerts_present=True)
    assert d.verdict == "ask" and d.rule_id == "ask-sensitive-path"


# ------------------------------------------------------------------------------------------------- resolved form (hub side)

STARTER = P.load_policy("builtin:starter")


def evr(args, resolved, incomplete=False, tool="read_text_file"):
    variants, bad = RA.parse(resolved, args, incomplete)
    return RA.evaluate(STARTER, "fs", tool, args, variants, bad, alerts_present=False, secrets_used=False), variants, bad


def test_a_symlink_to_a_sensitive_file_is_asked():
    d, v, bad = evr({"path": "/w/notes.txt"}, [{"path": "/w/.env"}])
    assert d.verdict == "ask" and d.rule_id == "ask-sensitive-path" and not bad
    assert v == [{"path": "/w/.env"}]


def test_a_symlink_inside_a_list_is_asked():
    d, _, _ = evr({"paths": ["/w/a", "/w/b"]}, [{"paths": {"1": "/home/u/.ssh/id_rsa"}}], tool="read_multiple_files")
    assert d.verdict == "ask"


def test_a_harmless_resolution_keeps_the_allow_and_no_resolution_is_todays_behaviour():
    assert evr({"path": "/w/a"}, [{"path": "/real/w/a"}])[0].verdict == "allow"
    assert evr({"path": "/w/a"}, None)[0].verdict == "allow"


def test_the_resolved_form_can_never_loosen():
    # the written form asks; a resolution to something harmless does not turn it into an allow
    assert evr({"path": "/w/.env"}, [{"path": "/w/plain"}])[0].verdict == "ask"


@pytest.mark.parametrize("bad", [
    "x", 5, {}, {"path": "/x"}, [5], ["x"], [{"nope": "/x"}], [{"path": 5}], [{"path": "/x\x00"}], [{"path": "x" * 5000}],
    [{"path": {"0": "/x"}}],                      # path is a string, not a list
    [{"paths": "/x"}],                            # paths is a list, not a string
    [{"paths": {"9": "/x"}}], [{"paths": {"a": "/x"}}], [{"paths": {"0": 5}}], [{"paths": {"-1": "/x"}}],
    [{"path": "/x"}] * 9, [{f"k{i}": "/x" for i in range(65)}],
    [{"path": "/x", "isUrl": "/y"}],             # isUrl is not a string argument
])
def test_a_malformed_resolution_never_crashes_and_can_only_make_things_stricter(bad):
    args = {"path": "/w/a", "paths": ["/w/a"], "isUrl": False}
    variants, invalid = RA.parse(bad, args, False)
    assert invalid and variants == []
    d = RA.evaluate(STARTER, "fs", "read_text_file", {"path": "/w/a"}, variants, invalid)
    assert d.verdict == "ask"


def test_an_incomplete_resolution_floors_an_allow_at_ask():
    d, _, bad = evr({"path": "/w/a"}, [], incomplete=True)
    assert bad and d.verdict == "ask"


def test_substitute_does_not_modify_the_written_args():
    args = {"path": "/w/a", "paths": ["/w/a", "/w/b"]}
    out = RA.substitute(args, {"path": "/r/a", "paths": {"1": "/r/b"}})
    assert out == {"path": "/r/a", "paths": ["/w/a", "/r/b"]}
    assert args == {"path": "/w/a", "paths": ["/w/a", "/w/b"]}


def test_evaluate_never_raises():
    class Boom:
        def evaluate(self, *a, **k):
            raise RuntimeError("x")
    assert RA.evaluate(Boom(), "fs", "t", {}, [], False).verdict == "ask"


def test_a_floored_allow_does_not_name_the_allow_rule():
    v, bad = RA.parse("junk", {"path": "/w/a"})
    d = RA.evaluate(STARTER, "fs", "read_text_file", {"path": "/w/a"}, v, bad)
    assert d.verdict == "ask" and d.rule_id is None and d.reason == "resolved_invalid"
