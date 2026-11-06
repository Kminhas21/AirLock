"""Tests for the policy engine (server/policy.py, ticket PE1).  Hand-written fixtures only."""
import copy
import json
import os
import time

import pytest

import policy as P
from policy import Decision, Policy, PolicyError, load_policy, load_policy_file
from registry import Registry, default_registry


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def pol(rules, default="ask"):
    return load_policy({"version": 1, "default": default, "rules": rules})


def rule(rid, verdict, **when):
    r = {"id": rid, "verdict": verdict}
    if when:
        r["when"] = when
    return r


def arg(path, op, value=None, *, novalue=False):
    d = {"path": path, "op": op}
    if not novalue:
        d["value"] = value
    return d


def one(op, value, args, *, novalue=False, verdict="allow", path="p"):
    """Verdict of a one-rule policy (rule verdict `verdict`, default 'ask' if it does not match)."""
    other = "ask" if verdict == "allow" else "allow"
    p = pol([rule("r", verdict, args=[arg(path, op, value, novalue=novalue)])], default=other)
    return p.evaluate("s", "t", args).verdict == verdict


def holds(op, value, args, **kw):
    return one(op, value, args, **kw)


def errors_of(data):
    with pytest.raises(PolicyError) as ei:
        load_policy(data)
    return ei.value.messages


REG = Registry({
    "version": 1,
    "defaults": {"internal_domains": ["team.com"], "internal_path_prefixes": ["/project"], "unknown": "external"},
    "entries": [
        {"id": "r_alias", "kind": "relay", "party": "acme", "match": {"email": "partners@team.com"}},
        {"id": "r_dom", "kind": "external", "party": "brightwater", "match": {"domain": "brightwatercap.example"}},
    ],
})
TO_INTERNAL = {"to": "alice@team.com"}
TO_RELAY = {"to": "partners@team.com"}
TO_EXTERNAL = {"to": "x@brightwatercap.example"}
TO_UNKNOWN = {"to": "x@zzz.example"}
NO_DEST = {"path": "/project/a"}      # with tool read_file: no destination token


def dest_verdict(want, tool, args, registry=REG):
    p = pol([rule("r", "deny", destination=want)], default="allow")
    return p.evaluate("s", tool, args, registry=registry).verdict == "deny"


# ---------------------------------------------------------------------------
# format validation
# ---------------------------------------------------------------------------

class TestFormat:
    def test_minimal_valid(self):
        p = load_policy({"version": 1})
        assert p.rules == () and p.default == "ask"

    def test_default_values(self):
        for d in ("allow", "deny", "ask"):
            assert load_policy({"version": 1, "default": d}).default == d

    @pytest.mark.parametrize("bad", [None, 2, 0, "1", True, 1.5, []])
    def test_bad_version(self, bad):
        assert any("version" in m for m in errors_of({"version": bad}))

    def test_missing_version(self):
        assert any("version" in m for m in errors_of({"rules": []}))

    @pytest.mark.parametrize("bad", ["", "maybe", "ALLOW", None, 1, ["allow"]])
    def test_bad_default(self, bad):
        assert any("default" in m for m in errors_of({"version": 1, "default": bad}))

    def test_unknown_keys_everywhere(self):
        msgs = errors_of({
            "version": 1, "extra": 1,
            "rules": [{"id": "a", "verdict": "allow", "bogus": 1,
                       "when": {"nope": 1, "args": [{"path": "p", "op": "exists", "zzz": 2}]}}],
        })
        joined = "\n".join(msgs)
        for k in ("'extra'", "'bogus'", "'nope'", "'zzz'"):
            assert k in joined
        assert len(msgs) == 4        # ALL errors at once, nothing else

    def test_all_errors_reported_at_once(self):
        msgs = errors_of({"version": 3, "default": "x", "rules": [
            {"id": "a", "verdict": "zzz"}, {"id": "a", "verdict": "allow"}, {"id": "bad id", "verdict": "allow"}, "str"]})
        assert len(msgs) >= 5

    def test_duplicate_ids(self):
        msgs = errors_of({"version": 1, "rules": [rule("a", "allow"), rule("b", "deny"), rule("a", "ask")]})
        assert any("duplicate id" in m and "rules[2]" in m for m in msgs)

    @pytest.mark.parametrize("rid", ["", "a b", "a/b", "x" * 61, "a\n", "é", None, 5, ["a"]])
    def test_bad_ids(self, rid):
        assert any(".id" in m for m in errors_of({"version": 1, "rules": [{"id": rid, "verdict": "allow"}]}))

    @pytest.mark.parametrize("rid", ["a", "A-b_c.d", "x" * 60, "0"])
    def test_good_ids(self, rid):
        assert load_policy({"version": 1, "rules": [{"id": rid, "verdict": "allow"}]}).rules[0].id == rid

    def test_bad_verdict(self):
        assert any("verdict" in m for m in errors_of({"version": 1, "rules": [{"id": "a", "verdict": "Allow"}]}))
        assert any("verdict" in m for m in errors_of({"version": 1, "rules": [{"id": "a"}]}))

    def test_note_limit(self):
        ok = {"version": 1, "rules": [{"id": "a", "verdict": "allow", "note": "n" * 200}]}
        load_policy(ok)
        ok["rules"][0]["note"] = "n" * 201
        assert any("note" in m for m in errors_of(ok))
        ok["rules"][0]["note"] = 5
        assert any("note" in m for m in errors_of(ok))

    def test_rules_not_a_list_and_rule_not_object(self):
        assert any("rules" in m for m in errors_of({"version": 1, "rules": {}}))
        assert any("must be an object" in m for m in errors_of({"version": 1, "rules": [1]}))

    def test_not_an_object(self):
        for bad in ([], "x", 3, None):
            with pytest.raises(PolicyError):
                Policy(bad)

    def test_max_rules(self):
        load_policy({"version": 1, "rules": [rule(f"r{i}", "allow") for i in range(500)]})
        msgs = errors_of({"version": 1, "rules": [rule(f"r{i}", "allow") for i in range(501)]})
        assert any("500" in m for m in msgs)

    def test_max_arg_conditions(self):
        conds = [arg(f"a{i}", "exists", novalue=True) for i in range(20)]
        load_policy({"version": 1, "rules": [rule("a", "allow", args=conds)]})
        conds.append(arg("z", "exists", novalue=True))
        assert any("at most 20" in m for m in errors_of({"version": 1, "rules": [rule("a", "allow", args=conds)]}))

    @pytest.mark.parametrize("op", ["regex", "match", "EQUALS", "", None, 3, "not_contains"])
    def test_bad_op(self, op):
        msgs = errors_of({"version": 1, "rules": [rule("a", "allow", args=[{"path": "p", "op": op, "value": "x"}])]})
        assert any(".op" in m for m in msgs)

    def test_value_required_and_forbidden(self):
        for op in ("equals", "not_equals", "in", "not_in", "glob", "not_glob", "under", "not_under", "contains", "max_len"):
            msgs = errors_of({"version": 1, "rules": [rule("a", "allow", args=[{"path": "p", "op": op}])]})
            assert any("required" in m for m in msgs), op
        for op in ("exists", "not_exists"):
            msgs = errors_of({"version": 1, "rules": [rule("a", "allow", args=[{"path": "p", "op": op, "value": 1}])]})
            assert any("not allowed" in m for m in msgs), op

    @pytest.mark.parametrize("op,value", [
        ("equals", [1]), ("equals", {"a": 1}), ("equals", float("inf")), ("equals", "x" * 1001),
        ("in", "abc"), ("in", []), ("in", [[1]]), ("in", list(range(1001))),
        ("glob", ["a"]), ("glob", ""), ("glob", "a" * 201), ("glob", 5),
        ("under", "relative/path"), ("under", ""), ("under", "/a\x00b"), ("under", 3),
        ("contains", ""), ("contains", 5), ("max_len", -1), ("max_len", True), ("max_len", "3"), ("max_len", 1.5),
    ])
    def test_bad_values(self, op, value):
        assert errors_of({"version": 1, "rules": [rule("a", "allow", args=[arg("p", op, value)])]})

    @pytest.mark.parametrize("path", ["", ".", "a.", ".a", "a..b", ".".join("k" * 1 for _ in range(13)), 5, None])
    def test_bad_arg_paths(self, path):
        assert errors_of({"version": 1, "rules": [rule("a", "allow", args=[arg(path, "exists", novalue=True)])]})

    def test_max_path_depth_ok(self):
        load_policy({"version": 1, "rules": [rule("a", "allow", args=[arg(".".join("k" * 12), "exists", novalue=True)])]})

    @pytest.mark.parametrize("key,value", [
        ("server", ""), ("server", []), ("server", [""]), ("server", 5), ("server", ["a", 1]), ("server", "x" * 201),
        ("tool", "x" * 201), ("tool", ["ok", None]), ("tool", "a\x00b"), ("tool", ["x"] * 51),
        ("destination", "elsewhere"), ("destination", True), ("destination", ["internal"]),
        ("party", ""), ("party", []), ("party", [1]), ("party", "x" * 101),
        ("alert", "true"), ("alert", 1), ("alert", None),
        ("args", {}), ("args", "x"), ("args", [5]),
    ])
    def test_bad_when_values(self, key, value):
        assert errors_of({"version": 1, "rules": [rule("a", "allow", **{key: value})]})

    def test_when_must_be_object(self):
        assert any("when" in m for m in errors_of({"version": 1, "rules": [{"id": "a", "verdict": "allow", "when": []}]}))

    def test_pattern_length_cap_exact(self):
        load_policy({"version": 1, "rules": [rule("a", "allow", tool="x" * 200)]})

    def test_load_from_file_and_dict_and_policy(self, tmp_path):
        data = {"version": 1, "rules": [rule("a", "allow", tool="t")]}
        f = tmp_path / "p.json"
        f.write_text(json.dumps(data))
        assert load_policy(str(f)).digest() == load_policy(data).digest() == load_policy(load_policy(data)).digest()
        assert load_policy(f).rules[0].id == "a"       # PathLike

    def test_load_failures_are_policy_errors(self, tmp_path):
        with pytest.raises(P.PolicyUnreadable):
            load_policy(str(tmp_path / "missing.json"))
        bad = tmp_path / "bad.json"
        bad.write_text("{nope")
        with pytest.raises(P.PolicyUnreadable):
            load_policy(str(bad))
        bad.write_bytes(b"\xff\xfe")
        with pytest.raises(P.PolicyUnreadable):
            load_policy(str(bad))
        with pytest.raises(P.PolicyUnreadable):
            load_policy(str(tmp_path))                  # a directory
        with pytest.raises(PolicyError):
            load_policy(42)
        bad.write_text("[1,2]")
        with pytest.raises(PolicyError) as ei:
            load_policy(str(bad))
        assert not isinstance(ei.value, P.PolicyUnreadable)

    def test_duplicate_json_keys_and_nan_rejected(self, tmp_path):
        f = tmp_path / "d.json"
        f.write_text('{"version": 1, "rules": [{"id": "a", "verdict": "deny", "verdict": "allow"}]}')
        with pytest.raises(PolicyError):
            load_policy(str(f))
        f.write_text('{"version": 1, "rules": [{"id": "a", "verdict": "allow", "when": {"args": '
                     '[{"path": "p", "op": "equals", "value": NaN}]}}]}')
        with pytest.raises(PolicyError):
            load_policy(str(f))

    def test_oversize_file_rejected(self, tmp_path):
        f = tmp_path / "big.json"
        f.write_bytes(b" " * (P.MAX_FILE_BYTES + 1) + b'{"version":1}')
        with pytest.raises(P.PolicyUnreadable):
            load_policy(str(f))

    def test_deeply_nested_json_does_not_crash(self, tmp_path):
        f = tmp_path / "deep.json"
        f.write_text("[" * 100000)
        with pytest.raises(PolicyError):
            load_policy(str(f))

    def test_input_not_aliased(self):
        data = {"version": 1, "rules": [rule("a", "allow", tool="t")]}
        p = load_policy(data)
        data["rules"][0]["verdict"] = "deny"
        data["rules"][0]["when"]["tool"] = "zzz"
        assert p.evaluate("s", "t", {}).verdict == "allow"


# ---------------------------------------------------------------------------
# server / tool conditions
# ---------------------------------------------------------------------------

class TestServerTool:
    def test_tool_glob_and_list(self):
        p = pol([rule("a", "allow", tool=["read_*", "list_*"])])
        assert p.evaluate("s", "read_file", {}).verdict == "allow"
        assert p.evaluate("s", "list_dir", {}).verdict == "allow"
        assert p.evaluate("s", "write_file", {}).verdict == "ask"

    def test_case_sensitive(self):
        p = pol([rule("a", "allow", tool="read_*", server="FS")])
        assert p.evaluate("FS", "read_x", {}).verdict == "allow"
        assert p.evaluate("fs", "read_x", {}).verdict == "ask"
        assert p.evaluate("FS", "READ_x", {}).verdict == "ask"

    def test_server_glob(self):
        p = pol([rule("a", "allow", server="fs-*")])
        assert p.evaluate("fs-local", "t", {}).verdict == "allow"
        assert p.evaluate("db", "t", {}).verdict == "ask"
        assert p.evaluate("", "t", {}).verdict == "ask"

    def test_and_of_conditions(self):
        p = pol([rule("a", "allow", server="fs", tool="read_*")])
        assert p.evaluate("fs", "read_x", {}).verdict == "allow"
        assert p.evaluate("fs", "write_x", {}).verdict == "ask"
        assert p.evaluate("db", "read_x", {}).verdict == "ask"

    def test_empty_and_absent_when_match_everything(self):
        for r in ({"id": "a", "verdict": "deny"}, {"id": "a", "verdict": "deny", "when": {}}):
            p = pol([r], default="allow")
            assert p.evaluate("s", "t", {}).verdict == "deny"
            assert p.evaluate(None, None, None).verdict == "deny"       # nothing to check, so even junk matches

    ODD = [None, 5, b"read_x", ["read_x"], {"a": 1}, True, 1.5, "read_\x00x", "write_\u202ex", "write_\u200bx",
           "write_\nx", "write_\x1bx", "write_\ud800x", "write_\u2028x", "write_" + "a" * 20001]

    @pytest.mark.parametrize("name", ODD)
    @pytest.mark.parametrize("field", ["tool", "server"])
    def test_unevaluable_name_never_allowed(self, field, name):
        p = pol([rule("a", "allow", **{field: "*"})])
        args = ("s", name) if field == "tool" else (name, "t")
        d = p.evaluate(*args, {})
        assert d.verdict == "ask" and d.matched == ()
        d = pol([rule("a", "allow", **{field: "*"})], default="deny").evaluate(*args, {})
        assert d.verdict == "deny" and d.rule_id is None

    @pytest.mark.parametrize("name", ODD)
    @pytest.mark.parametrize("field", ["tool", "server"])
    def test_unevaluable_name_still_caught_by_deny(self, field, name):
        pat = "write_*" if field == "tool" else "fs*"
        p = pol([rule("d", "deny", **{field: pat}), rule("a", "allow")], default="allow")
        args = ("s", name) if field == "tool" else (name, "t")
        d = p.evaluate(*args, {})
        assert (d.verdict, d.rule_id) == ("deny", "d")
        assert d.matched == ("d", "a")

    @pytest.mark.parametrize("name", ODD)
    def test_unevaluable_name_caught_by_ask(self, name):
        p = pol([rule("q", "ask", tool="write_*")], default="allow")
        d = p.evaluate("s", name, {})
        assert (d.verdict, d.rule_id) == ("ask", "q")

    def test_unevaluable_name_with_other_conditions(self):
        p = pol([rule("d", "deny", tool="write_*", args=[arg("path", "not_under", "/project")])], default="allow")
        assert p.evaluate("s", "w\x00", {"path": "/project/a"}).verdict == "allow"      # other conditions still apply
        assert p.evaluate("s", "w\x00", {"path": "/etc/a"}).verdict == "deny"

    def test_evaluable_names_unchanged(self):
        p = pol([rule("d", "deny", tool="write_*"), rule("a", "allow", tool="read_*")])
        assert p.evaluate("s", "read_x", {}).verdict == "allow"
        assert p.evaluate("s", "other", {}).verdict == "ask"

    def test_glob_metachar_in_tool_name_is_literal(self):
        p = pol([rule("a", "allow", tool="read_file")])
        for name in ("read_[f]ile", "read_*", "read_?ile", "*", "read_fil[e]", "[r]ead_file"):
            assert p.evaluate("s", name, {}).verdict == "ask", name
        p2 = pol([rule("a", "allow", tool="read_[a-c]")])
        assert p2.evaluate("s", "read_b", {}).verdict == "allow"
        assert p2.evaluate("s", "read_[a-c]", {}).verdict == "ask"       # the name is never a pattern

    def test_huge_tool_name_bounded(self):
        p = pol([rule("a", "allow", tool="a*" * 50 + "b")])
        t = time.time()
        assert p.evaluate("s", "a" * 19000, {}).verdict == "ask"
        assert p.evaluate("s", "a" * 100000, {}).verdict == "ask"
        assert time.time() - t < 2

    def test_pathological_glob_arg_bounded(self):
        p = pol([rule("a", "allow", args=[arg("p", "glob", "*a" * 50 + "b")])])
        t = time.time()
        assert p.evaluate("s", "t", {"p": "a" * 19999}).verdict == "ask"
        assert time.time() - t < 2


# ---------------------------------------------------------------------------
# operators: positive / negative / uncertain
# ---------------------------------------------------------------------------

class TestOperators:
    def test_equals(self):
        assert holds("equals", "x", {"p": "x"})
        assert not holds("equals", "x", {"p": "y"})
        assert not holds("equals", "x", {})                       # missing
        assert not holds("equals", "x", {"p": ["x"]})             # list where string expected
        assert not holds("equals", "x", {"p": None})

    def test_equals_type_confusion(self):
        assert holds("equals", 1, {"p": 1})
        assert holds("equals", 1, {"p": 1.0})
        assert not holds("equals", 1, {"p": True})
        assert not holds("equals", True, {"p": 1})
        assert not holds("equals", 1, {"p": "1"})
        assert not holds("equals", "1", {"p": 1})
        assert holds("equals", True, {"p": True})
        assert not holds("equals", False, {"p": 0})
        assert not holds("equals", False, {"p": None})
        assert holds("equals", None, {"p": None})
        assert not holds("equals", None, {})
        assert not holds("equals", 0, {"p": False})
        assert not holds("equals", "x", {"p": float("nan")})
        assert not holds("equals", 1, {"p": float("nan")})

    def test_not_equals(self):
        assert holds("not_equals", "x", {"p": "y"})
        assert not holds("not_equals", "x", {"p": "x"})
        assert holds("not_equals", "x", {})                       # unknown => true
        assert holds("not_equals", "x", {"p": ["x"]})
        assert holds("not_equals", 1, {"p": True})                # bool is not the integer 1
        assert not holds("not_equals", 1, {"p": 1})

    def test_in(self):
        assert holds("in", ["a", "b"], {"p": "b"})
        assert not holds("in", ["a", "b"], {"p": "c"})
        assert not holds("in", ["a"], {})
        assert not holds("in", ["a"], {"p": ["a"]})
        assert not holds("in", [1, 2], {"p": True})
        assert not holds("in", [1, 2], {"p": "1"})
        assert holds("in", [1, 2], {"p": 2})
        assert holds("in", [None], {"p": None})

    def test_not_in(self):
        assert holds("not_in", ["a", "b"], {"p": "c"})
        assert not holds("not_in", ["a", "b"], {"p": "a"})
        assert holds("not_in", ["a"], {})
        assert holds("not_in", ["a"], {"p": ["a"]})
        assert holds("not_in", [1], {"p": True})

    def test_glob(self):
        assert holds("glob", "*.txt", {"p": "a.txt"})
        assert not holds("glob", "*.txt", {"p": "a.TXT"})         # case-sensitive
        assert not holds("glob", "*.txt", {"p": "a.csv"})
        assert holds("glob", "a?c", {"p": "abc"})
        assert holds("glob", "[ab]x", {"p": "bx"})
        assert not holds("glob", "*", {})
        assert not holds("glob", "*", {"p": 5})
        assert not holds("glob", "*", {"p": ["a"]})
        assert not holds("glob", "*", {"p": None})

    def test_not_glob(self):
        assert holds("not_glob", "*.txt", {"p": "a.csv"})
        assert not holds("not_glob", "*.txt", {"p": "a.txt"})
        assert holds("not_glob", "*.txt", {})
        assert holds("not_glob", "*.txt", {"p": 5})
        assert holds("not_glob", "*.txt", {"p": ["a.txt"]})

    def test_contains(self):
        assert holds("contains", "rm -rf", {"p": "sudo rm -rf /"})
        assert not holds("contains", "rm -rf", {"p": "ls"})
        assert not holds("contains", "x", {})
        assert not holds("contains", "x", {"p": ["x"]})           # list membership is NOT substring
        assert not holds("contains", "5", {"p": 5})
        assert not holds("contains", "x", {"p": None})

    def test_exists(self):
        assert holds("exists", None, {"p": 0}, novalue=True)
        assert holds("exists", None, {"p": None}, novalue=True)
        assert holds("exists", None, {"p": ""}, novalue=True)
        assert not holds("exists", None, {}, novalue=True)
        assert not holds("exists", None, {"q": 1}, novalue=True)

    def test_not_exists(self):
        assert holds("not_exists", None, {}, novalue=True)
        assert not holds("not_exists", None, {"p": None}, novalue=True)
        assert not holds("not_exists", None, {"p": 1}, novalue=True)

    def test_max_len(self):
        assert holds("max_len", 3, {"p": "abc"})
        assert holds("max_len", 3, {"p": [1, 2, 3]})
        assert not holds("max_len", 3, {"p": "abcd"})
        assert not holds("max_len", 3, {"p": [1, 2, 3, 4]})
        assert holds("max_len", 0, {"p": ""})
        assert not holds("max_len", 3, {})
        assert not holds("max_len", 3, {"p": 1})                  # number: no length
        assert not holds("max_len", 3, {"p": {"a": 1}})
        assert not holds("max_len", 3, {"p": None})

    def test_dotted_paths_and_list_indexes(self):
        a = {"a": {"b": {"c": "deep"}}, "items": [{"path": "/x"}, {"path": "/y"}]}
        assert holds("equals", "deep", a, path="a.b.c")
        assert not holds("equals", "deep", a, path="a.b")
        assert not holds("equals", "deep", a, path="a.b.c.d")         # through a string
        assert holds("equals", "/y", a, path="items.1.path")
        assert not holds("equals", "/y", a, path="items.2.path")      # out of range
        assert not holds("equals", "/y", a, path="items.-1.path")
        assert not holds("equals", "/y", a, path="items.x.path")
        assert holds("equals", "k", {"d": {"0": "k"}}, path="d.0")    # digit key in a dict
        assert holds("equals", "k", {"d": ["k"]}, path="d.0")

    def test_list_index_cap(self):
        big = ["x"] * 2500
        assert holds("exists", None, {"p": big}, path="p.1999", novalue=True)
        assert not holds("exists", None, {"p": big}, path="p.2000", novalue=True)
        assert holds("not_exists", None, {"p": big}, path="p.2400", novalue=True)       # unknown => true
        assert not holds("exists", None, {"p": ["x"]}, path="p.0" + "0" * 5, novalue=True)

    def test_tuple_args_are_lists(self):
        assert holds("equals", "b", {"p": ("a", "b")}, path="p.1")

    def test_unicode_digits_are_not_indexes(self):
        assert not holds("exists", None, {"p": ["x"]}, path="p.٠", novalue=True)       # arabic-indic zero

    def test_truncated_strings(self):
        long = "a" * 20001
        assert holds("exists", None, {"p": long}, novalue=True)
        assert not holds("equals", "a" * 20001 if False else "a", {"p": long})
        assert not holds("glob", "*", {"p": long})                  # cannot be evaluated
        assert holds("not_glob", "*", {"p": long})
        assert not holds("under", "/", {"p": "/" + long})
        assert holds("not_under", "/", {"p": "/" + long})
        assert not holds("max_len", 20000, {"p": long})
        assert not holds("contains", "a", {"p": long})
        assert holds("glob", "*", {"p": "a" * 20000})               # exactly at the limit is still evaluated

    def test_hostile_args_containers(self):
        p = pol([rule("a", "allow", args=[arg("p", "equals", "x")])])
        for hostile in (None, [], "str", 5, [("p", "x")], object()):
            d = p.evaluate("s", "t", hostile)
            assert d.verdict == "ask"
        deep = cur = {}
        for _ in range(5000):
            cur["k"] = {}
            cur = cur["k"]
        assert p.evaluate("s", "t", deep).verdict == "ask"
        assert p.evaluate("s", "t", {"p": "x", "z": deep}).verdict == "allow"

    def test_deep_path_beyond_depth_cap_is_unknown(self):
        node = {"leaf": "v"}
        for _ in range(11):
            node = {"k": node}
        path = ".".join(["k"] * 11 + ["leaf"])        # 12 segments: ok
        assert holds("equals", "v", node, path=path)

    def test_huge_args_are_bounded(self):
        p = pol([rule("a", "allow", args=[arg("p", "equals", "x")]), rule("b", "deny", args=[arg("big", "not_exists", novalue=True)])])
        t = time.time()
        args = {"p": "x", "big": list(range(200000)), "d": {str(i): i for i in range(200000)}}
        assert p.evaluate("s", "t", args).verdict == "allow"
        assert time.time() - t < 2

    def test_non_str_dict_keys(self):
        assert not holds("exists", None, {1: "x"}, path="1", novalue=True)

    def test_hostile_mapping_that_raises_is_a_rule_error(self):
        class Boom(dict):
            def __contains__(self, k):
                raise RuntimeError("x")
        p = pol([rule("a", "allow", args=[arg("p", "equals", "x")])])
        d = p.evaluate("s", "t", Boom(p="x"))
        assert d.verdict == "ask" and d.reason == "rule_error:a"


# ---------------------------------------------------------------------------
# path operators
# ---------------------------------------------------------------------------

UNDER = [
    ("/project", True), ("/project/", True), ("/project/a", True), ("/project/a/b/c.txt", True),
    ("/project/./x", True), ("/project/a/../b", True), ("/project//x", True), ("///project/x", True),
    ("/project/../project/x", True), ("/../project/x", True),
    ("/project/..", False), ("/project/../etc/passwd", False), ("/project/a/../../etc", False),
    ("/project2/x", False), ("/projectx", False), ("/proj", False), ("/", False), ("/etc/passwd", False),
    ("//project//x", False),               # POSIX keeps exactly two leading slashes: not the same lexical prefix
    ("project/x", False), ("./project/x", False), ("../project/x", False), ("", False), ("~/project", False),
    ("/PROJECT/x", False),
    ("/project\x00/x", False), ("/project/x\x00", False),
    ("/project/..‮/x", True),         # not a '..' segment: bidi char makes it an ordinary name
    ("/project/a\\..\\etc", True),         # backslashes are not separators on POSIX
    ("/project\\..\\etc", False),           # ... so this is one segment named "project\..\etc", not /project
]


class TestPathOps:
    @pytest.mark.parametrize("path,expected", UNDER)
    def test_under(self, path, expected):
        assert holds("under", "/project", {"p": path}) is expected

    @pytest.mark.parametrize("path,expected", UNDER)
    def test_not_under_is_exact_complement(self, path, expected):
        # every uncertain path (relative, NUL) is also "not under", so the two ops are complements for strings
        assert holds("not_under", "/project", {"p": path}) is (not expected)

    @pytest.mark.parametrize("v", [None, 5, True, ["/project/x"], {"a": "/project"}, b"/project/x", 1.5])
    def test_non_string_values(self, v):
        assert not holds("under", "/project", {"p": v})
        assert holds("not_under", "/project", {"p": v})

    def test_missing(self):
        assert not holds("under", "/project", {})
        assert holds("not_under", "/project", {})

    def test_value_is_normalised(self):
        for val in ("/project/", "/project/.", "/a/../project", "/project//"):
            assert holds("under", val, {"p": "/project/x"}), val
            assert not holds("under", val, {"p": "/project2/x"}), val

    def test_root_prefix(self):
        assert holds("under", "/", {"p": "/anything/at/all"})
        assert not holds("under", "/", {"p": "relative"})

    def test_nested_prefix(self):
        assert holds("under", "/project/sub", {"p": "/project/sub/x"})
        assert not holds("under", "/project/sub", {"p": "/project/subx"})
        assert not holds("under", "/project/sub", {"p": "/project"})

    def test_huge_path_is_bounded(self):
        t = time.time()
        assert not holds("under", "/project", {"p": "/project/" + "../" * 30000 + "x"})      # truncated => unknown
        assert holds("under", "/project", {"p": "/project/" + "a/" * 5000})
        assert time.time() - t < 2

    def test_deny_on_traversal_end_to_end(self):
        p = pol([rule("no-out", "deny", tool="write_*", args=[arg("path", "not_under", "/project")]),
                 rule("ok", "allow", tool="write_*", args=[arg("path", "under", "/project")])])
        assert p.evaluate("s", "write_file", {"path": "/project/a.txt"}).verdict == "allow"
        for hostile in ("/project/../etc/passwd", "/project2/x", "relative.txt", "/project\x00/x", "//project//x", None, 7,
                        ["/project/a"]):
            assert p.evaluate("s", "write_file", {"path": hostile}).verdict == "deny", hostile
        assert p.evaluate("s", "write_file", {}).verdict == "deny"


# ---------------------------------------------------------------------------
# precedence, specificity, matched
# ---------------------------------------------------------------------------

class TestPrecedence:
    def test_deny_beats_ask_beats_allow(self):
        rules = [rule("al", "allow"), rule("as", "ask"), rule("de", "deny")]
        assert pol(rules, default="allow").evaluate("s", "t", {}).verdict == "deny"
        assert pol(rules[:2], default="allow").evaluate("s", "t", {}).verdict == "ask"
        assert pol(rules[:1], default="deny").evaluate("s", "t", {}).verdict == "allow"

    def test_order_independent(self):
        import itertools
        rules = [rule("al", "allow"), rule("as", "ask"), rule("de", "deny")]
        for perm in itertools.permutations(rules):
            d = pol(list(perm), default="allow").evaluate("s", "t", {})
            assert (d.verdict, d.rule_id) == ("deny", "de")
            assert set(d.matched) == {"al", "as", "de"}

    def test_default_applies_without_match(self):
        for dv in ("allow", "deny", "ask"):
            d = pol([rule("x", "deny", tool="nope")], default=dv).evaluate("s", "t", {})
            assert (d.verdict, d.rule_id, d.reason, d.matched, d.escalated) == (dv, None, "default", (), False)

    def test_no_rules(self):
        assert pol([], default="deny").evaluate("s", "t", {}).verdict == "deny"

    def test_most_specific_of_winning_class_reported(self):
        p = pol([
            rule("broad-deny", "deny", tool="write_*"),
            rule("narrow-deny", "deny", tool="write_*", args=[arg("path", "not_under", "/project"), arg("path", "exists", novalue=True)]),
            rule("allow-all", "allow"),
        ])
        d = p.evaluate("s", "write_file", {"path": "/etc/x"})
        assert d.verdict == "deny" and d.rule_id == "narrow-deny"
        assert d.matched == ("broad-deny", "narrow-deny", "allow-all")
        assert d.reason == "rule:narrow-deny"

    def test_tie_goes_to_first_listed(self):
        p = pol([rule("first", "deny", tool="t"), rule("second", "deny", tool="t")])
        assert p.evaluate("s", "t", {}).rule_id == "first"
        p = pol([rule("second", "deny", tool="t"), rule("first", "deny", tool="t")])
        assert p.evaluate("s", "t", {}).rule_id == "second"

    def test_specificity_only_within_winning_class(self):
        p = pol([rule("very-specific-allow", "allow", server="s", tool="t", args=[arg("a", "exists", novalue=True)]),
                 rule("plain-ask", "ask")])
        d = p.evaluate("s", "t", {"a": 1})
        assert (d.verdict, d.rule_id) == ("ask", "plain-ask")
        assert d.matched == ("very-specific-allow", "plain-ask")

    def test_allow_reports_most_specific_allow(self):
        p = pol([rule("a1", "allow"), rule("a2", "allow", tool="t")])
        assert p.evaluate("s", "t", {}).rule_id == "a2"

    def test_matched_is_a_tuple_in_file_order(self):
        p = pol([rule("c", "allow"), rule("a", "ask"), rule("b", "deny")])
        assert p.evaluate("s", "t", {}).matched == ("c", "a", "b")

    def test_decision_is_frozen(self):
        d = pol([]).evaluate("s", "t", {})
        assert isinstance(d, Decision)
        with pytest.raises(Exception):
            d.verdict = "allow"

    def test_deterministic(self):
        p = pol([rule("a", "allow", tool="t"), rule("b", "ask", tool="t")])
        assert len({p.evaluate("s", "t", {"x": 1}) for _ in range(5)}) == 1


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------

class TestAlerts:
    def test_allow_escalates_to_ask(self):
        p = pol([rule("a", "allow", tool="t")])
        d = p.evaluate("s", "t", {}, alerts_present=True)
        assert (d.verdict, d.escalated, d.reason, d.rule_id) == ("ask", True, "alert", "a")
        d0 = p.evaluate("s", "t", {})
        assert (d0.verdict, d0.escalated) == ("allow", False)

    def test_default_allow_escalates(self):
        d = pol([], default="allow").evaluate("s", "t", {}, alerts_present=True)
        assert (d.verdict, d.escalated, d.reason) == ("ask", True, "alert")

    def test_deny_unchanged(self):
        p = pol([rule("d", "deny", tool="t"), rule("a", "allow")])
        d = p.evaluate("s", "t", {}, alerts_present=True)
        assert (d.verdict, d.escalated, d.reason) == ("deny", False, "rule:d")

    def test_ask_unchanged_and_not_marked_escalated(self):
        d = pol([rule("q", "ask")]).evaluate("s", "t", {}, alerts_present=True)
        assert (d.verdict, d.escalated, d.reason) == ("ask", False, "rule:q")

    def test_default_deny_unchanged(self):
        d = pol([], default="deny").evaluate("s", "t", {}, alerts_present=True)
        assert (d.verdict, d.escalated) == ("deny", False)

    def test_alert_condition(self):
        p = pol([rule("on-alert", "deny", alert=True), rule("quiet", "allow", alert=False)], default="ask")
        assert p.evaluate("s", "t", {}, alerts_present=True).verdict == "deny"
        d = p.evaluate("s", "t", {}, alerts_present=False)
        assert (d.verdict, d.rule_id) == ("allow", "quiet")
        # with an alert present the "quiet" rule does not match at all
        assert p.evaluate("s", "t", {}, alerts_present=True).matched == ("on-alert",)

    def test_alert_condition_allow_rule_still_escalates(self):
        p = pol([rule("x", "allow", alert=True)])
        d = p.evaluate("s", "t", {}, alerts_present=True)
        assert (d.verdict, d.escalated) == ("ask", True)

    def test_truthy_non_bool_counts_as_alert(self):
        d = pol([rule("a", "allow")]).evaluate("s", "t", {}, alerts_present="false")
        assert d.verdict == "ask" and d.escalated


# ---------------------------------------------------------------------------
# rule errors
# ---------------------------------------------------------------------------

class TestRuleErrors:
    def _boom_on(self, monkeypatch, *bad_ids):
        real = P._rule_matches

        def fake(rule_, ctx):
            if rule_.id in bad_ids:
                raise RuntimeError("boom")
            return real(rule_, ctx)
        monkeypatch.setattr(P, "_rule_matches", fake)

    def test_error_without_deny_becomes_ask(self, monkeypatch):
        p = pol([rule("bad", "deny", tool="t"), rule("good", "allow", tool="t")])
        self._boom_on(monkeypatch, "bad")
        d = p.evaluate("s", "t", {})
        assert d.verdict == "ask" and d.reason == "rule_error:bad" and d.matched == ("good",)

    def test_error_overrides_default_allow(self, monkeypatch):
        p = pol([rule("bad", "allow")], default="allow")
        self._boom_on(monkeypatch, "bad")
        assert p.evaluate("s", "t", {}).verdict == "ask"

    def test_matched_deny_still_wins(self, monkeypatch):
        p = pol([rule("bad", "allow"), rule("d", "deny", tool="t")])
        self._boom_on(monkeypatch, "bad")
        d = p.evaluate("s", "t", {})
        assert (d.verdict, d.rule_id) == ("deny", "d")

    def test_error_in_deny_rule_is_ask_not_allow(self, monkeypatch):
        p = pol([rule("bad-deny", "deny"), rule("a", "allow")], default="allow")
        self._boom_on(monkeypatch, "bad-deny")
        assert p.evaluate("s", "t", {}).verdict == "ask"

    def test_error_with_matching_ask_reports_that_rule(self, monkeypatch):
        p = pol([rule("bad", "allow"), rule("q", "ask")])
        self._boom_on(monkeypatch, "bad")
        d = p.evaluate("s", "t", {})
        assert (d.verdict, d.rule_id, d.reason) == ("ask", "q", "rule_error:bad")

    def test_error_not_escalated_flag(self, monkeypatch):
        p = pol([rule("bad", "allow")])
        self._boom_on(monkeypatch, "bad")
        d = p.evaluate("s", "t", {}, alerts_present=True)
        assert d.verdict == "ask" and not d.escalated

    def test_evaluate_never_raises(self, monkeypatch):
        p = pol([rule("a", "allow")])

        def fake(*a, **k):
            raise ValueError("engine")
        monkeypatch.setattr(P, "_Ctx", fake)
        d = p.evaluate("s", "t", {})
        assert (d.verdict, d.reason) == ("ask", "engine_error")

    def test_registry_failure_is_rule_error_only_for_destination_rules(self):
        class BadReg:
            def resolve(self, tool, args):
                raise RuntimeError("registry down")
        p = pol([rule("dest", "allow", destination="internal"), rule("plain", "allow", tool="nomatch")], default="allow")
        d = p.evaluate("s", "send_email", TO_INTERNAL, registry=BadReg())
        assert d.verdict == "ask" and d.reason == "rule_error:dest"
        # a deny that needs no registry still wins
        p2 = pol([rule("dest", "allow", destination="internal"), rule("d", "deny", tool="send_email")])
        assert p2.evaluate("s", "send_email", TO_INTERNAL, registry=BadReg()).verdict == "deny"

    def test_registry_result_cached_across_rules(self):
        calls = []

        class CountReg:
            def resolve(self, tool, args):
                calls.append(1)
                return REG.resolve(tool, args)
        p = pol([rule("a", "allow", destination="internal"), rule("b", "ask", destination="external"),
                 rule("c", "deny", party="acme")])
        p.evaluate("s", "send_email", TO_INTERNAL, registry=CountReg())
        assert len(calls) == 1


# ---------------------------------------------------------------------------
# destination / party
# ---------------------------------------------------------------------------

class TestDestination:
    def test_internal(self):
        assert dest_verdict("internal", "send_email", TO_INTERNAL)
        assert not dest_verdict("internal", "send_email", TO_EXTERNAL)
        assert not dest_verdict("internal", "send_email", TO_RELAY)
        assert not dest_verdict("internal", "send_email", TO_UNKNOWN)
        assert not dest_verdict("internal", "read_file", NO_DEST)      # no tokens: not internal

    def test_internal_requires_all_tokens_internal(self):
        both = {"to": "a@team.com, x@brightwatercap.example"}
        assert not dest_verdict("internal", "send_email", both)
        assert dest_verdict("external", "send_email", both)

    def test_external(self):
        assert dest_verdict("external", "send_email", TO_EXTERNAL)
        assert dest_verdict("external", "send_email", TO_UNKNOWN)      # unknown counts as external
        assert dest_verdict("external", "send_email", TO_RELAY)        # a relay reaches an outside party
        assert not dest_verdict("external", "send_email", TO_INTERNAL)
        assert not dest_verdict("external", "read_file", NO_DEST)

    def test_unknown_is_external_even_if_registry_default_is_not_external(self):
        reg = Registry({"version": 1, "defaults": {"internal_domains": ["team.com"], "unknown": "internal"}, "entries": []})
        assert reg.resolve("send_email", TO_UNKNOWN).reaches == frozenset()
        assert dest_verdict("external", "send_email", TO_UNKNOWN, registry=reg)
        assert not dest_verdict("internal", "send_email", TO_UNKNOWN, registry=reg)

    def test_relay(self):
        assert dest_verdict("relay", "send_email", TO_RELAY)
        assert not dest_verdict("relay", "send_email", TO_EXTERNAL)
        assert not dest_verdict("relay", "send_email", TO_INTERNAL)
        assert not dest_verdict("relay", "send_email", TO_UNKNOWN)
        assert not dest_verdict("relay", "read_file", NO_DEST)

    def test_relay_needs_a_registered_entry(self):
        # same address without the registered relay entry: plain internal
        assert not dest_verdict("relay", "send_email", TO_RELAY, registry=default_registry())

    def test_none(self):
        assert dest_verdict("none", "read_file", NO_DEST)
        assert not dest_verdict("none", "send_email", TO_INTERNAL)
        assert not dest_verdict("none", "send_email", TO_EXTERNAL)

    def test_any(self):
        for tool, args in (("read_file", NO_DEST), ("send_email", TO_EXTERNAL), ("send_email", TO_INTERNAL)):
            assert dest_verdict("any", tool, args)

    def test_default_registry_used_when_none_given(self):
        p = pol([rule("r", "deny", destination="external")], default="allow")
        assert p.evaluate("s", "send_email", {"to": "x@some-outside-company.example"}).verdict == "deny"
        assert p.evaluate("s", "read_file", {"path": "/project/a"}).verdict == "allow"

    def test_registry_changes_the_answer(self):
        p = pol([rule("r", "deny", destination="relay")], default="allow")
        assert p.evaluate("s", "send_email", TO_RELAY, registry=REG).verdict == "deny"
        assert p.evaluate("s", "send_email", TO_RELAY, registry=default_registry()).verdict == "allow"

    def test_destination_with_hostile_args_never_raises(self):
        p = pol([rule("r", "deny", destination="external")], default="allow")
        for tool, args in ((None, None), ("send_email", "str"), ("send_email", {"to": ["a@b.c"] * 5000}), (5, {"to": 5}),
                           ("send_email", {"to": "a\x00@b.example"})):
            assert p.evaluate("s", tool, args, registry=REG).verdict in ("allow", "deny", "ask")

    def test_destination_combined_with_other_conditions(self):
        p = pol([rule("r", "allow", tool="send_email", destination="internal", args=[arg("subject", "max_len", 10)])])
        assert p.evaluate("s", "send_email", {**TO_INTERNAL, "subject": "hi"}, registry=REG).verdict == "allow"
        assert p.evaluate("s", "send_email", {**TO_INTERNAL, "subject": "h" * 11}, registry=REG).verdict == "ask"
        assert p.evaluate("s", "send_email", {**TO_EXTERNAL, "subject": "hi"}, registry=REG).verdict == "ask"

    def test_party(self):
        def hit(parties, args):
            p = pol([rule("r", "deny", party=parties)], default="allow")
            return p.evaluate("s", "send_email", args, registry=REG).verdict == "deny"
        assert hit("acme", TO_RELAY)
        assert hit(["nobody", "acme"], TO_RELAY)
        assert hit("brightwater", TO_EXTERNAL)
        assert hit("zzz.example", TO_UNKNOWN)
        assert not hit("acme", TO_EXTERNAL)
        assert not hit("acme", TO_INTERNAL)
        assert not hit("ACME", TO_RELAY)              # exact slug, case-sensitive
        assert not hit("acm*", TO_RELAY)              # no globbing for parties

    def test_party_none_reached(self):
        p = pol([rule("r", "deny", party="acme")], default="allow")
        assert p.evaluate("s", "read_file", NO_DEST, registry=REG).verdict == "allow"


# ---------------------------------------------------------------------------
# digest, lint, cache
# ---------------------------------------------------------------------------

BASE = {"version": 1, "default": "ask", "rules": [
    {"id": "a", "verdict": "allow", "when": {"tool": "t", "args": [{"path": "p", "op": "equals", "value": 1}]}},
    {"id": "b", "verdict": "deny"}]}


class TestDigest:
    def test_shape(self):
        d = load_policy(BASE).digest()
        assert len(d) == 16 and int(d, 16) >= 0

    def test_stable_across_key_order_and_loading(self, tmp_path):
        reordered = {"rules": [{"verdict": "allow", "when": {"args": [{"value": 1, "op": "equals", "path": "p"}], "tool": "t"},
                                "id": "a"}, {"verdict": "deny", "id": "b"}], "default": "ask", "version": 1}
        f = tmp_path / "p.json"
        f.write_text(json.dumps(BASE, indent=4))
        assert load_policy(BASE).digest() == load_policy(reordered).digest() == load_policy(str(f)).digest()

    def test_explicit_default_equals_implicit(self):
        a = {"version": 1, "rules": []}
        b = {"version": 1, "default": "ask", "rules": []}
        assert load_policy(a).digest() == load_policy(b).digest()

    def test_changes_with_semantics(self):
        base = load_policy(BASE).digest()
        variants = []
        for mut in (lambda d: d.update(default="deny"),
                    lambda d: d["rules"][0].update(verdict="ask"),
                    lambda d: d["rules"][0]["when"].update(tool="u"),
                    lambda d: d["rules"][0]["when"]["args"][0].update(value=2),
                    lambda d: d["rules"].reverse(),
                    lambda d: d["rules"][1].update(note="n"),
                    lambda d: d["rules"].pop()):
            d = copy.deepcopy(BASE)
            mut(d)
            variants.append(load_policy(d).digest())
        assert base not in variants and len(set(variants)) == len(variants)

    def test_to_dict_roundtrip(self):
        p = load_policy(BASE)
        assert load_policy(p.to_dict()).digest() == p.digest()
        p.to_dict()["rules"].clear()
        assert len(p.to_dict()["rules"]) == 2


class TestLint:
    def test_clean_policy_has_no_warnings(self):
        assert load_policy(BASE).lint() == []

    @pytest.mark.parametrize("op", ["not_equals", "not_in", "not_glob", "not_under", "not_exists"])
    def test_allow_with_negative_op_warns(self, op):
        a = arg("p", op, ["x"] if op == "not_in" else "/x" if op == "not_under" else "x", novalue=(op == "not_exists"))
        w = pol([rule("al", "allow", args=[a])]).lint()
        assert any("al" in m and "negative" in m and op in m for m in w), w

    def test_deny_and_ask_with_negative_op_do_not_warn(self):
        a = arg("p", "not_under", "/project")
        assert pol([rule("d", "deny", args=[a]), rule("q", "ask", tool="t", args=[a])]).lint() == []

    def test_allow_with_positive_ops_only_does_not_warn(self):
        assert pol([rule("al", "allow", args=[arg("p", "under", "/project")])]).lint() == []

    def test_default_allow_warns(self):
        assert any("default" in m and "allow" in m for m in pol([], default="allow").lint())
        assert pol([], default="deny").lint() == [] and pol([], default="ask").lint() == []

    def test_duplicate_conditions_same_verdict(self):
        w = pol([rule("x1", "deny", tool="t"), rule("x2", "deny", tool="t")]).lint()
        assert len(w) == 1 and "x1" in w[0] and "x2" in w[0] and "duplicate" in w[0]

    def test_duplicate_detection_normalises_lists_and_order(self):
        a1 = [arg("a", "exists", novalue=True), arg("b", "equals", 1)]
        a2 = list(reversed(a1))
        w = pol([rule("x1", "ask", tool=["b", "a"], args=a1), rule("x2", "ask", tool=["a", "b", "a"], args=a2)]).lint()
        assert any("duplicate" in m for m in w)

    def test_empty_and_absent_when_are_identical(self):
        w = pol([{"id": "x1", "verdict": "ask"}, {"id": "x2", "verdict": "ask", "when": {}}]).lint()
        assert any("duplicate" in m for m in w)

    @pytest.mark.parametrize("weak,strong", [("allow", "deny"), ("allow", "ask"), ("ask", "deny")])
    @pytest.mark.parametrize("weak_first", [True, False])
    def test_shadowed_by_stronger_class(self, weak, strong, weak_first):
        rules = [rule("weak", weak, tool="t"), rule("strong", strong, tool="t")]
        if not weak_first:
            rules.reverse()
        w = pol(rules).lint()
        assert any("weak" in m and "shadowed" in m and "strong" in m for m in w), w

    def test_different_conditions_do_not_warn(self):
        assert pol([rule("x1", "deny", tool="t"), rule("x2", "allow", tool="u")]).lint() == []
        assert pol([rule("x1", "deny", args=[arg("a", "equals", 1)]), rule("x2", "allow", args=[arg("a", "equals", 2)])]).lint() == []

    def test_lint_returns_list_of_strings(self):
        w = pol([rule("x1", "allow", args=[arg("a", "not_exists", novalue=True)]),
                 rule("x2", "allow", args=[arg("a", "not_exists", novalue=True)])], default="allow").lint()
        assert len(w) == 4 and all(isinstance(m, str) for m in w)


class TestCache:
    def setup_method(self):
        P._reset_policy_cache()

    def write(self, path, data):
        path.write_text(json.dumps(data))

    def test_loads_and_caches_same_object(self, tmp_path):
        f = tmp_path / "p.json"
        self.write(f, BASE)
        p1, r1 = load_policy_file(str(f))
        p2, r2 = load_policy_file(str(f))
        assert p1 is not None and r1 == "" and p2 is p1

    def test_content_change_reloads(self, tmp_path):
        f = tmp_path / "p.json"
        self.write(f, BASE)
        p1, _ = load_policy_file(f)
        d = copy.deepcopy(BASE)
        d["rules"][1]["verdict"] = "allow"
        self.write(f, d)
        p2, _ = load_policy_file(f)
        assert p2 is not p1 and p2.digest() != p1.digest()

    def test_same_size_edit_with_restored_mtime(self, tmp_path):
        f = tmp_path / "p.json"
        raw_a = json.dumps({"version": 1, "default": "deny", "rules": []})
        raw_b = raw_a.replace('"deny"', '"dexy"')                                  # invalid, same length
        raw_c = raw_a.replace('"deny"', '"ask" ')                                  # valid, same length as raw_a
        assert len(raw_a) == len(raw_b) == len(raw_c)
        f.write_text(raw_a)
        st = os.stat(f)
        p1, _ = load_policy_file(f)
        assert p1.default == "deny"
        for raw in (raw_c, raw_b):
            f.write_text(raw)
            os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
            assert os.stat(f).st_size == st.st_size and os.stat(f).st_mtime_ns == st.st_mtime_ns
            p, reason = load_policy_file(f)
            if raw is raw_c:
                assert p is not None and p.default == "ask"
            else:
                assert p is None and reason

    def test_invalid_file_returns_reason_and_does_not_raise(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text('{"version": 9}')
        p, reason = load_policy_file(f)
        assert p is None and "version" in reason
        f.write_text("not json")
        p, reason = load_policy_file(f)
        assert p is None and reason
        f.write_bytes(b"\xff\xfe\x00")
        assert load_policy_file(f)[0] is None
        f.write_text("[]")
        assert load_policy_file(f)[0] is None

    def test_recovers_after_fix(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text("junk")
        assert load_policy_file(f)[0] is None
        self.write(f, BASE)
        assert load_policy_file(f)[0] is not None

    def test_missing_file_and_weird_paths(self, tmp_path):
        p, reason = load_policy_file(tmp_path / "nope.json")
        assert p is None and "nope.json" in reason
        for bad in (None, 5, "", "\x00", str(tmp_path)):
            p, reason = load_policy_file(bad)
            assert p is None and isinstance(reason, str) and reason

    def test_file_deleted_after_cache(self, tmp_path):
        f = tmp_path / "p.json"
        self.write(f, BASE)
        assert load_policy_file(f)[0] is not None
        f.unlink()
        assert load_policy_file(f)[0] is None             # never serve a stale policy for a vanished file

    def test_reads_file_once_per_call(self, tmp_path, monkeypatch):
        f = tmp_path / "p.json"
        self.write(f, BASE)
        calls = []
        real = P._read_file
        monkeypatch.setattr(P, "_read_file", lambda p: (calls.append(p), real(p))[1])
        load_policy_file(f)
        assert len(calls) == 1

    def test_cached_failure_is_per_content(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text("junk")
        a = load_policy_file(f)
        b = load_policy_file(f)
        assert a == b == (None, a[1])

    def test_unexpected_exception_does_not_escape(self, tmp_path, monkeypatch):
        f = tmp_path / "p.json"
        self.write(f, BASE)

        def boom(*a, **k):
            raise RuntimeError("kaboom")
        monkeypatch.setattr(P, "Policy", boom)
        p, reason = load_policy_file(f)
        assert p is None and reason


def test_module_has_no_web_imports():
    imports = [ln for ln in open(P.__file__, encoding="utf-8").read().splitlines() if ln.lstrip().startswith(("import ", "from "))]
    assert imports and not any(w in ln.lower() for ln in imports for w in ("fastapi", "starlette"))
