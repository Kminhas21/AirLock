"""The `write` right in a rule's `confine` map (DECISIONS D32): validation, the closed set, the digest, the file loader, `policy_cli`, the floor
(`write_unsupported`), and the hub on a policy that carries it. Phase 1 pinned `write` as refused at every policy layer; the cases that became
allowed were flipped on purpose and the rest stay as negative controls (a `write` anywhere but a bounded, tool-named, glob-narrowed rule on
`path` is a policy ERROR and the whole policy is refused, so every call is held).

The shipped starter's own write rules (extensions, sensitive paths, replay numbers) are tests/server/test_policy_starter_write.py."""
import json

import pytest

import inbox_hub
import policy as P
import policy_cli as C
import proposal_monitor
from test_inbox_hub import Rig, call, wait_for

PATH_DOCS = {"path": "path", "op": "glob", "value": "*.md"}
LEN = {"path": "content", "op": "max_len", "value": 20000}
RULE = {"id": "w", "verdict": "allow",
        "when": {"tool": "write_file", "arg_keys": ["path", "content"], "args": [PATH_DOCS, LEN]}, "confine": {"path": "write"}}
GOOD_READ = {"id": "r", "verdict": "allow", "when": {"tool": "read_file", "arg_keys": ["path"]}, "confine": {"path": "read"}}
MSG = "confine.'path': must be \"read\" (exactly that file), \"list\" (names beneath that directory) or \"write\" (overwrite that one existing file)"


def doc(*rules):
    return {"version": 1, "default": "ask", "rules": list(rules)}


def when(**kw):
    return {**RULE["when"], **kw}


def errors(*rules):
    with pytest.raises(P.PolicyError) as e:
        P.Policy(doc(*rules))
    return e.value.messages


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG"):
        monkeypatch.delenv(k, raising=False)
    P._reset_policy_cache()
    inbox_hub._logged_policy_problems.clear()
    proposal_monitor._reset_errors()
    yield
    P._reset_policy_cache()
    proposal_monitor._reset_errors()


# --------------------------------------------------------------------------- the closed set


def test_the_closed_set_of_rights_is_read_list_and_write():
    assert P.CONFINE_RIGHTS == ("read", "list", "write")


@pytest.mark.parametrize("right", ["WRITE", "Write", " write", "write ", "read|write", "read,write", "rw", "w", "create", "append", "truncate", "delete",
                                   "execute", "", True, 1, None, ["write"], {"write": True}])
def test_a_confine_right_outside_the_three_is_a_policy_error_with_the_exact_message(right):
    assert any(MSG in m for m in errors({**RULE, "confine": {"path": right}})), right


def test_a_valid_write_rule_loads_and_is_part_of_the_digest():
    pol = P.Policy(doc(RULE))
    assert pol.rules[0].confine == {"path": "write"}
    assert pol.digest() != P.Policy(doc({**RULE, "confine": {"path": "read"}})).digest()


# --------------------------------------------------------------------------- a write rule must be narrow (each is an error at load)


def test_write_is_only_for_the_argument_path():
    for key in ("paths", "file", "destination", "source", "directory", "file_path", "content"):
        m = errors({**RULE, "when": when(arg_keys=["path", "content", key]), "confine": {key: "write"}})
        assert any(f"confine.{key!r}" in x and "only for the argument 'path'" in x for x in m), (key, m)


def test_a_write_rule_confines_exactly_path_and_nothing_else():
    m = errors({**RULE, "when": when(arg_keys=["path", "content", "dest"]), "confine": {"path": "write", "dest": "read"}})
    assert any("exactly" in x and "path" in x for x in m), m


def test_a_write_rule_must_name_the_tool():
    w = {"arg_keys": ["path", "content"], "args": [PATH_DOCS, LEN]}
    assert any("a write rule needs when.tool" in x for x in errors({**RULE, "when": w}))


def test_a_write_rule_must_bound_the_content_with_max_len():
    for args in ([PATH_DOCS], [PATH_DOCS, {"path": "content", "op": "exists"}], [PATH_DOCS, {"path": "query", "op": "max_len", "value": 5}],
                 [PATH_DOCS, {"path": "content.x", "op": "max_len", "value": 5}], [PATH_DOCS, {"path": "content", "op": "not_exists"}]):
        assert any("max_len on content or edits" in x for x in errors({**RULE, "when": when(args=args)})), args


def test_a_write_rule_may_bound_edits_instead_of_content():
    edits = {"path": "edits", "op": "max_len", "value": 50}
    P.Policy(doc({**RULE, "when": {"tool": "edit_file", "arg_keys": ["path", "edits", "dryRun"], "args": [PATH_DOCS, edits]}}))


def test_a_write_rule_must_narrow_path_with_a_glob():
    for args in ([LEN], [LEN, {"path": "path", "op": "exists"}], [LEN, {"path": "path", "op": "under", "value": "/w"}],
                 [LEN, {"path": "path", "op": "contains", "value": ".md"}], [LEN, {"path": "other", "op": "glob", "value": "*.md"}],
                 [LEN, {"path": "path", "op": "not_glob", "value": "*.py"}]):
        assert any("a glob on path" in x for x in errors({**RULE, "when": when(args=args)})), args


def test_a_glob_that_matches_everything_is_not_a_narrowing_glob():
    for v in ("*", "**", "/*", "*/*", "?*"):
        assert any("a glob on path" in x for x in errors({**RULE, "when": when(args=[LEN, {"path": "path", "op": "glob", "value": v}])})), v


def test_a_write_rule_needs_an_allow_verdict_and_the_verdict_error_comes_first():
    for verdict in ("ask", "deny"):
        assert any("only allow rules can have one" in m for m in errors({**RULE, "verdict": verdict}))


def test_a_bad_write_rule_rejects_the_whole_policy_not_just_the_rule():
    m = errors(GOOD_READ, {**RULE, "id": "w2", "when": {"tool": "write_file", "arg_keys": ["path", "content"], "args": [PATH_DOCS]}})
    assert len(m) == 1 and "w2" in m[0]


# --------------------------------------------------------------------------- the glob accepts a list of patterns (any one matches)


def test_a_glob_on_a_list_of_patterns_matches_any_and_is_valid_for_write():
    g = {"path": "path", "op": "glob", "value": ["*.md", "*.txt"]}
    pol = P.Policy(doc({**RULE, "when": when(args=[g, LEN])}))
    ok = lambda p: pol.evaluate_call("fs", "write_file", {"path": p, "content": "x"}, confinable=True, write_confinable=True).verdict  # noqa: E731
    assert [ok("/w/a.md"), ok("/w/a.txt"), ok("/w/a.py"), ok("/w/a.md.sh")] == ["allow", "allow", "ask", "ask"]


@pytest.mark.parametrize("value", [[], [""], [5], ["a\x00b"], ["x" * 201], ["*.md"] * 51, {"a": 1}, 5, None])
def test_a_bad_glob_value_is_still_an_error(value):
    assert errors({**RULE, "when": when(args=[{"path": "path", "op": "glob", "value": value}, LEN])})


def test_not_glob_with_a_list_is_true_only_when_no_pattern_matches():
    pol = P.Policy(doc({"id": "a", "verdict": "ask", "when": {"args": [{"path": "path", "op": "not_glob", "value": ["*.md", "*.txt"]}]}}))
    assert pol.evaluate("fs", "t", {"path": "/x.py"}).verdict == "ask"
    assert pol.evaluate("fs", "t", {"path": "/x.md"}).verdict == "ask" and pol.default == "ask"


# --------------------------------------------------------------------------- the floor: write_unsupported


def test_a_write_allow_stands_only_when_the_proxy_says_the_write_is_confinable():
    pol = P.Policy(doc(RULE))
    args = {"path": "/w/a.md", "content": "x"}
    d = pol.evaluate_call("fs", "write_file", args, confinable=True, write_confinable=True)
    assert (d.verdict, d.rule_id, d.confine, d.reason) == ("allow", "w", {"path": "write"}, "rule:w")
    for kw in ({}, {"write_confinable": False}, {"write_confinable": None}, {"write_confinable": 1}, {"write_confinable": "true"}):
        d = pol.evaluate_call("fs", "write_file", args, confinable=True, **kw)
        assert (d.verdict, d.rule_id, d.reason, d.confine) == ("ask", "w", "write_unsupported", None), kw


def test_an_unconfinable_server_asks_for_a_write_with_the_server_reason_first():
    d = P.Policy(doc(RULE)).evaluate_call("fs", "write_file", {"path": "/w/a.md", "content": "x"}, confinable=False, write_confinable=True)
    assert (d.verdict, d.reason) == ("ask", "unconfinable")


def test_write_confinable_never_makes_a_read_allow_or_a_non_write_call_different():
    pol = P.Policy(doc(RULE, GOOD_READ))
    for wc in (True, False):
        assert pol.evaluate_call("fs", "read_file", {"path": "/w/a.md"}, confinable=True, write_confinable=wc).verdict == "allow"
    assert pol.evaluate_call("fs", "read_file", {"path": "/w/a.md"}, confinable=False, write_confinable=True).verdict == "ask"


def test_write_confinable_can_only_make_a_decision_stricter_never_allow_what_the_rules_do_not():
    pol = P.Policy(doc(RULE))
    for args in ({"path": "/w/a.py", "content": "x"}, {"path": "/w/a.md", "content": "x" * 30000}, {"path": "/w/a.md", "content": "x", "mode": "w"},
                 {"path": "/w/a.md"}):
        assert pol.evaluate_call("fs", "write_file", args, confinable=True, write_confinable=True).verdict == "ask", args
    assert pol.evaluate_call("fs", "other_tool", {"path": "/w/a.md", "content": "x"}, confinable=True, write_confinable=True).verdict == "ask"


def test_a_deny_or_an_ask_rule_still_beats_a_write_allow():
    deny = {"id": "d", "verdict": "deny", "when": {"args": [{"path": "path", "op": "contains", "value": "private"}]}}
    ask = {"id": "k", "verdict": "ask", "when": {"args": [{"path": "path", "op": "icontains_any", "value": [".github/"]}]}}
    pol = P.Policy(doc(RULE, deny, ask))
    assert pol.evaluate_call("fs", "write_file", {"path": "/w/private/a.md", "content": "x"}, confinable=True, write_confinable=True).verdict == "deny"
    d = pol.evaluate_call("fs", "write_file", {"path": "/w/.github/a.md", "content": "x"}, confinable=True, write_confinable=True)
    assert (d.verdict, d.rule_id) == ("ask", "k")


def test_the_floor_function_directly():
    d = P.Decision("allow", "w", ("w",), "rule:w", False, {"path": "write"})
    assert P.confinement_floor(d, {"path": "/w/a.md"}, True, True).verdict == "allow"
    assert P.confinement_floor(d, {"path": "/w/a.md"}, True, False).reason == "write_unsupported"
    assert P.confinement_floor(d, {"path": "/w/a.md"}, True).reason == "write_unsupported"          # the default is "not confinable"
    r = P.Decision("allow", "r", ("r",), "rule:r", False, {"path": "read"})
    assert P.confinement_floor(r, {"path": "/w/a.md"}, True, False).verdict == "allow"


# --------------------------------------------------------------------------- the file loader, the CLI, the hub


def test_the_file_loader_reports_a_rejected_policy_and_returns_none(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc({**RULE, "when": {"tool": "write_file", "arg_keys": ["path", "content"]}})))
    pol, why = P.load_policy_file(str(f))
    assert pol is None and "rejected" in why and "a write rule needs" in why


def test_lint_accepts_a_good_write_rule_and_names_the_rule_and_the_problem_of_a_bad_one(tmp_path, capsys):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc(RULE)))
    assert C.main(["lint", str(f)]) == 0
    assert "WARN" not in capsys.readouterr().out
    f.write_text(json.dumps(doc({**RULE, "confine": {"path": "write", "paths": "read"}, "when": when(arg_keys=["path", "content", "paths"])})))
    assert C.main(["lint", str(f)]) == 1
    out = capsys.readouterr()
    assert "(w)" in out.err + out.out


def test_lint_warns_about_a_write_rule_next_to_a_policy_file_the_server_may_rewrite(tmp_path, capsys, monkeypatch):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc(RULE)))
    assert C.main(["lint", str(f)]) == 0
    assert "SENTINEL_POLICY_WRITABLE" not in capsys.readouterr().out
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "1")
    assert C.main(["lint", str(f)]) == 0
    out = capsys.readouterr().out
    assert "WARN" in out and "SENTINEL_POLICY_WRITABLE" in out and "outside every sandbox.write" in out
    f.write_text(json.dumps(doc(GOOD_READ)))
    assert C.main(["lint", str(f)]) == 0 and "SENTINEL_POLICY_WRITABLE" not in capsys.readouterr().out


def test_explain_shows_the_write_decision_and_honours_unconfinable(tmp_path, capsys):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc(RULE)))
    argv = ["explain", str(f), "--server", "fs", "--tool", "write_file", "--args", json.dumps({"path": "/w/a.md", "content": "x"})]
    assert C.main(argv) == 0
    out = capsys.readouterr().out
    assert "verdict: allow" in out and '{"path": "write"}' in out
    assert C.main(argv + ["--unconfinable"]) == 0
    assert "verdict: ask" in capsys.readouterr().out


async def test_a_hub_with_a_good_write_rule_allows_a_confinable_write_and_sends_the_confine_map(monkeypatch, tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc(RULE)))
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    r = await Rig().start()
    assert r.session.policy is not None
    await r.send(call("c1", tool="write_file", args={"path": "/w/a.md", "content": "x"}, confinable=True, write_confinable=True, auto=True))
    await wait_for(lambda: len(r.decisions()) == 1)
    d = r.decisions()[0]
    assert d["decision"] == "approve" and d["reason"] == "policy" and d["confine"] == {"path": "write"}


async def test_a_hub_on_a_policy_file_with_a_bad_write_rule_holds_every_call(monkeypatch, tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc({**RULE, "when": {"tool": "write_file", "arg_keys": ["path", "content"]}}, GOOD_READ)))
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    r = await Rig().start()
    assert r.session.policy is None and r.session.policy_mode is True
    await r.send(call("c1", tool="write_file", args={"path": "/w/a.md", "content": "x"}, confinable=True, write_confinable=True, auto=True))
    await r.send(call("c2", tool="read_file", args={"path": "/w/a.md"}, confinable=True, auto=True))   # a valid rule next to it: still broken
    await wait_for(lambda: len(r.ui.events("inbox_pending")) == 2)
    assert r.decisions() == []
    assert all(p["rule_id"] is None and p["policy_digest"] is None for p in r.ui.events("inbox_pending"))
