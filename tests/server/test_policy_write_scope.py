"""Scope the starter's write rules to a named server (DECISIONS D32, docs/policy.md "Scope the write rules to one server").

The starter is generic: `allow-write-docs` / `allow-edit-docs` carry no `when.server`, so ANY server that has a tool named write_file / edit_file gets its
doc overwrites auto-allowed. Changing that would change the shipped behaviour (and the v3 replay numbers), so instead `lint` WARNS (never an error) about an
allow rule with a `write` confine and no server condition, and the docs give a ready-to-paste scoped example, which a production deployment should use."""
import json
import os

import pytest

import policy as P
import policy_cli as C

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STARTER = os.path.join(ROOT, "server", "policies", "starter.json")
WRITE_RULES = ("allow-write-docs", "allow-edit-docs")


def scoped_data(server="filesystem"):
    with open(STARTER) as fh:
        data = json.load(fh)
    for r in data["rules"]:
        if r["id"] in WRITE_RULES:
            r["when"]["server"] = server
    return data


def scope_warnings(pol):
    return [w for w in pol.lint() if "server" in w and "docs/policy.md" in w]


def call(pol, server, tool="write_file", path="/p/notes.md"):
    args = {"path": path, "content": "x"} if tool == "write_file" else {"path": path, "edits": [{"oldText": "a", "newText": "b"}]}
    return pol.evaluate_call(server, tool, args, confinable=True, write_confinable=True)


def test_lint_warns_for_each_write_rule_of_the_starter_as_shipped_but_it_still_loads_and_exits_zero(capsys):
    pol = P.load_policy(STARTER)
    warns = scope_warnings(pol)
    assert len(warns) == 2
    for rid, w in zip(WRITE_RULES, sorted(warns, key=lambda w: WRITE_RULES.index(next(r for r in WRITE_RULES if r in w)))):
        assert f"rule {rid}:" in w and '"server"' in w and "no server condition" in w
    assert C.main(["lint", STARTER]) == 0
    out = capsys.readouterr().out
    assert out.count("WARN:") >= 2 and "docs/policy.md" in out and "OK:" in out


def test_lint_is_silent_about_it_once_both_rules_name_a_server():
    assert scope_warnings(P.Policy(scoped_data())) == []


def test_scoping_only_one_rule_leaves_a_warning_for_the_other():
    data = scoped_data()
    for r in data["rules"]:
        if r["id"] == "allow-edit-docs":
            del r["when"]["server"]
    warns = scope_warnings(P.Policy(data))
    assert len(warns) == 1 and "allow-edit-docs" in warns[0]


def test_a_server_pattern_of_just_star_is_not_a_scope():
    assert len(scope_warnings(P.Policy(scoped_data("*")))) == 2
    assert len(scope_warnings(P.Policy(scoped_data(["filesystem", "*"])))) == 2
    assert scope_warnings(P.Policy(scoped_data(["filesystem", "docs-*"]))) == []


@pytest.mark.parametrize("pattern", ["**", "?*", "*?", "???", "*?*", "?"])
def test_any_pattern_made_only_of_star_and_question_mark_is_not_a_scope(pattern):
    assert len(scope_warnings(P.Policy(scoped_data(pattern)))) == 2
    assert len(scope_warnings(P.Policy(scoped_data(["filesystem", pattern])))) == 2


@pytest.mark.parametrize("pattern", ["filesystem", "fs-?", "?s", "*fs*", "docs-*"])
def test_a_pattern_with_a_literal_character_is_a_scope(pattern):
    assert scope_warnings(P.Policy(scoped_data(pattern))) == []


def test_only_allow_rules_with_a_write_confine_are_warned():
    d = {"version": 1, "default": "ask", "rules": [
        {"id": "read-any", "verdict": "allow", "when": {"tool": "read_file", "arg_keys": ["path"]}, "confine": {"path": "read"}},
        {"id": "ask-write", "verdict": "ask", "when": {"tool": "write_file"}}]}
    assert scope_warnings(P.Policy(d)) == []


def test_the_scoped_rule_allows_the_named_server_and_asks_another():
    pol = P.Policy(scoped_data())
    for tool, rid in (("write_file", "allow-write-docs"), ("edit_file", "allow-edit-docs")):
        d = call(pol, "filesystem", tool)
        assert (d.verdict, d.rule_id, d.confine) == ("allow", rid, {"path": "write"})
        d = call(pol, "other", tool)
        assert d.verdict == "ask" and d.rule_id != rid and d.confine in (None, {})


def test_the_unscoped_starter_allows_any_server_which_is_why_it_is_warned_about():
    pol = P.load_policy(STARTER)
    assert call(pol, "anything-at-all").verdict == "allow"


def test_a_server_pattern_list_and_a_glob_match():
    pol = P.Policy(scoped_data(["filesystem", "docs-*"]))
    assert call(pol, "docs-eu").verdict == "allow" and call(pol, "filesystem").verdict == "allow"
    assert call(pol, "docs").verdict == "ask"
    assert call(pol, "filesystem-evil").verdict == "ask" and call(pol, "").verdict == "ask"


def test_explain_shows_the_scoped_rule_for_the_named_server_and_not_for_another(tmp_path, capsys):
    f = tmp_path / "scoped.json"
    f.write_text(json.dumps(scoped_data()))
    args = json.dumps({"path": "/p/notes.md", "content": "x"})
    assert C.main(["explain", str(f), "--server", "filesystem", "--tool", "write_file", "--args", args]) == 0
    out = capsys.readouterr().out
    assert "verdict: allow" in out and "rule:    allow-write-docs" in out
    assert C.main(["explain", str(f), "--server", "other", "--tool", "write_file", "--args", args]) == 0
    out = capsys.readouterr().out
    assert "verdict: ask" in out and "allow-write-docs" not in out.split("matched:")[0]


def test_the_ready_to_paste_example_in_the_docs_is_valid_and_lints_without_the_warning():
    text = open(os.path.join(ROOT, "docs", "policy.md")).read()
    assert "Scope the write rules to one server" in text and '{"server": "filesystem"}' in text
    d32 = open(os.path.join(ROOT, "DECISIONS.md")).read().split("## D32:")[1].split("\n## ")[0]
    assert '"server": "filesystem"' in d32 and "lint" in d32


def test_the_starter_file_itself_and_its_replay_numbers_are_unchanged():
    base = P.load_policy(STARTER)
    assert all(r.server is None for r in base.rules)
    for r in base.rules:
        if r.id in WRITE_RULES:
            assert r.confine == {"path": "write"}
