"""The `secrets` condition of the policy engine (EB3): credentials are only ever allowed by a rule that says so."""
import json

import pytest

import policy as P
from policy import Policy, PolicyError, load_policy
import policy_writer


def pol(rules, default="ask"):
    return load_policy({"version": 1, "default": default, "rules": rules})


def rule(rid, verdict, **when):
    r = {"id": rid, "verdict": verdict}
    if when:
        r["when"] = when
    return r


def test_default_keyword_false_keeps_existing_behaviour():
    p = pol([rule("a", "allow", tool=["t"])])
    assert p.evaluate("s", "t", {}).verdict == "allow"
    assert p.evaluate("s", "t", {}, secrets_used=False).verdict == "allow"


def test_allow_rule_without_secrets_condition_does_not_allow_a_call_with_secrets():
    d = pol([rule("a", "allow", tool=["t"])]).evaluate("s", "t", {}, secrets_used=True)
    assert (d.verdict, d.rule_id, d.reason, d.escalated) == ("ask", "a", "secrets", True)


def test_default_allow_does_not_cover_secrets():
    d = pol([], default="allow").evaluate("s", "t", {}, secrets_used=True)
    assert d.verdict == "ask" and d.reason == "secrets" and d.rule_id is None
    assert pol([], default="allow").evaluate("s", "t", {}).verdict == "allow"


def test_allow_rule_with_secrets_true_allows_only_calls_with_secrets():
    p = pol([rule("a", "allow", tool=["t"], secrets=True)], default="deny")
    d = p.evaluate("s", "t", {}, secrets_used=True)
    assert (d.verdict, d.rule_id, d.reason) == ("allow", "a", "rule:a")
    assert p.evaluate("s", "t", {}, secrets_used=False).verdict == "deny"      # the rule does not match: default


def test_allow_rule_with_secrets_false_never_allows_credentials():
    p = pol([rule("a", "allow", tool=["t"], secrets=False)], default="deny")
    assert p.evaluate("s", "t", {}).verdict == "allow"
    assert p.evaluate("s", "t", {}, secrets_used=True).verdict == "deny"       # does not match, default deny


def test_more_specific_secrets_rule_wins_over_a_plain_allow_rule():
    p = pol([rule("plain", "allow", tool=["t"]), rule("creds", "allow", tool=["t"], secrets=True)])
    assert p.evaluate("s", "t", {}, secrets_used=True).rule_id == "creds"
    assert p.evaluate("s", "t", {}, secrets_used=True).verdict == "allow"
    assert p.evaluate("s", "t", {}).rule_id == "plain"


def test_deny_and_ask_rules_without_the_condition_still_match_calls_with_secrets():
    p = pol([rule("d", "deny", tool=["rm"]), rule("k", "ask", tool=["w"]), rule("a", "allow", tool=["w"], secrets=True)])
    assert p.evaluate("s", "rm", {}, secrets_used=True).verdict == "deny"
    d = p.evaluate("s", "w", {}, secrets_used=True)
    assert d.verdict == "ask" and d.rule_id == "k"


def test_deny_rule_with_secrets_true_only_denies_calls_with_secrets():
    p = pol([rule("d", "deny", tool=["t"], secrets=True)], default="allow")
    assert p.evaluate("s", "t", {}, secrets_used=True).verdict == "deny"
    assert p.evaluate("s", "t", {}).verdict == "allow"


def test_alert_reason_wins_over_secrets():
    d = pol([rule("a", "allow", tool=["t"], secrets=True)]).evaluate("s", "t", {}, alerts_present=True, secrets_used=True)
    assert d.verdict == "ask" and d.reason == "alert"


@pytest.mark.parametrize("bad", ["true", 1, 0, None, [], {}])
def test_secrets_must_be_a_boolean(bad):
    with pytest.raises(PolicyError):
        pol([rule("a", "allow", tool=["t"], secrets=bad)])


def test_lint_warns_for_a_bare_secrets_allow_rule():
    warns = pol([rule("wide", "allow", secrets=True)]).lint()
    assert any("wide" in w and "secrets" in w for w in warns)
    assert not any("secrets" in w for w in pol([rule("ok", "allow", tool=["t"], secrets=True)]).lint())
    assert not any("secrets" in w for w in pol([rule("d", "deny", secrets=True)]).lint())


def test_digest_and_duplicate_detection_see_the_condition():
    a = pol([rule("a", "allow", tool=["t"], secrets=True)])
    b = pol([rule("a", "allow", tool=["t"])])
    assert a.digest() != b.digest()
    dup = pol([rule("x", "allow", tool=["t"], secrets=True), rule("y", "allow", tool=["t"])])
    assert not any("identical" in w for w in dup.lint())                    # different conditions


# ------------------------------------------------------------------ writer round trip
def test_build_rule_never_emits_secrets_and_append_rule_accepts_a_file_that_has_it(tmp_path):
    for verdict, scope in (("allow", "exact"), ("allow", "tool_under"), ("deny", "tool"), ("ask", "exact")):
        r = policy_writer.build_rule(verdict, scope, "fs", "write_file", {"path": "/p/a", "n": 1})
        assert "secrets" not in r["when"]
    f = tmp_path / "p.json"
    f.write_text(json.dumps({"version": 1, "default": "ask",
                             "rules": [rule("creds", "allow", tool=["t"], secrets=True)]}))
    out = policy_writer.append_rule(str(f), policy_writer.build_rule("deny", "tool", "fs", "rm", {}))
    data = json.loads(f.read_text())
    assert [r["id"] for r in data["rules"]][0] == "creds" and data["rules"][0]["when"]["secrets"] is True
    assert out["rule_id"] in [r["id"] for r in data["rules"]]
    assert P.load_policy_file(str(f))[0] is not None
