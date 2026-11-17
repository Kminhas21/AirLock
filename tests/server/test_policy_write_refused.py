"""`write` is refused in a rule's `confine` map today, at every policy layer (phase 1 of the "narrow write right" plan; the proxy and sandbox
layers are in tests/proxy/test_confine_write_refused.py and test_sandbox_grants_spec.py). When the right is added these are the tests that
flip on purpose: validation, the closed set, the file loader, `policy_cli lint`, the hub (a policy that carries it is a broken policy, so
every call is held) and the digest."""
import json

import pytest

import inbox_hub
import policy as P
import policy_cli as C
import proposal_monitor
from test_inbox_hub import Rig, call, wait_for

RULE = {"id": "w", "verdict": "allow", "when": {"tool": "write_file", "arg_keys": ["path", "content"]}, "confine": {"path": "write"}}
GOOD = {**RULE, "confine": {"path": "read"}}
MSG = "confine.'path': must be \"read\" (exactly that file) or \"list\" (names beneath that directory)"


def doc(*rules):
    return {"version": 1, "default": "ask", "rules": list(rules)}


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


def test_the_closed_set_of_rights_is_read_and_list():
    assert P.CONFINE_RIGHTS == ("read", "list")


@pytest.mark.parametrize("right", ["write", "WRITE", "Write", " write", "write ", "read|write", "read,write", "rw", "w", "create", "append",
                                   "truncate", "delete", "execute", "", True, 1, None, ["write"], {"write": True}])
def test_a_confine_right_outside_read_and_list_is_a_policy_error_with_the_exact_message(right):
    with pytest.raises(P.PolicyError) as e:
        P.Policy(doc({**RULE, "confine": {"path": right}}))
    assert any(MSG in m for m in e.value.messages), e.value.messages


def test_a_write_right_next_to_valid_ones_rejects_the_whole_policy():
    rule = {**RULE, "id": "w2", "when": {"tool": "copy", "arg_keys": ["source", "destination", "path"]},
            "confine": {"source": "read", "destination": "write", "path": "list"}}
    with pytest.raises(P.PolicyError) as e:
        P.Policy(doc(GOOD, rule))
    assert len(e.value.messages) == 1 and "confine.'destination'" in e.value.messages[0]


def test_a_write_right_on_a_rule_that_is_not_an_allow_is_refused_for_the_verdict_first():
    for verdict in ("ask", "deny"):
        with pytest.raises(P.PolicyError) as e:
            P.Policy(doc({**RULE, "verdict": verdict}))
        assert any("only allow rules can have one" in m for m in e.value.messages)


def test_the_valid_rights_still_load_and_are_part_of_the_digest():
    assert P.Policy(doc(GOOD)).rules[0].confine == {"path": "read"}
    assert P.Policy(doc({**GOOD, "confine": {"path": "list"}})).rules[0].confine == {"path": "list"}
    assert P.Policy(doc(GOOD)).digest() != P.Policy(doc({**GOOD, "confine": {"path": "list"}})).digest()


def test_the_file_loader_reports_a_rejected_policy_and_returns_none(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc(RULE)))
    pol, why = P.load_policy_file(str(f))
    assert pol is None and "rejected" in why and MSG in why


def test_lint_exits_1_and_names_the_rule_and_the_right(tmp_path, capsys):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc(RULE)))
    assert C.main(["lint", str(f)]) == 1
    out = capsys.readouterr()
    text = out.err + out.out
    assert "(w)" in text and "confine.'path'" in text and '"read"' in text and '"list"' in text
    f.write_text(json.dumps(doc(GOOD)))
    assert C.main(["lint", str(f)]) == 0


@pytest.mark.parametrize("sub", ["explain", "test"])
def test_the_other_cli_commands_refuse_it_too(tmp_path, capsys, sub):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc(RULE)))
    argv = ["explain", str(f), "--server", "fs", "--tool", "write_file", "--args", "{}"] if sub == "explain" else ["test", str(f), "--traces", str(f)]
    assert C.main(argv) == 1


async def test_a_hub_on_a_policy_file_with_a_write_right_holds_every_call(monkeypatch, tmp_path):
    f = tmp_path / "p.json"
    f.write_text(json.dumps(doc(RULE, {"id": "r", "verdict": "allow", "when": {"tool": "read_text_file", "arg_keys": ["path"]},
                                       "confine": {"path": "read"}})))
    monkeypatch.setenv("SENTINEL_POLICY", str(f))
    r = await Rig().start()
    assert r.session.policy is None and r.session.policy_mode is True
    await r.send(call("c1", tool="write_file", args={"path": "/w/a.md", "content": "x"}, confinable=True, auto=True))
    await r.send(call("c2", tool="read_text_file", args={"path": "/w/a.md"}, confinable=True, auto=True))   # a valid rule next to it: still broken
    await wait_for(lambda: len(r.ui.events("inbox_pending")) == 2)
    assert r.decisions() == []
    assert all(p["rule_id"] is None and p["policy_digest"] is None for p in r.ui.events("inbox_pending"))


def test_the_starter_and_the_shipped_example_carry_no_write_right():
    import pathlib
    root = pathlib.Path(P.__file__).resolve().parents[1]
    for rel in ("server/policies/starter.json", "docs/examples/policy.example.json"):
        text = (root / rel).read_text()
        assert '"write"' not in "".join(json.dumps(r.get("confine", {})) for r in json.loads(text).get("rules", [])), rel
