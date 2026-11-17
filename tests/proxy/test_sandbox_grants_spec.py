"""`write` is refused at EVERY layer today (phase 1 of the "narrow write right" plan): when the right is added these become the acceptance
tests, flipped on purpose. This file is the sandbox side: the grant list of a confined worker's spec (`sandbox._grants`, reached through
`validate_spec(..., internal=True)`), `sandbox_params`, the trampoline's `main`, and the exact error text. Other layers:
  policy        tests/server/test_policy_confine.py, tests/server/test_policy_write_refused.py (load, lint, writer)
  backend       tests/proxy/test_confine_precheck.py (`_confine_map`), tests/proxy/test_confine_write_refused.py (wire + proxy)
No process, no kernel feature needed: `sandbox_exec.main` is driven with a stub `execve` that must never be called."""
import json

import pytest

from sentinel_proxy import confine, sandbox, sandbox_exec

BASE = {"read": [], "write": [], "runtime": [], "network": "none", "env_allow": [], "rlimits": {}, "require": True}


def spec(*grants, **kw):
    return {**BASE, "grants": [list(g) for g in grants], **kw}


def bad(*grants, match, **kw):
    with pytest.raises(sandbox.SandboxSpecError, match=match):
        sandbox.validate_spec(spec(*grants, **kw), internal=True)


# --------------------------------------------------------------------------- the right


@pytest.mark.parametrize("right", ["write", "WRITE", "Write", "read|write", "rw", "w", "create", "append", "truncate", "delete", "execute", "",
                                   " read", "read ", "read\x00", "list,write", None, 1, True])
def test_any_right_but_read_and_list_is_rejected_with_the_list_of_valid_ones(right):
    bad(("/", "/w/a.txt", right), match=r"right must be one of read, list")


@pytest.mark.parametrize("right", [["read"], {"read": 1}])
def test_an_unhashable_right_is_a_spec_error_and_the_trampoline_exits_126(right):
    """`isinstance(right, str)` comes before the membership test, so a list / object is a SandboxSpecError, not a TypeError, and the
    trampoline never gets as far as exec."""
    bad(("/", "/w/a.txt", right), match=r"right must be one of read, list")
    called = []
    rc = sandbox_exec.main(["--spec", sandbox.encode_spec(spec(("/", "/w/a.txt", right))), "--", "/bin/true"], execve=lambda *a: called.append(a))
    assert rc == 126 and called == []


def test_the_valid_rights_are_read_and_list_and_come_back_unchanged():
    out = sandbox.validate_spec(spec(("/", "/w/a.txt", "read"), ("/w", "sub", "list")), internal=True)
    assert out["grants"] == [["/", "/w/a.txt", "read"], ["/w", "sub", "list"]]


def test_a_write_grant_next_to_valid_ones_rejects_the_whole_spec_not_just_the_entry():
    bad(("/", "/w/a.txt", "read"), ("/", "/w/b.txt", "write"), ("/", "/w/c.txt", "read"), match="right must be one of")


def test_the_operators_write_directories_are_not_grants_and_stay_a_separate_key():
    out = sandbox.validate_spec(spec(("/", "/w/a.txt", "read"), write=["/data/out"]), internal=True)
    assert out["write"] == ["/data/out"] and all(g[2] in ("read", "list") for g in out["grants"])


# --------------------------------------------------------------------------- shape


@pytest.mark.parametrize("grants", ["x", {"a": 1}, 5, None, "/", ("/", "a", "read")])
def test_grants_must_be_a_list(grants):
    with pytest.raises(sandbox.SandboxSpecError, match="grants: must be a list"):
        sandbox.validate_spec({**BASE, "grants": grants}, internal=True)


@pytest.mark.parametrize("entry", [[], ["/"], ["/", "a"], ["/", "a", "read", "x"], "abc", 5, None, {"base": "/"}, "rea"])
def test_an_entry_must_be_exactly_base_value_right(entry):
    with pytest.raises(sandbox.SandboxSpecError, match=r"entries must be \[base, value, right\]"):
        sandbox.validate_spec({**BASE, "grants": [entry]}, internal=True)


def test_an_entry_may_be_a_tuple_and_comes_back_as_a_list():
    out = sandbox._grants([("/", "/w/a", "read")])
    assert out == [["/", "/w/a", "read"]] and isinstance(out[0], list)


@pytest.mark.parametrize("base", ["relative", "", "//x", "/a/../b", "/a\x00b", 5, None, ["/"]])
def test_the_base_must_be_an_absolute_clean_path(base):
    with pytest.raises(sandbox.SandboxSpecError, match="grants base"):
        sandbox.validate_spec(spec((base, "a.txt", "read")), internal=True)


@pytest.mark.parametrize("value", ["", "a\x00b", "\x00", 5, None, ["a"], "x" * (sandbox.MAX_PATH_LEN + 1)])
def test_the_value_must_be_a_nonempty_string_without_nul_of_bounded_length(value):
    bad(("/", value, "read"), match="a value must be a non-empty string without NUL")


def test_a_value_of_exactly_the_maximum_length_is_accepted_and_a_relative_or_dotdot_value_is_not_judged_here():
    """Judging WHERE a value leads is the walk's job (openat2 beneath the base), not the spec's: `..` and relative values are valid text."""
    ok = ["/", "x" * sandbox.MAX_PATH_LEN, "read"], ["/w", "../x", "read"], ["/w", "a/./b", "list"]
    assert sandbox._grants([list(g) for g in ok]) == [list(g) for g in ok]


def test_the_grant_count_is_capped_at_max_grants():
    many = [["/", f"/w/{i}", "read"] for i in range(sandbox.MAX_GRANTS)]
    assert len(sandbox.validate_spec({**BASE, "grants": many}, internal=True)["grants"]) == sandbox.MAX_GRANTS
    bad(*(many + [["/", "/w/x", "read"]]), match=f"at most {sandbox.MAX_GRANTS}")
    assert sandbox.MAX_GRANTS == confine.MAX_VALUES * confine.MAX_BASES


def test_grants_are_internal_an_operators_config_can_never_carry_them():
    with pytest.raises(sandbox.SandboxSpecError, match="unknown sandbox key 'grants'"):
        sandbox.validate_spec({**BASE, "grants": [["/", "/w/a", "read"]]})
    assert "grants" not in sandbox.validate_spec(BASE, internal=True)


# --------------------------------------------------------------------------- the confine layer feeds the same validation


def test_a_write_confine_map_produces_a_spec_the_sandbox_refuses():
    """`confine.grant_specs` passes the right through unjudged (the policy and the wire already refused it); the sandbox is the last gate."""
    class SC:
        args, cwd = ["/w"], None
    specs = confine.grant_specs({"path": "/w/a.md"}, {"path": "write"}, SC())
    assert specs == [["/", "/w/a.md", "write"]]
    with pytest.raises(sandbox.SandboxSpecError, match="right must be one of"):
        sandbox.validate_spec(confine.confined_spec(BASE, specs), internal=True)
    with pytest.raises(sandbox.SandboxSpecError):
        sandbox.sandbox_params(confine.confined_spec(BASE, specs), "/bin/true", [])


# --------------------------------------------------------------------------- the trampoline refuses before it does anything


def run_main(*grants, **kw):
    called = []
    blob = sandbox.encode_spec(spec(*grants, **kw))                      # encoded WITHOUT validation: what a hostile caller could send
    rc = sandbox_exec.main(["--spec", blob, "--", "/bin/true"], execve=lambda *a: called.append(a))
    return rc, called


def test_the_trampoline_fails_closed_on_a_write_grant_and_never_runs_the_command(capfd):
    rc, called = run_main(("/", "/w/a.md", "write"))
    err = capfd.readouterr().err
    assert rc == sandbox_exec.EXIT_FAIL_CLOSED == 126 and called == []
    assert "invalid spec" in err and "right must be one of read, list" in err and "SENTINEL_SANDBOX_STATUS" not in err


def test_the_trampoline_fails_closed_on_a_nul_value_and_on_a_malformed_entry(capfd):
    for grants in ([("/", "a\x00b", "read")], [("/",)], [("/", "x", "write"), ("/", "y", "read")]):
        rc, called = run_main(*grants)
        assert rc == 126 and called == []
    assert "invalid spec" in capfd.readouterr().err


def test_the_trampoline_rejects_a_spec_blob_that_is_not_valid_base64_json():
    for blob in ("not base64!!", sandbox.encode_spec({"grants": "x"}), "e30="[:3], ""):
        assert sandbox_exec.main(["--spec", blob, "--", "/bin/true"], execve=lambda *a: pytest.fail("exec")) == 126


def test_a_valid_spec_blob_decodes_to_the_same_grants():
    blob = sandbox.encode_spec(spec(("/", "/w/a", "read")))
    assert sandbox.decode_spec(blob)["grants"] == [["/", "/w/a", "read"]]
    assert json.loads(__import__("base64").b64decode(blob))["grants"] == [["/", "/w/a", "read"]]
