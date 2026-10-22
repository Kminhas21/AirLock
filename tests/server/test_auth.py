"""Tests for server/auth.py (A1). The env mapping is always passed explicitly."""
import dataclasses
import hmac

import pytest

import auth
from auth import AccessResult, check_ws_access

DEFAULT_ORIGIN = "http://localhost:5173"


def test_no_token_configured_is_open():
    r = check_ws_access(None, None, env={})
    assert r == AccessResult(True, "open")


def test_no_token_configured_ignores_supplied_token():
    assert check_ws_access(None, "whatever", env={}).allowed is True


def test_empty_token_env_counts_as_unset():
    assert check_ws_access(None, None, env={"SENTINEL_WS_TOKEN": ""}).reason == "open"


def test_token_missing_denied():
    r = check_ws_access(None, None, env={"SENTINEL_WS_TOKEN": "s3cret"})
    assert r == AccessResult(False, "bad_token")


def test_token_empty_string_denied():
    assert not check_ws_access(None, "", env={"SENTINEL_WS_TOKEN": "s3cret"}).allowed


def test_token_wrong_denied():
    r = check_ws_access(None, "nope", env={"SENTINEL_WS_TOKEN": "s3cret"})
    assert r == AccessResult(False, "bad_token")


def test_token_prefix_denied():
    assert not check_ws_access(None, "s3cre", env={"SENTINEL_WS_TOKEN": "s3cret"}).allowed


def test_token_right_allowed():
    r = check_ws_access(None, "s3cret", env={"SENTINEL_WS_TOKEN": "s3cret"})
    assert r.allowed is True and r.reason == "ok"


def test_non_ascii_token_does_not_raise():
    env = {"SENTINEL_WS_TOKEN": "sécret"}
    assert check_ws_access(None, "sécret", env=env).allowed
    assert not check_ws_access(None, "secret", env=env).allowed


def test_constant_time_compare_used(monkeypatch):
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(auth.hmac, "compare_digest", spy)
    check_ws_access(None, "s3cret", env={"SENTINEL_WS_TOKEN": "s3cret"})
    assert len(calls) == 1


def test_origin_absent_allowed():
    assert check_ws_access(None, None, env={}).allowed


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173"])
def test_default_origins_allowed(origin):
    assert check_ws_access(origin, None, env={}).allowed


@pytest.mark.parametrize(
    "origin",
    ["http://evil.example", "null", "", "http://localhost:5174", "https://localhost:5173",
     "http://localhost:5173/"],
)
def test_other_origins_blocked(origin):
    r = check_ws_access(origin, None, env={})
    assert r == AccessResult(False, "bad_origin")


def test_custom_origins_parsing_whitespace_and_trailing_commas():
    env = {"SENTINEL_ALLOWED_ORIGINS": "  https://a.example ,https://b.example, ,"}
    assert check_ws_access("https://a.example", None, env=env).allowed
    assert check_ws_access("https://b.example", None, env=env).allowed
    assert not check_ws_access("https://c.example", None, env=env).allowed
    # empty entries from stray commas must not whitelist the empty origin
    assert not check_ws_access("", None, env=env).allowed


def test_custom_origins_replace_defaults():
    env = {"SENTINEL_ALLOWED_ORIGINS": "https://a.example"}
    assert not check_ws_access(DEFAULT_ORIGIN, None, env=env).allowed


def test_blank_custom_origins_falls_back_to_defaults():
    env = {"SENTINEL_ALLOWED_ORIGINS": " , "}
    assert check_ws_access(DEFAULT_ORIGIN, None, env=env).allowed


def test_bad_origin_checked_even_with_right_token():
    env = {"SENTINEL_WS_TOKEN": "t"}
    assert check_ws_access("http://evil.example", "t", env=env) == AccessResult(False, "bad_origin")


def test_good_origin_wrong_token_denied():
    env = {"SENTINEL_WS_TOKEN": "t"}
    assert check_ws_access(DEFAULT_ORIGIN, "x", env=env) == AccessResult(False, "bad_token")


def test_good_origin_right_token_allowed():
    env = {"SENTINEL_WS_TOKEN": "t"}
    assert check_ws_access(DEFAULT_ORIGIN, "t", env=env).allowed


def test_result_is_frozen():
    r = check_ws_access(None, None, env={})
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.allowed = False


def test_module_does_not_import_fastapi():
    src = open(auth.__file__).read()
    assert "fastapi" not in src and "starlette" not in src
