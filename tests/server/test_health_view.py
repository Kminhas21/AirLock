import httpx
import pytest

import health_view as hv
import live_drift
import proposal_monitor
from main import app

INFO = {"monitor": "registry_learned_e", "requested_monitor": "registry_learned_e", "embedder": "minilm",
        "registry": {"path": "/etc/secret/ops/registry.json", "digest": "abc", "entries": 3},
        "frozen_model": {"path": "/srv/app/eval/frozen.json", "sha256": "ff", "schema_version": "v"},
        "last_session_fallback": "registry_learned_e -> action_sim: ValueError: bad file /etc/secret/ops/x.json line 3",
        "monitor_errors": 0, "session_fallbacks": 1}


def test_public_view_keeps_the_keys_but_hides_paths_and_messages():
    out = hv.public_view(INFO)
    assert set(out) == set(INFO)
    assert out["registry"] == {"path": "registry.json", "digest": "abc", "entries": 3}
    assert out["frozen_model"]["path"] == "frozen.json"
    assert out["last_session_fallback"] == "registry_learned_e -> action_sim: ValueError"
    assert "/etc" not in str(out) and "/srv" not in str(out) and "line 3" not in str(out)
    assert INFO["registry"]["path"].startswith("/etc"), "the input must not be mutated"


def test_public_view_handles_none_values():
    out = hv.public_view({"registry": None, "frozen_model": None, "last_session_fallback": None})
    assert out == {"registry": None, "frozen_model": None, "last_session_fallback": None}


@pytest.mark.parametrize("env,query,auth,ok", [
    ({}, None, None, False),                                                  # no token configured, no opt-in: public only
    ({"SENTINEL_HEALTH_DETAIL": "1"}, None, None, True),                       # explicit local opt-in
    ({"SENTINEL_HEALTH_DETAIL": "0"}, None, None, False),
    ({"SENTINEL_WS_TOKEN": "s3"}, None, None, False),                         # token configured: must be supplied
    ({"SENTINEL_WS_TOKEN": "s3"}, "wrong", None, False),
    ({"SENTINEL_WS_TOKEN": "s3"}, "s3", None, True),
    ({"SENTINEL_WS_TOKEN": "s3"}, None, "Bearer s3", True),
    ({"SENTINEL_WS_TOKEN": "s3"}, None, "bearer s3", True),
    ({"SENTINEL_WS_TOKEN": "s3"}, None, "Bearer nope", False),
    ({"SENTINEL_WS_TOKEN": "s3", "SENTINEL_HEALTH_DETAIL": "1"}, None, None, False),   # the opt-in never beats a configured token
    ({"SENTINEL_WS_TOKEN": "s3"}, "é", None, False),                     # non-ASCII must not raise
])
def test_detail_allowed(env, query, auth, ok):
    assert hv.detail_allowed(query, auth, env) is ok


async def _health(monkeypatch, env, params=None, headers=None):
    for k in ("SENTINEL_WS_TOKEN", "SENTINEL_HEALTH_DETAIL"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    monkeypatch.setattr(live_drift, "monitor_info", lambda: INFO)
    import main
    monkeypatch.setattr(main, "monitor_info", lambda: INFO)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return (await c.get("/health", params=params, headers=headers)).json()


async def test_endpoint_is_public_view_by_default(monkeypatch):
    body = await _health(monkeypatch, {})
    assert body["registry"]["path"] == "registry.json" and body["status"] == "ok"
    assert body["last_session_fallback"].endswith("ValueError")


async def test_endpoint_shows_detail_to_the_token_holder_only(monkeypatch):
    assert (await _health(monkeypatch, {"SENTINEL_WS_TOKEN": "s3"}))["registry"]["path"] == "registry.json"
    assert (await _health(monkeypatch, {"SENTINEL_WS_TOKEN": "s3"}, params={"token": "s3"}))["registry"]["path"].startswith("/etc")
    assert (await _health(monkeypatch, {"SENTINEL_WS_TOKEN": "s3"}, headers={"Authorization": "Bearer s3"}))["frozen_model"]["path"].startswith("/srv")


async def test_endpoint_opt_in_for_local_development(monkeypatch):
    assert (await _health(monkeypatch, {"SENTINEL_HEALTH_DETAIL": "1"}))["registry"]["path"].startswith("/etc")
