"""Agent credentials (ID3): Authorization header, no token in URLs, scrubbing, auth failures exit 3."""
import asyncio
import json

import pytest
from websockets.asyncio.server import serve

from conftest import FakeBackend, agent, make_config, run_proxy_exit
from test_proxy_integration import _raw_agent

TOK = "agent-tok-9f3c1d7a"
LEG = "legacy-tok-55aa12"


async def test_header_exact_and_url_has_no_token_when_agent_token_set(tmp_path, backend):
    cfg, _ = make_config(tmp_path, backend.url)
    async with agent(cfg, {"SENTINEL_AGENT_TOKEN": TOK, "SENTINEL_WS_TOKEN": LEG}) as s:
        assert not (await s.call_tool("echo", {})).is_error
    h = backend.handshakes[0]
    assert h["auth"] == f"Bearer {TOK}"
    assert "token" not in h["path"] and "?" not in h["path"] and TOK not in h["path"] and LEG not in h["path"]
    assert TOK not in json.dumps(backend.frames) and LEG not in json.dumps(backend.frames)


async def test_no_credentials_means_no_header(tmp_path, backend):
    cfg, _ = make_config(tmp_path, backend.url)
    async with agent(cfg) as s:
        await s.call_tool("echo", {})
    assert backend.handshakes[0]["auth"] is None and "?" not in backend.handshakes[0]["path"]


async def test_legacy_ws_token_keeps_query_and_also_sends_header(tmp_path, backend):
    cfg, _ = make_config(tmp_path, backend.url)
    async with agent(cfg, {"SENTINEL_WS_TOKEN": LEG}) as s:
        assert not (await s.call_tool("echo", {})).is_error
    h = backend.handshakes[0]
    assert h["path"].endswith(f"?token={LEG}") and h["auth"] == f"Bearer {LEG}"
    assert LEG not in json.dumps(backend.frames)


async def test_token_never_on_stderr_even_if_backend_echoes_it(tmp_path, backend):
    for env in ({"SENTINEL_AGENT_TOKEN": TOK}, {"SENTINEL_WS_TOKEN": LEG}):
        tok = next(iter(env.values()))
        backend.hello_reply = f"reject:bad credential {tok} presented"
        cfg, _ = make_config(tmp_path, backend.url)
        code, err, out = await run_proxy_exit(cfg, env)
        assert code == 3 and tok not in err and tok not in out and "[REDACTED]" in err


async def test_token_in_config_url_is_scrubbed_too(tmp_path, backend):
    backend.hello_reply = "reject:echo qq-url-token-77 echo"
    cfg, _ = make_config(tmp_path, backend.url + "?token=qq-url-token-77")
    code, err, _ = await run_proxy_exit(cfg)
    assert code == 3 and "qq-url-token-77" not in err


@pytest.mark.parametrize("reason", ["unauthorized", "forbidden_server"])
async def test_hello_reject_auth_reasons_exit_3_first_connect(tmp_path, backend, reason):
    backend.hello_reply = f"reject:{reason}"
    cfg, _ = make_config(tmp_path, backend.url)
    code, err, out = await run_proxy_exit(cfg, {"SENTINEL_AGENT_TOKEN": TOK})
    assert code == 3 and reason in err and out == "" and TOK not in err


@pytest.mark.parametrize("reason", ["unauthorized", "forbidden_server"])
async def test_hello_reject_auth_reasons_exit_3_on_reconnect_no_hammering(tmp_path, backend, reason):
    cfg, _ = make_config(tmp_path, backend.url)
    proc, _send = await _raw_agent(cfg, {"SENTINEL_AGENT_TOKEN": TOK})
    try:
        await backend.wait_for("proxy_hello")
        backend.hello_reply = f"reject:{reason}"
        await backend.kick()
        assert await asyncio.wait_for(proc.wait(), 20) == 3
        assert len(backend.of("proxy_hello")) == 2  # one rejected retry, then it gave up
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


async def test_close_1008_before_any_frame_exits_3(tmp_path):
    seen = []

    async def handler(ws):
        seen.append(1)
        await ws.close(1008, "origin not allowed")
    async with serve(handler, "127.0.0.1", 0) as srv:
        cfg, _ = make_config(tmp_path, f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}/proxy/ws")
        code, err, out = await run_proxy_exit(cfg, {"SENTINEL_AGENT_TOKEN": TOK})
    assert code == 3 and "unauthorized" in err and "1008" in err and TOK not in err and out == ""
    assert len(seen) == 1  # not retried


async def test_http_403_handshake_refusal_exits_3(tmp_path):
    from websockets.http11 import Response

    async def deny(connection, request):
        return connection.respond(403, "forbidden\n")
    async with serve(lambda ws: None, "127.0.0.1", 0, process_request=deny) as srv:
        cfg, _ = make_config(tmp_path, f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}/proxy/ws")
        code, err, _ = await run_proxy_exit(cfg)
    assert code == 3 and "unauthorized" in err


async def test_close_1008_after_a_successful_connect_is_retried_not_fatal(tmp_path, backend):
    cfg, _ = make_config(tmp_path, backend.url)
    async with agent(cfg) as s:
        await backend.wait_for("proxy_hello")
        for ws in list(backend.conns):
            await ws.close(1008)
        await backend.wait_for("proxy_hello", n=2, timeout=20)  # transient: reconnects
        assert not (await s.call_tool("echo", {})).is_error
