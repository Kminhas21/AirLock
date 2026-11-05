"""End to end: /proxy/ws and /inbox/ws through the FastAPI app (Starlette TestClient)."""
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import live_drift
import main
import proposal_monitor
from inbox_hub import InboxHub

HELLO = {"event": "proxy_hello", "session_id": "e2e", "servers": ["fs"], "auto_approve": ["fs:read_file"]}


def call(cid="c1", **kw):
    return {"event": "proxy_call", "call_id": cid, "server": "fs", "tool": "write_file", "args": {"path": "a.txt"},
            "auto": False, **kw}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    monkeypatch.delenv("SENTINEL_MONITOR", raising=False)
    monkeypatch.delenv("SENTINEL_WS_TOKEN", raising=False)
    live_drift._reset_embedder_cache()
    proposal_monitor._reset_factory_cache()
    monkeypatch.setattr(main, "inbox_hub", InboxHub(gate_timeout=30))
    with TestClient(main.app) as c:
        yield c
    live_drift._reset_embedder_cache()
    proposal_monitor._reset_factory_cache()


def open_pair(client, ws_ui, ws_proxy):
    snap = ws_ui.receive_json()
    assert snap == {"event": "inbox_snapshot", "sessions": []}
    ws_proxy.send_json(HELLO)
    assert ws_proxy.receive_json() == {"event": "hello_ack", "session_id": "e2e"}
    assert ws_ui.receive_json() == {"event": "inbox_session", "session_id": "e2e", "state": "open"}


@pytest.mark.parametrize("path", ["/proxy/ws", "/inbox/ws"])
def test_bad_origin_rejected_1008(client, path):
    with pytest.raises(WebSocketDisconnect) as ei:
        with client.websocket_connect(path, headers={"origin": "http://evil.example"}):
            pass
    assert ei.value.code == 1008


@pytest.mark.parametrize("path", ["/proxy/ws", "/inbox/ws"])
def test_allowed_origin_accepted(client, path):
    with client.websocket_connect(path, headers={"origin": "http://localhost:5173"}):
        pass


@pytest.mark.parametrize("path", ["/proxy/ws", "/inbox/ws"])
def test_token_enforced(client, monkeypatch, path):
    monkeypatch.setenv("SENTINEL_WS_TOKEN", "s3cret")
    for url in (path, path + "?token=wrong"):
        with pytest.raises(WebSocketDisconnect) as ei:
            with client.websocket_connect(url):
                pass
        assert ei.value.code == 1008
    with client.websocket_connect(path + "?token=s3cret"):
        pass


def test_approve_flow(client):
    with client.websocket_connect("/inbox/ws") as ui, client.websocket_connect("/proxy/ws") as proxy:
        open_pair(client, ui, proxy)
        proxy.send_json(call())
        p = ui.receive_json()
        assert p["event"] == "inbox_pending" and p["call_id"] == "c1" and p["tool"] == "write_file"
        assert p["args"] == {"path": "a.txt"} and p["alerts"] == [] and p["session_id"] == "e2e"
        ui.send_json({"event": "inbox_decision", "call_id": "c1", "decision": "approve"})
        assert proxy.receive_json() == {"event": "proxy_decision", "call_id": "c1", "decision": "approve",
                                        "reason": "human"}
        assert ui.receive_json()["event"] == "inbox_resolved"
        proxy.send_json({"event": "proxy_result", "call_id": "c1", "status": "ok", "summary": "wrote\n1 file"})
        r = ui.receive_json()
        assert r == {"event": "inbox_result", "session_id": "e2e", "call_id": "c1", "status": "ok",
                     "summary": "wrote 1 file"}


def test_deny_flow_and_forged_decisions(client):
    with client.websocket_connect("/inbox/ws") as ui, client.websocket_connect("/proxy/ws") as proxy:
        open_pair(client, ui, proxy)
        proxy.send_json(call())
        assert ui.receive_json()["event"] == "inbox_pending"
        ui.send_json({"event": "inbox_decision", "call_id": "c1", "decision": "APPROVE"})   # ignored
        ui.send_json("not an object")
        ui.send_json({"event": "inbox_decision", "call_id": "c1", "decision": "deny"})
        d = proxy.receive_json()
        assert d == {"event": "proxy_decision", "call_id": "c1", "decision": "deny", "reason": "human"}
        res = ui.receive_json()
        assert res["event"] == "inbox_resolved" and res["decision"] == "deny"


def test_timeout_denies(client, monkeypatch):
    monkeypatch.setattr(main, "inbox_hub", InboxHub(gate_timeout=0.1))
    with client.websocket_connect("/proxy/ws") as proxy:     # no UI at all
        proxy.send_json(HELLO)
        assert proxy.receive_json()["event"] == "hello_ack"
        proxy.send_json(call())
        assert proxy.receive_json() == {"event": "proxy_decision", "call_id": "c1", "decision": "deny",
                                        "reason": "timeout"}


def test_auto_approve_without_alert_with_rules_monitor(client):
    with client.websocket_connect("/inbox/ws") as ui, client.websocket_connect("/proxy/ws") as proxy:
        open_pair(client, ui, proxy)
        proxy.send_json(call(tool="read_file", auto=True))
        assert proxy.receive_json() == {"event": "proxy_decision", "call_id": "c1", "decision": "approve",
                                        "reason": "auto"}
        assert ui.receive_json()["reason"] == "auto"


def test_proxy_disconnect_resolves_pending_for_ui(client):
    with client.websocket_connect("/inbox/ws") as ui:
        assert ui.receive_json()["event"] == "inbox_snapshot"
        with client.websocket_connect("/proxy/ws") as proxy:
            proxy.send_json(HELLO)
            proxy.receive_json()
            assert ui.receive_json()["state"] == "open"
            proxy.send_json(call())
            assert ui.receive_json()["event"] == "inbox_pending"
        r = ui.receive_json()
        assert (r["event"], r["decision"], r["reason"]) == ("inbox_resolved", "deny", "disconnected")
        assert ui.receive_json()["state"] == "closed"


def test_snapshot_for_late_ui(client):
    with client.websocket_connect("/proxy/ws") as proxy:
        proxy.send_json(HELLO)
        proxy.receive_json()
        proxy.send_json(call())
        with client.websocket_connect("/inbox/ws") as ui:
            # the pending broadcast may race with the connect: either way the call is visible exactly once at start
            snap = ui.receive_json()
            if snap["sessions"] and snap["sessions"][0]["pending"]:
                assert snap["sessions"][0]["pending"][0]["call_id"] == "c1"
                ui.send_json({"event": "inbox_decision", "call_id": "c1", "decision": "deny"})
                assert proxy.receive_json()["decision"] == "deny"


def test_first_frame_must_be_hello(client):
    with client.websocket_connect("/proxy/ws") as proxy:
        proxy.send_json(call())
        assert proxy.receive_json() == {"event": "hello_reject", "reason": "bad_hello"}
        with pytest.raises(WebSocketDisconnect):
            proxy.receive_json()


def test_duplicate_session_id_over_the_wire(client):
    with client.websocket_connect("/proxy/ws") as a:
        a.send_json(HELLO)
        assert a.receive_json()["event"] == "hello_ack"
        with client.websocket_connect("/proxy/ws") as b:
            b.send_json(HELLO)
            assert b.receive_json() == {"event": "hello_reject", "reason": "duplicate_session_id"}


def test_garbage_does_not_crash_hub(client):
    with client.websocket_connect("/proxy/ws") as proxy:
        proxy.send_text("{not json")
        assert proxy.receive_json() == {"event": "hello_reject", "reason": "bad_hello"}
        with pytest.raises(WebSocketDisconnect):
            proxy.receive_json()
    with client.websocket_connect("/proxy/ws") as proxy:
        proxy.send_json(HELLO)
        proxy.receive_json()
        proxy.send_json({"event": "mystery"})                 # ignored
        proxy.send_json(call(tool="read_file", auto=True))
        assert proxy.receive_json()["decision"] == "approve"  # still alive
        proxy.send_text("x" * 1_100_000)                       # oversize: closes the proxy
        with pytest.raises(WebSocketDisconnect):
            proxy.receive_json()
    with client.websocket_connect("/inbox/ws") as ui:
        assert ui.receive_json()["event"] == "inbox_snapshot"
        ui.send_text("{bad")
        ui.send_text("x" * 1_100_000)
        ui.send_json({"event": "weird"})
        ui.send_json({"event": "inbox_decision", "call_id": "none", "decision": "approve"})
    with client.websocket_connect("/inbox/ws") as ui:          # hub still serves
        assert ui.receive_json()["event"] == "inbox_snapshot"
