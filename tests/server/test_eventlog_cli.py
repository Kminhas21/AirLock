"""Tests for server/eventlog_cli.py (ticket EL2)."""
import json
import os
import sqlite3
import subprocess
import sys

import pytest

import eventlog as EL
import eventlog_cli as C
from eventlog import EventStore

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SERVER_DIR = os.path.join(ROOT, "server")
EXAMPLE = os.path.join(ROOT, "docs", "examples", "policy.example.json")
KEY = "cli-test-key-0123456789"


class Clock:
    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self):
        self.t += 1.5
        return self.t


def run(*argv, env=None):
    e = dict(os.environ, PYTHONPATH=SERVER_DIR)
    e.pop("SENTINEL_LOG_KEY", None)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "eventlog_cli", *argv], capture_output=True, text=True, env=e, cwd=SERVER_DIR)


def dec(d, reason="human", actor="human", rule_id=None):
    return {"decision": d, "reason": reason, "actor": actor, "rule_id": rule_id, "policy_digest": None}


def build(tmp_path, key=None, name="e.db"):
    path = str(tmp_path / name)
    s = EventStore(path, key=key.encode() if key else None, clock=Clock(), checkpoint_every=5)
    s.open()
    s.append("proxy_hello", session_id="s1", payload={"servers": ["fs"], "auto_approve": False, "monitor_mode": "x", "policy_digest": None})
    calls = [
        ("c0", "read_file", {"path": "/project/a.txt"}, "approve", "human", []),                       # policy allows
        ("c1", "read_file", {"path": "/etc/passwd"}, "deny", "human", []),                             # policy asks
        ("c2", "write_file", {"path": "/etc/cron", "content": "x"}, "deny", "human", []),              # policy denies
        ("c3", "write_file", {"path": "/project/ok.txt", "content": "hi"}, "approve", "human", []),    # policy allows
        ("c4", "write_file", {"path": "/project/outbox/x", "content": "hi"}, "deny", "human", []),     # policy asks (outbox)
        ("c5", "read_file", {"path": "/project/b", "password": "SECRET-PW"}, "approve", "policy", []),  # not human
        ("c6", "read_file", {"path": "/project/c"}, "deny", "human", [{"severity": "high", "trigger": "t", "score": 0.9,
                                                                         "threshold": 0.5, "message": "bad\x1b[31m!"}]),  # alert => ask
    ]
    for cid, tool, args, d, actor, alerts in calls:
        s.append("call_proposed", session_id="s1", call_id=cid, payload={"server": "fs", "tool": tool, "args": args, "auto": False,
                                                                       "alerts": alerts, "policy": {"verdict": "ask", "rule_id": "r", "digest": "d"}})
        s.append("decision", session_id="s1", call_id=cid, payload=dec(d, actor=actor))
        s.append("call_result", session_id="s1", call_id=cid, payload={"status": "ok", "summary": f"result of {cid}"})
    s.append("call_proposed", session_id="s2", call_id="x0", payload={"server": "db", "tool": "query_database", "args": {}, "alerts": []})
    s.append("proxy_close", session_id="s1", payload={"reason": "bye"})
    s.close()
    return path


def sql(path, stmt):
    c = sqlite3.connect(path, isolation_level=None)
    c.execute(stmt)
    c.close()


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

class TestVerify:
    def test_ok_unkeyed(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["verify", p]) == 0
        out = capsys.readouterr().out
        assert out.splitlines()[-1].startswith("OK:") and "unkeyed" in out and "NOT detectable" in out

    def test_ok_keyed_via_env(self, tmp_path, capsys, monkeypatch):
        p = build(tmp_path, KEY)
        monkeypatch.setenv("SENTINEL_LOG_KEY", KEY)
        assert C.main(["verify", p]) == 0
        assert "keyed" in capsys.readouterr().out

    def test_custom_key_env_name(self, tmp_path, capsys, monkeypatch):
        p = build(tmp_path, KEY)
        monkeypatch.setenv("MY_KEY", KEY)
        assert C.main(["verify", p, "--key-env", "MY_KEY"]) == 0
        monkeypatch.setenv("MY_KEY", "a-different-key-0123456789")
        assert C.main(["verify", p, "--key-env", "MY_KEY"]) == 1
        assert "MAC" in capsys.readouterr().out

    def test_bad_key_env_value_exit_two(self, tmp_path, capsys, monkeypatch):
        p = build(tmp_path)
        monkeypatch.setenv("SENTINEL_LOG_KEY", "short")
        assert C.main(["verify", p]) == 2
        assert "16" in capsys.readouterr().err

    def test_tamper_prints_first_bad_seq_and_every_problem(self, tmp_path, capsys):
        p = build(tmp_path)
        sql(p, "UPDATE events SET payload = '{\"server\":\"evil\"}' WHERE seq IN (4, 9)")
        assert C.main(["verify", p]) == 1
        out = capsys.readouterr().out
        assert "FIRST BAD SEQ: 4" in out and out.count("PROBLEM:") >= 2 and "seq 9" in out and "FAILED:" in out

    def test_truncated_tail_detected_via_anchor(self, tmp_path, capsys):
        p = build(tmp_path)
        c = sqlite3.connect(p, isolation_level=None)
        last = c.execute("SELECT hash FROM events WHERE seq = 3").fetchone()[0]
        c.execute("DELETE FROM events WHERE seq > 3")
        c.execute("UPDATE head SET seq = 3, hash = ?", (last,))
        c.close()
        assert C.main(["verify", p]) == 1
        out = capsys.readouterr().out
        assert "truncated" in out and "anchor mismatch" in out

    def test_anchor_option(self, tmp_path, capsys):
        p = build(tmp_path)
        moved = str(tmp_path / "moved.anchor")
        os.rename(p + ".anchor", moved)
        assert C.main(["verify", p]) == 1
        assert C.main(["verify", p, "--anchor", moved]) == 0
        capsys.readouterr()

    def test_dropped_anchor(self, tmp_path, capsys):
        p = build(tmp_path)
        os.unlink(p + ".anchor")
        assert C.main(["verify", p]) == 1
        assert "removed" in capsys.readouterr().out

    def test_unreadable_exit_two(self, tmp_path, capsys):
        assert C.main(["verify", str(tmp_path / "nope.db")]) == 2
        assert not (tmp_path / "nope.db").exists()
        g = tmp_path / "garbage.db"
        g.write_bytes(os.urandom(3000))
        assert C.main(["verify", str(g)]) == 2
        e = tmp_path / "empty.db"
        e.write_bytes(b"")
        assert C.main(["verify", str(e)]) == 2
        f = tmp_path / "foreign.db"
        sqlite3.connect(str(f)).execute("CREATE TABLE t(x)").connection.close()
        assert C.main(["verify", str(f)]) == 2
        assert C.main(["verify", str(tmp_path)]) == 2
        assert "Traceback" not in capsys.readouterr().err

    def test_verify_is_read_only(self, tmp_path):
        p = build(tmp_path)
        before = (open(p, "rb").read(), open(p + ".anchor", "rb").read())
        n = sqlite3.connect(p).execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert C.main(["verify", p]) == 0
        # (a read-only WAL reader may create the -shm/-wal side files; the database and anchor bytes never change)
        assert (open(p, "rb").read(), open(p + ".anchor", "rb").read()) == before
        assert sqlite3.connect(p).execute("SELECT COUNT(*) FROM events").fetchone()[0] == n

    def test_output_is_terminal_safe(self, tmp_path, capsys):
        p = build(tmp_path)
        sql(p, "UPDATE events SET kind = 'evil\x1b[2J‮kind' WHERE seq = 4")
        assert C.main(["verify", p]) == 1
        out = capsys.readouterr().out
        assert "\x1b" not in out and "\u202e" not in out and ("\\x1b" in out or "\\u001b" in out)

    def test_subprocess_exit_codes(self, tmp_path):
        p = build(tmp_path, KEY)
        r = run("verify", p, env={"SENTINEL_LOG_KEY": KEY})
        assert r.returncode == 0 and r.stdout.strip().endswith("keyed")
        r = run("verify", p, env={"SENTINEL_LOG_KEY": "another-key-0123456789"})
        assert r.returncode == 1 and "Traceback" not in r.stderr
        r = run("verify", str(tmp_path / "missing.db"))
        assert r.returncode == 2 and "Traceback" not in r.stderr

    def test_usage_errors_exit_two(self):
        for argv in ([], ["verify"], ["bogus"], ["show", "x.db"], ["export", "x.db"], ["policy-test", "x.db"]):
            r = run(*argv)
            assert r.returncode == 2 and "Traceback" not in r.stderr, argv


# ---------------------------------------------------------------------------
# show / export
# ---------------------------------------------------------------------------

class TestShowExport:
    def test_show_timeline(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["show", p, "--session", "s1"]) == 0
        out = capsys.readouterr().out
        lines = out.splitlines()
        assert "SESSION START" in lines[0] and "SESSION END" in lines[-1]
        i_prop = next(i for i, ln in enumerate(lines) if "PROPOSED call c6" in ln)
        assert "alert: high t" in lines[i_prop + 1] and "policy: ask" in lines[i_prop + 2]
        assert "DECISION call c6: DENY (reason human, by human)" in lines[i_prop + 3]
        assert "RESULT call c6: ok result of c6" in lines[i_prop + 4]
        assert "2023-11-14" in lines[0]                                # readable UTC time
        assert "SECRET-PW" not in out and "[REDACTED]" in out
        assert "x0" not in out                                         # other session
        assert "\x1b" not in out

    def test_show_single_call(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["show", p, "--session", "s1", "--call", "c2"]) == 0
        out = capsys.readouterr().out
        assert out.count("PROPOSED") == 1 and "c2" in out and "c3" not in out and "SESSION" not in out

    def test_show_nothing_found_exit_one(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["show", p, "--session", "nope"]) == 1
        assert C.main(["show", p, "--session", "s1", "--call", "nope"]) == 1
        assert "no events" in capsys.readouterr().err

    def test_show_unreadable(self, tmp_path):
        assert C.main(["show", str(tmp_path / "nope.db"), "--session", "s"]) == 2

    def test_show_warns_on_tampered_log_but_still_shows(self, tmp_path, capsys):
        p = build(tmp_path)
        sql(p, "UPDATE events SET payload = '{\"decision\":\"approve\"}' WHERE seq = 5")
        assert C.main(["show", p, "--session", "s1"]) == 0
        cap = capsys.readouterr()
        assert "WARNING" in cap.err and "does not verify" in cap.err and "PROPOSED" in cap.out

    def test_show_escapes_hostile_strings(self, tmp_path, capsys):
        path = str(tmp_path / "h.db")
        s = EventStore(path)
        s.open()
        s.append("call_proposed", session_id="s", call_id="c\x1b[1m", payload={"server": "a\nb", "tool": "‮tool", "args": {"k": "v\x07"}})
        s.close()
        assert C.main(["show", path, "--session", "s"]) == 0
        out = capsys.readouterr().out
        assert "\x1b" not in out and "\x07" not in out and "‮" not in out and len(out.splitlines()) == 1

    def test_export_jsonl(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["export", p, "--jsonl"]) == 0
        lines = capsys.readouterr().out.splitlines()
        objs = [json.loads(ln) for ln in lines]
        db = [(r[0], r[1]) for r in sqlite3.connect(p).execute("SELECT seq, kind FROM events ORDER BY seq")]
        assert [(o["seq"], o["kind"]) for o in objs] == db
        assert set(objs[0]) == {"seq", "ts", "session_id", "call_id", "kind", "payload", "prev_hash", "hash"}
        assert objs[0]["prev_hash"] == "0" * 64 and objs[1]["prev_hash"] == objs[0]["hash"]
        assert "SECRET-PW" not in "".join(lines)

    def test_export_session_filter(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["export", p, "--jsonl", "--session", "s2"]) == 0
        objs = [json.loads(ln) for ln in capsys.readouterr().out.splitlines()]
        assert len(objs) == 1 and objs[0]["call_id"] == "x0"
        assert C.main(["export", p, "--jsonl", "--session", "none"]) == 0
        assert capsys.readouterr().out == ""

    def test_export_requires_jsonl_and_readable(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["export", p]) == 2
        assert C.main(["export", str(tmp_path / "nope.db"), "--jsonl"]) == 2
        capsys.readouterr()

    def test_export_is_one_line_per_event_even_with_hostile_text(self, tmp_path):
        path = str(tmp_path / "h.db")
        s = EventStore(path)
        s.open()
        s.append("proxy_hello", session_id="a\nb c", payload={"x": "l1\nl2\r\n "})
        s.close()
        r = run("export", path, "--jsonl")
        assert r.returncode == 0
        assert len(r.stdout.split("\n")) == 4          # log_open, proxy_hello, checkpoint + trailing newline: no embedded breaks
        objs = [json.loads(ln) for ln in r.stdout.split("\n") if ln]
        assert objs[1]["session_id"] == "a\nb c"

    def test_commands_do_not_modify_the_log(self, tmp_path, capsys):
        p = build(tmp_path)
        before = open(p, "rb").read()
        C.main(["show", p, "--session", "s1"])
        C.main(["export", p, "--jsonl"])
        C.main(["policy-test", p, EXAMPLE])
        capsys.readouterr()
        assert open(p, "rb").read() == before


# ---------------------------------------------------------------------------
# policy-test
# ---------------------------------------------------------------------------

class TestPolicyTest:
    def test_json_counts_and_comparison(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["policy-test", p, EXAMPLE, "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["proposals"] == 8
        assert sum(out["verdicts"].values()) == 8
        # c0 allow, c1 ask, c2 deny, c3 allow, c4 ask (outbox), c5 allow (read-project), c6 alert -> ask, x0 query_database -> ask
        assert out["verdicts"] == {"allow": 3, "deny": 1, "ask": 4}
        assert out["by_label"]["ok"] == {"allow": 2, "deny": 0, "ask": 0}                  # c0, c3 (human approved)
        assert out["by_label"]["violation"] == {"allow": 0, "deny": 1, "ask": 3}           # c1, c2, c4, c6 (human denied)
        assert out["by_label"]["unlabeled"] == {"allow": 1, "deny": 0, "ask": 1}           # c5 (policy decided), x0 (pending)
        assert out["violating_allowed"] == 0 and out["benign_asked"] == 0
        assert out["comparison"] == {"human_decided": 6, "agree": 3, "policy_would_allow_a_denied_call": 0,
                                     "policy_would_deny_an_approved_call": 0, "policy_would_ask": 3, "not_human_decided": 2}
        assert out["rule_hits"]["allow-read-project"] == 2
        assert sum(out["rule_hits"].values()) == 8

    def test_logged_alerts_are_used(self, tmp_path, capsys):
        p = build(tmp_path)
        C.main(["policy-test", p, EXAMPLE, "--json", "--session", "s1"])
        with_alerts = json.loads(capsys.readouterr().out)
        # c6 reads /project/c: only the logged alert keeps it from being allowed
        assert with_alerts["by_label"]["violation"]["allow"] == 0

    def test_would_auto_allow_a_denied_call(self, tmp_path, capsys):
        permissive = tmp_path / "p.json"
        permissive.write_text(json.dumps({"version": 1, "default": "allow", "rules": [
            {"id": "deny-writes", "verdict": "deny", "when": {"tool": "write_*"}}]}))
        p = build(tmp_path)
        assert C.main(["policy-test", p, str(permissive), "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        # human-denied reads c1 and (c6 has an alert => escalated to ask) -> c1 would be auto-allowed
        assert out["violating_allowed"] == 1
        assert out["comparison"]["policy_would_allow_a_denied_call"] == 1
        assert out["comparison"]["policy_would_deny_an_approved_call"] == 1               # c3 write approved by the human
        assert out["would_allow_denied"] == [{"session_id": "s1", "call_id": "c1", "tool": "read_file", "rule_id": None}]

    def test_text_output(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["policy-test", p, EXAMPLE]) == 0
        out = capsys.readouterr().out
        assert "8 logged proposals" in out and "overall: allow 3  deny 1  ask 4" in out
        assert "violating proposals the policy would ALLOW: 0" in out
        assert "benign proposals the policy would ASK: 0" in out
        assert "policy would auto-allow a call the human DENIED: 0" in out
        assert "agreement" in out and "rule hits:" in out and "redacted" in out

    def test_text_output_lists_risky_calls(self, tmp_path, capsys):
        permissive = tmp_path / "p.json"
        permissive.write_text(json.dumps({"version": 1, "default": "allow", "rules": []}))
        p = build(tmp_path)
        C.main(["policy-test", p, str(permissive)])
        out = capsys.readouterr().out
        assert "! session s1 call c1 tool read_file allowed by (default)" in out

    def test_session_filter(self, tmp_path, capsys):
        p = build(tmp_path)
        C.main(["policy-test", p, EXAMPLE, "--session", "s2", "--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["proposals"] == 1 and out["comparison"]["human_decided"] == 0

    def test_registry_option(self, tmp_path, capsys):
        path = str(tmp_path / "r.db")
        s = EventStore(path)
        s.open()
        s.append("call_proposed", session_id="s", call_id="c", payload={"server": "mail", "tool": "send_email",
                                                                      "args": {"to": "partners@team.com"}, "alerts": []})
        s.append("decision", session_id="s", call_id="c", payload=dec("deny"))
        s.close()
        pol = tmp_path / "p.json"
        pol.write_text(json.dumps({"version": 1, "default": "allow", "rules": [{"id": "r", "verdict": "deny", "when": {"destination": "relay"}}]}))
        reg = tmp_path / "reg.json"
        reg.write_text(json.dumps({"version": 1, "defaults": {"internal_domains": ["team.com"]}, "entries": [
            {"id": "r_alias", "kind": "relay", "party": "acme", "match": {"email": "partners@team.com"}}]}))
        C.main(["policy-test", path, str(pol), "--json"])
        assert json.loads(capsys.readouterr().out)["violating_allowed"] == 1              # default registry: plain internal
        C.main(["policy-test", path, str(pol), "--registry", str(reg), "--json"])
        assert json.loads(capsys.readouterr().out)["violating_allowed"] == 0

    def test_server_name_comes_from_the_log(self, tmp_path, capsys):
        path = str(tmp_path / "srv.db")
        s = EventStore(path)
        s.open()
        for sid, srv in (("a", "fs"), ("b", "db")):
            s.append("call_proposed", session_id=sid, call_id="c", payload={"server": srv, "tool": "t", "args": {}, "alerts": []})
        s.close()
        pol = tmp_path / "p.json"
        pol.write_text(json.dumps({"version": 1, "rules": [{"id": "r", "verdict": "allow", "when": {"server": "fs"}}]}))
        C.main(["policy-test", path, str(pol), "--json"])
        assert json.loads(capsys.readouterr().out)["verdicts"] == {"allow": 1, "deny": 0, "ask": 1}

    def test_odd_logged_payloads_do_not_crash(self, tmp_path, capsys):
        path = str(tmp_path / "odd.db")
        s = EventStore(path)
        s.open()
        for i, pl in enumerate([{}, {"server": 5, "tool": None, "args": "str"}, {"tool": ["x"], "args": [1]}, {"alerts": "yes"}]):
            s.append("call_proposed", session_id="s", call_id=f"c{i}", payload=pl)
        s.close()
        assert C.main(["policy-test", path, EXAMPLE, "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["proposals"] == 4 and sum(out["verdicts"].values()) == 4

    def test_exit_codes(self, tmp_path, capsys):
        p = build(tmp_path)
        assert C.main(["policy-test", p, str(tmp_path / "missing.json")]) == 2
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"version": 9}))
        assert C.main(["policy-test", p, str(bad)]) == 1
        assert C.main(["policy-test", str(tmp_path / "nope.db"), EXAMPLE]) == 2
        assert C.main(["policy-test", p, EXAMPLE, "--registry", str(tmp_path / "nope.json")]) == 2
        assert "Traceback" not in capsys.readouterr().err

    def test_empty_log(self, tmp_path, capsys):
        path = str(tmp_path / "empty.db")
        s = EventStore(path)
        s.open()
        s.close()
        assert C.main(["policy-test", path, EXAMPLE, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["proposals"] == 0

    def test_subprocess(self, tmp_path):
        p = build(tmp_path)
        r = run("policy-test", p, EXAMPLE, "--json")
        assert r.returncode == 0 and json.loads(r.stdout)["proposals"] == 8
