"""Tests for server/policy_cli.py (ticket PE2) and docs/examples/policy.example.json."""
import json
import os
import subprocess
import sys

import pytest

import policy as P
import policy_cli as C

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SERVER_DIR = os.path.join(ROOT, "server")
EXAMPLE = os.path.join(ROOT, "docs", "examples", "policy.example.json")
TRACES = os.path.join(ROOT, "eval", "final_v3", "traces.json")

POLICY = {"version": 1, "default": "ask", "rules": [
    {"id": "read-project", "verdict": "allow", "note": "reads are routine",
     "when": {"tool": "read_*", "args": [{"path": "path", "op": "under", "value": "/project"}]}},
    {"id": "no-write-outside", "verdict": "deny", "when": {"tool": "write_*", "args": [{"path": "path", "op": "not_under", "value": "/project"}]}},
    {"id": "ext", "verdict": "ask", "when": {"destination": "external"}},
]}


def run(*argv, cwd=SERVER_DIR):
    env = dict(os.environ, PYTHONPATH=SERVER_DIR)
    return subprocess.run([sys.executable, "-m", "policy_cli", *argv], capture_output=True, text=True, env=env, cwd=cwd)


@pytest.fixture
def pfile(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(json.dumps(POLICY))
    return str(f)


def write(tmp_path, name, data):
    f = tmp_path / name
    f.write_text(data if isinstance(data, str) else json.dumps(data))
    return str(f)


def proposal(tool, args, label):
    return {"tool": tool, "args": args, "decision": "approve", "label": label}


def traces_file(tmp_path, proposals):
    steps = [{"i": i, "proposal": p} for i, p in enumerate(proposals)]
    steps.append({"i": len(steps), "proposal": None})
    return write(tmp_path, "traces.json", [{"id": "t1", "steps": steps}])


# ---------------------------------------------------------------------------
# lint
# ---------------------------------------------------------------------------

class TestLint:
    def test_ok(self, pfile, capsys):
        assert C.main(["lint", pfile]) == 0
        out = capsys.readouterr().out
        assert "OK: 3 rules" in out and P.load_policy(pfile).digest() in out

    def test_warnings_still_exit_zero(self, tmp_path, capsys):
        f = write(tmp_path, "w.json", {"version": 1, "default": "allow", "rules": []})
        assert C.main(["lint", f]) == 0
        out = capsys.readouterr().out
        assert "WARN:" in out and "default" in out and "1 warning" in out

    def test_errors_exit_one_and_list_all(self, tmp_path, capsys):
        f = write(tmp_path, "bad.json", {"version": 2, "bogus": 1, "rules": [{"id": "a", "verdict": "x"}]})
        assert C.main(["lint", f]) == 1
        out = capsys.readouterr().out
        assert out.count("ERROR:") == 3 and "FAILED: 3 error(s)" in out

    def test_valid_json_wrong_shape_is_exit_one(self, tmp_path):
        assert C.main(["lint", write(tmp_path, "l.json", "[1]")]) == 1

    @pytest.mark.parametrize("content", ["not json", "", "{", b"\xff\xfe"])
    def test_unparseable_is_exit_two(self, tmp_path, content, capsys):
        f = tmp_path / "x.json"
        f.write_bytes(content if isinstance(content, bytes) else content.encode())
        assert C.main(["lint", str(f)]) == 2
        assert "ERROR:" in capsys.readouterr().err

    def test_missing_and_directory_exit_two(self, tmp_path, capsys):
        assert C.main(["lint", str(tmp_path / "nope.json")]) == 2
        assert C.main(["lint", str(tmp_path)]) == 2
        assert "Traceback" not in capsys.readouterr().err

    def test_subprocess_exit_codes_and_no_traceback(self, pfile, tmp_path):
        r = run("lint", pfile)
        assert r.returncode == 0 and r.stdout.startswith("OK:")
        bad = write(tmp_path, "bad.json", {"version": 3})
        r = run("lint", bad)
        assert r.returncode == 1 and "Traceback" not in r.stderr
        r = run("lint", str(tmp_path / "missing.json"))
        assert r.returncode == 2 and "Traceback" not in r.stderr

    def test_bad_cli_usage_exit_two(self):
        for argv in ([], ["lint"], ["bogus"], ["explain", "p.json"], ["test", "p.json"]):
            r = run(*argv)
            assert r.returncode == 2 and "Traceback" not in r.stderr, argv


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------

class TestExplain:
    def test_allow(self, pfile, capsys):
        assert C.main(["explain", pfile, "--tool", "read_file", "--args", '{"path": "/project/a"}']) == 0
        out = capsys.readouterr().out
        assert "verdict: allow" in out and "rule:    read-project" in out and "reads are routine" in out

    def test_deny_lists_every_matched_rule(self, pfile, capsys):
        reg = {"version": 1, "defaults": {"unknown": "external"}, "entries": []}
        out = run_explain(capsys, pfile, "--tool", "write_file", "--args", '{"path": "/etc/x", "to": "a@zzz.example"}')
        assert "verdict: deny" in out
        assert "*no-write-outside [deny]" in out and "ext [ask]" in out

    def test_default(self, pfile, capsys):
        out = run_explain(capsys, pfile, "--tool", "mystery")
        assert "verdict: ask" in out and "rule:    (none)" in out and "reason:  default" in out and "(no rule)" in out

    def test_alert_flag_escalates(self, pfile, capsys):
        out = run_explain(capsys, pfile, "--tool", "read_file", "--args", '{"path": "/project/a"}', "--alert")
        assert "verdict: ask" in out and "escalated: yes" in out and "reason:  alert" in out

    def test_alert_does_not_change_deny(self, pfile, capsys):
        out = run_explain(capsys, pfile, "--tool", "write_file", "--args", '{"path": "/etc/x"}', "--alert")
        assert "verdict: deny" in out and "escalated: no" in out

    def test_server_matters(self, tmp_path, capsys):
        f = write(tmp_path, "p.json", {"version": 1, "rules": [{"id": "a", "verdict": "allow", "when": {"server": "fs"}}]})
        assert "verdict: allow" in run_explain(capsys, f, "--tool", "t", "--server", "fs")
        assert "verdict: ask" in run_explain(capsys, f, "--tool", "t", "--server", "db")
        assert "verdict: ask" in run_explain(capsys, f, "--tool", "t")

    def test_registry_option(self, tmp_path, capsys):
        p = write(tmp_path, "p.json", {"version": 1, "rules": [{"id": "r", "verdict": "deny", "when": {"destination": "relay"}}]})
        reg = write(tmp_path, "reg.json", {"version": 1, "defaults": {"internal_domains": ["team.com"]}, "entries": [
            {"id": "r_alias", "kind": "relay", "party": "acme", "match": {"email": "partners@team.com"}}]})
        a = '{"to": "partners@team.com"}'
        assert "verdict: deny" in run_explain(capsys, p, "--tool", "send_email", "--args", a, "--registry", reg)
        assert "verdict: ask" in run_explain(capsys, p, "--tool", "send_email", "--args", a)        # default registry

    def test_bad_args_json_exit_two(self, pfile, capsys):
        assert C.main(["explain", pfile, "--tool", "t", "--args", "{nope"]) == 2
        assert "--args" in capsys.readouterr().err

    def test_non_object_args_do_not_crash(self, pfile, capsys):
        for a in ("[1]", "5", "null", '"str"'):
            assert C.main(["explain", pfile, "--tool", "write_file", "--args", a]) == 0
            assert "verdict: deny" in capsys.readouterr().out          # no path: not_under is true on unknowns

    def test_missing_registry_exit_two(self, pfile, tmp_path, capsys):
        assert C.main(["explain", pfile, "--tool", "t", "--registry", str(tmp_path / "nope.json")]) == 2
        bad = write(tmp_path, "r.json", "junk")
        assert C.main(["explain", pfile, "--tool", "t", "--registry", bad]) == 2

    def test_bad_policy_codes(self, tmp_path):
        assert C.main(["explain", str(tmp_path / "nope.json"), "--tool", "t"]) == 2
        assert C.main(["explain", write(tmp_path, "b.json", {"version": 7}), "--tool", "t"]) == 1

    def test_subprocess(self, pfile):
        r = run("explain", pfile, "--tool", "read_file", "--args", '{"path": "/project/../etc/passwd"}')
        assert r.returncode == 0 and "verdict: ask" in r.stdout


def run_explain(capsys, *argv):
    assert C.main(["explain", *argv]) == 0
    return capsys.readouterr().out


# ---------------------------------------------------------------------------
# test (replay)
# ---------------------------------------------------------------------------

class TestReplay:
    PROPS = [
        proposal("read_file", {"path": "/project/a"}, "ok"),             # allow
        proposal("read_file", {"path": "/etc/passwd"}, "violation"),     # ask (default)
        proposal("write_file", {"path": "/etc/x"}, "violation"),         # deny
        proposal("read_file", {"path": "/project/b"}, "violation"),      # allow  -> violating allowed
        proposal("list_directory", {"path": "/project"}, "ok"),          # ask    -> benign asked
        proposal("send_email", {"to": "x@outside.example"}, "denied_seed"),   # ask (ext)
    ]

    def test_json_counts(self, pfile, tmp_path, capsys):
        t = traces_file(tmp_path, self.PROPS)
        assert C.main(["test", pfile, "--traces", t, "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["proposals"] == 6                                   # null proposals are not counted
        assert out["verdicts"] == {"allow": 2, "deny": 1, "ask": 3}
        assert out["by_label"] == {"denied_seed": {"allow": 0, "deny": 0, "ask": 1},
                                   "ok": {"allow": 1, "deny": 0, "ask": 1},
                                   "violation": {"allow": 1, "deny": 1, "ask": 1}}
        assert out["rule_hits"] == {"read-project": 2, "(default)": 2, "ext": 1, "no-write-outside": 1}
        assert out["violating_allowed"] == 1
        assert out["benign_asked"] == 1
        assert out["policy_digest"] == P.load_policy(pfile).digest()

    def test_text_output(self, pfile, tmp_path, capsys):
        t = traces_file(tmp_path, self.PROPS)
        assert C.main(["test", pfile, "--traces", t]) == 0
        out = capsys.readouterr().out
        assert "6 proposals" in out and "overall: allow 2  deny 1  ask 3" in out
        assert "violating proposals the policy would ALLOW: 1" in out
        assert "benign proposals the policy would ASK: 1" in out
        assert "read-project" in out and "(default)" in out and "violation" in out

    def test_perfectly_safe_policy_reports_zero(self, tmp_path, capsys):
        p = write(tmp_path, "p.json", {"version": 1, "default": "deny", "rules": []})
        t = traces_file(tmp_path, self.PROPS)
        C.main(["test", p, "--traces", t, "--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["violating_allowed"] == 0 and out["benign_asked"] == 0 and out["verdicts"]["deny"] == 6

    def test_allow_everything_policy(self, tmp_path, capsys):
        p = write(tmp_path, "p.json", {"version": 1, "default": "allow", "rules": []})
        t = traces_file(tmp_path, self.PROPS)
        C.main(["test", p, "--traces", t, "--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["violating_allowed"] == 4 and out["verdicts"]["allow"] == 6      # 3 violation + 1 denied_seed

    def test_alerts_are_assumed_absent(self, tmp_path, capsys):
        p = write(tmp_path, "p.json", {"version": 1, "rules": [{"id": "x", "verdict": "allow"},
                                                               {"id": "al", "verdict": "deny", "when": {"alert": True}}]})
        t = traces_file(tmp_path, [proposal("read_file", {}, "ok")])
        C.main(["test", p, "--traces", t, "--json"])
        assert json.loads(capsys.readouterr().out)["verdicts"] == {"allow": 1, "deny": 0, "ask": 0}

    def test_server_option(self, tmp_path, capsys):
        p = write(tmp_path, "p.json", {"version": 1, "rules": [{"id": "x", "verdict": "allow", "when": {"server": "fs"}}]})
        t = traces_file(tmp_path, [proposal("t", {}, "ok")])
        C.main(["test", p, "--traces", t, "--json"])
        assert json.loads(capsys.readouterr().out)["verdicts"]["allow"] == 0
        C.main(["test", p, "--traces", t, "--server", "fs", "--json"])
        assert json.loads(capsys.readouterr().out)["verdicts"]["allow"] == 1

    def test_registry_option(self, tmp_path, capsys):
        p = write(tmp_path, "p.json", {"version": 1, "default": "allow",
                                       "rules": [{"id": "r", "verdict": "deny", "when": {"destination": "relay"}}]})
        reg = write(tmp_path, "reg.json", {"version": 1, "entries": [
            {"id": "r_alias", "kind": "relay", "party": "acme", "match": {"email": "partners@team.com"}}]})
        t = traces_file(tmp_path, [proposal("send_email", {"to": "partners@team.com"}, "violation")])
        C.main(["test", p, "--traces", t, "--json"])
        assert json.loads(capsys.readouterr().out)["violating_allowed"] == 1
        C.main(["test", p, "--traces", t, "--registry", reg, "--json"])
        assert json.loads(capsys.readouterr().out)["violating_allowed"] == 0

    def test_odd_proposals_do_not_crash(self, pfile, tmp_path, capsys):
        props = [{"tool": None, "args": None, "label": None}, {}, {"tool": 5, "args": [1], "label": 7},
                 {"tool": "write_file", "args": {"path": "/etc/x"}}]
        t = traces_file(tmp_path, props)
        assert C.main(["test", pfile, "--traces", t, "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["proposals"] == 4 and sum(out["verdicts"].values()) == 4
        assert out["by_label"]["unlabeled"]["deny"] == 4      # unevaluable tool names are caught by the deny rule

    def test_empty_traces(self, pfile, tmp_path, capsys):
        assert C.main(["test", pfile, "--traces", write(tmp_path, "e.json", [])]) == 0
        assert "0 proposals" in capsys.readouterr().out

    @pytest.mark.parametrize("content", ["junk", "{}", '{"steps": []}', '[1]', '[{"steps": 3}]', '[{"steps": [5]}]',
                                         '[{"steps": [{"proposal": 5}]}]', '[{"id": 1}]', ""])
    def test_bad_traces_exit_two(self, pfile, tmp_path, content, capsys):
        assert C.main(["test", pfile, "--traces", write(tmp_path, "t.json", content)]) == 2
        assert "ERROR:" in capsys.readouterr().err

    def test_missing_traces_and_policy(self, pfile, tmp_path):
        assert C.main(["test", pfile, "--traces", str(tmp_path / "nope.json")]) == 2
        t = traces_file(tmp_path, [])
        assert C.main(["test", str(tmp_path / "nope.json"), "--traces", t]) == 2
        assert C.main(["test", write(tmp_path, "b.json", {"version": 4}), "--traces", t]) == 1

    def test_subprocess_json(self, pfile, tmp_path):
        r = run("test", pfile, "--traces", traces_file(tmp_path, self.PROPS), "--json")
        assert r.returncode == 0 and json.loads(r.stdout)["proposals"] == 6


# ---------------------------------------------------------------------------
# example policy + the real eval traces
# ---------------------------------------------------------------------------

class TestExampleAndTraces:
    def test_example_lints_clean(self, capsys):
        assert C.main(["lint", EXAMPLE]) == 0
        out = capsys.readouterr().out
        assert "WARN" not in out and "OK:" in out

    def test_example_shape(self):
        pol = P.load_policy(EXAMPLE)
        assert 6 <= len(pol.rules) <= 8
        assert pol.lint() == []
        ops = {c.op for r in pol.rules for c in r.args}
        assert {"under", "not_under"} <= ops
        assert any(r.destination for r in pol.rules) and any(r.alert for r in pol.rules) and any(r.party for r in pol.rules)
        assert {r.verdict for r in pol.rules} == {"allow", "deny", "ask"}

    def test_example_sanity_decisions(self):
        pol = P.load_policy(EXAMPLE)
        assert pol.evaluate("", "read_file", {"path": "/project/a.txt"}).verdict == "allow"
        assert pol.evaluate("", "read_file", {"path": "/project/../etc/passwd"}).verdict == "ask"
        assert pol.evaluate("", "write_file", {"path": "/etc/cron.d/x", "content": "x"}).verdict == "deny"
        assert pol.evaluate("", "send_email", {"to": "someone@outside-company.example"}).verdict == "ask"
        assert pol.evaluate("", "read_file", {"path": "/project/a.txt"}, alerts_present=True).verdict == "ask"

    @pytest.mark.skipif(not os.path.exists(TRACES), reason="eval/final_v3/traces.json not present")
    def test_replay_final_v3_counts_add_up(self, capsys):
        traces = json.load(open(TRACES))
        n = sum(1 for t in traces for s in t["steps"] if s.get("proposal"))
        assert n > 100
        assert C.main(["test", EXAMPLE, "--traces", TRACES, "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["proposals"] == n
        assert sum(out["verdicts"].values()) == n
        assert sum(sum(c.values()) for c in out["by_label"].values()) == n
        assert sum(out["rule_hits"].values()) == n
        assert set(out["by_label"]) <= {"ok", "violation", "denied_seed"}
        assert 0 <= out["violating_allowed"] <= out["by_label"]["violation"]["allow"] + out["by_label"]["denied_seed"]["allow"]
        assert out["benign_asked"] == out["by_label"]["ok"]["ask"]
        # a real policy decides something of every class on real data
        assert all(out["verdicts"][v] > 0 for v in ("allow", "deny", "ask"))
        assert set(out["rule_hits"]) <= {r.id for r in P.load_policy(EXAMPLE).rules} | {"(default)"}

    @pytest.mark.skipif(not os.path.exists(TRACES), reason="eval/final_v3/traces.json not present")
    def test_replay_text_headline_numbers(self):
        r = run("test", EXAMPLE, "--traces", TRACES)
        assert r.returncode == 0
        assert "violating proposals the policy would ALLOW:" in r.stdout
        assert "benign proposals the policy would ASK:" in r.stdout

    @pytest.mark.skipif(not os.path.exists(TRACES), reason="eval/final_v3/traces.json not present")
    def test_deny_all_policy_has_zero_violations_allowed(self, tmp_path, capsys):
        p = write(tmp_path, "p.json", {"version": 1, "default": "deny", "rules": []})
        C.main(["test", p, "--traces", TRACES, "--json"])
        out = json.loads(capsys.readouterr().out)
        assert out["violating_allowed"] == 0 and out["verdicts"]["deny"] == out["proposals"]
