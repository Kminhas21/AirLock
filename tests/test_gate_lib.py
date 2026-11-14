"""scripts/gate_lib.sh: the gate reports each stage the moment it ends (GATE_EVENTS file, GATE_ON_FAIL hook), can stop at the first failure
(GATE_FAIL_FAST=1), and a preflight fails in seconds when an opted-in stage cannot possibly work (instead of after hours of other stages)."""
import os
import subprocess
from pathlib import Path

LIB = Path(__file__).resolve().parent.parent / "scripts" / "gate_lib.sh"


def sh(script: str, tmp_path: Path, **env):
    full = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), **env}
    return subprocess.run(["bash", "-c", f"set -u; fail=0; source '{LIB}'; {script}; echo \"fail=$fail\""],
                          capture_output=True, text=True, env=full, cwd=tmp_path, timeout=30)


def test_each_stage_writes_start_and_its_verdict_to_the_events_file_as_it_ends(tmp_path):
    ev = tmp_path / "events.log"
    r = sh("run 'good stage' true; run 'bad stage' false; run 'after' true", tmp_path, GATE_EVENTS=str(ev))
    lines = [l.split(" ", 1)[1] for l in ev.read_text().splitlines()]          # drop the timestamp
    assert [l.rsplit(" (", 1)[0] for l in lines] == ["START good stage", "PASS good stage", "START bad stage", "FAIL bad stage",
                                                     "START after", "PASS after"]
    assert "fail=1" in r.stdout and "--- FAIL: bad stage" in r.stdout and "--- PASS: after" in r.stdout


def test_on_fail_hook_runs_once_per_failed_stage_with_the_stage_name(tmp_path):
    out = tmp_path / "hook.txt"
    sh("run ok true; run 'stage two' false", tmp_path, GATE_ON_FAIL=f'echo "failed: $GATE_STAGE" >> {out}')
    assert out.read_text() == "failed: stage two\n"


def test_a_failing_hook_never_changes_the_verdict_or_stops_the_gate(tmp_path):
    r = sh("run a false; run b true", tmp_path, GATE_ON_FAIL="exit 7")
    assert "--- PASS: b" in r.stdout and "fail=1" in r.stdout


def test_fail_fast_stops_at_the_first_failure_with_a_red_exit(tmp_path):
    ev = tmp_path / "events.log"
    r = sh("gate_install_done_trap; run a true; run b false; run c true", tmp_path, GATE_FAIL_FAST="1", GATE_EVENTS=str(ev))
    assert r.returncode != 0 and "--- FAIL: b" in r.stdout and "=== GATE: c" not in r.stdout and "GATE: RED" in r.stdout
    assert ev.read_text().splitlines()[-1].endswith(" DONE RED")       # a watcher waiting for the end is not left hanging


def test_without_the_switches_nothing_extra_happens(tmp_path):
    r = sh("run a false; run b true", tmp_path)
    assert r.returncode == 0 and "fail=1" in r.stdout and not list(tmp_path.glob("*.log"))


def _fakebin(tmp_path, name, code):
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    (d / name).write_text(f"#!/bin/sh\nexit {code}\n")
    (d / name).chmod(0o755)
    return f"{d}:{os.environ['PATH']}"


def test_preflight_fails_fast_when_docker_is_opted_in_behind_a_proxy_without_the_build_ca(tmp_path):
    # the exact failure seen in a real gate run: pip inside the image build could not verify the proxy's certificate, hours in
    r = sh("gate_preflight || exit 3", tmp_path, PATH=_fakebin(tmp_path, "docker", 0), RUN_DOCKER_TESTS="1", HTTPS_PROXY="http://127.0.0.1:9")
    assert r.returncode != 0 and "SENTINEL_DOCKER_BUILD_CA" in r.stdout + r.stderr


def test_preflight_passes_with_the_proxy_settings_and_a_running_daemon(tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    r = sh("gate_preflight || exit 3", tmp_path, PATH=_fakebin(tmp_path, "docker", 0), RUN_DOCKER_TESTS="1", HTTPS_PROXY="http://127.0.0.1:9",
           SENTINEL_DOCKER_BUILD_CA=str(ca), SENTINEL_DOCKER_FORWARD_PROXY="1", SENTINEL_DOCKER_NETWORK_HOST="1")
    assert r.returncode == 0, r.stdout + r.stderr


def test_preflight_fails_when_the_docker_daemon_is_down(tmp_path):
    r = sh("gate_preflight || exit 3", tmp_path, PATH=_fakebin(tmp_path, "docker", 1), RUN_DOCKER_TESTS="1")
    assert r.returncode != 0 and "daemon" in (r.stdout + r.stderr).lower()


def test_preflight_fails_when_the_claude_stage_is_opted_in_without_a_working_cli(tmp_path):
    r = sh("gate_preflight || exit 3", tmp_path, PATH=_fakebin(tmp_path, "claude", 1), RUN_CLAUDE_TESTS="1")
    assert r.returncode != 0 and "claude" in (r.stdout + r.stderr).lower()


def test_preflight_with_nothing_opted_in_passes(tmp_path):
    assert sh("gate_preflight || exit 3", tmp_path).returncode == 0


def test_verify_sh_uses_the_library_runs_preflight_first_and_reports_the_end():
    v = (LIB.parent / "verify.sh").read_text()
    assert "source scripts/gate_lib.sh" in v and "\nrun() " not in v
    first_run = next(l for l in v.splitlines() if l.startswith("run "))
    assert "gate_preflight" in first_run
    assert "gate_install_done_trap" in v and "source scripts/gate_lib.sh ||" in v


# --- review round: fail closed, DONE on every way out, a preflight that catches this sandbox's real misconfigurations ---

def test_verify_sh_is_red_not_green_when_its_library_is_missing(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "verify.sh").write_text((LIB.parent / "verify.sh").read_text())
    (tmp_path / "frontend" / "node_modules").mkdir(parents=True)        # so no OTHER check turns this run red by accident
    (tmp_path / "frontend" / "package.json").write_text("{}")
    r = subprocess.run(["bash", str(tmp_path / "scripts" / "verify.sh")], capture_output=True, text=True, timeout=30,
                       env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)})
    assert r.returncode != 0 and "GATE: RED" in r.stdout and "GATE: GREEN" not in r.stdout


def _events_after(tmp_path, script):
    ev = tmp_path / "events.log"
    r = sh(f"gate_install_done_trap; {script}", tmp_path, GATE_EVENTS=str(ev))
    return r, ev.read_text().splitlines()


def test_done_is_written_on_a_normal_green_end(tmp_path):
    _, lines = _events_after(tmp_path, "run a true")
    assert lines[-1].endswith(" DONE GREEN")


def test_done_red_is_written_when_the_gate_aborts_on_an_unset_variable(tmp_path):
    r, lines = _events_after(tmp_path, "run a true; echo $UNDEFINED_GATE_VAR")
    assert r.returncode != 0 and lines[-1].endswith(" DONE RED")


def test_done_red_is_written_when_the_gate_is_terminated(tmp_path):
    ev = tmp_path / "events.log"
    p = subprocess.Popen(["bash", "-c", f"set -u; fail=0; source '{LIB}'; gate_install_done_trap; run a true; sleep 30 & wait"],
                         env={"PATH": os.environ["PATH"], "GATE_EVENTS": str(ev)}, cwd=tmp_path)
    import time
    for _ in range(100):
        if ev.exists() and "PASS a" in ev.read_text():
            break
        time.sleep(0.05)
    p.terminate()
    p.wait(timeout=10)
    assert ev.read_text().splitlines()[-1].endswith(" DONE RED")


def _docker_env(tmp_path, **kw):
    ca = tmp_path / "ca.crt"
    ca.write_text("x")
    env = dict(PATH=_fakebin(tmp_path, "docker", 0), RUN_DOCKER_TESTS="1", HTTPS_PROXY="http://proxy.example:3128",
               SENTINEL_DOCKER_BUILD_CA=str(ca), SENTINEL_DOCKER_FORWARD_PROXY="1")
    env.update(kw)
    return {k: v for k, v in env.items() if v is not None}


def _preflight(tmp_path, **kw):
    return sh("gate_preflight || exit 3", tmp_path, **_docker_env(tmp_path, **kw))


def test_preflight_requires_host_networking_for_a_loopback_proxy(tmp_path):
    for proxy in ("http://127.0.0.1:45973", "http://localhost:3128", "http://[::1]:3128"):
        r = _preflight(tmp_path, HTTPS_PROXY=proxy)
        assert r.returncode != 0 and "SENTINEL_DOCKER_NETWORK_HOST" in r.stdout, proxy
        assert _preflight(tmp_path, HTTPS_PROXY=proxy, SENTINEL_DOCKER_NETWORK_HOST="1").returncode == 0, proxy


def test_preflight_passes_a_non_loopback_proxy_without_host_networking(tmp_path):
    assert _preflight(tmp_path).returncode == 0


def test_preflight_checks_a_lowercase_only_proxy_too(tmp_path):
    assert _preflight(tmp_path, HTTPS_PROXY=None, https_proxy="http://proxy.example:3128", SENTINEL_DOCKER_FORWARD_PROXY=None).returncode != 0


def test_preflight_fails_on_an_unreadable_or_directory_ca(tmp_path):
    assert _preflight(tmp_path, SENTINEL_DOCKER_BUILD_CA=str(tmp_path / "missing.crt")).returncode != 0
    assert _preflight(tmp_path, SENTINEL_DOCKER_BUILD_CA=str(tmp_path)).returncode != 0


def test_preflight_fails_when_the_ca_is_set_but_the_proxy_is_not_forwarded(tmp_path):
    assert _preflight(tmp_path, SENTINEL_DOCKER_FORWARD_PROXY=None).returncode != 0


def test_preflight_escape_hatch_for_a_proxy_that_does_not_intercept_tls(tmp_path):
    assert _preflight(tmp_path, SENTINEL_DOCKER_BUILD_CA=None, SENTINEL_DOCKER_FORWARD_PROXY=None,
                      SENTINEL_DOCKER_PREFLIGHT_PROXY="0").returncode == 0


def test_docker_test_sh_forwards_the_same_proxy_variable_the_preflight_checks():
    d = (LIB.parent / "docker_test.sh").read_text()
    assert '${HTTPS_PROXY:-${https_proxy:-}}' in d


def test_missing_frontend_or_browser_goes_through_run_so_it_is_reported_as_a_failed_stage():
    v = (LIB.parent / "verify.sh").read_text()
    assert "fail=1" not in v.replace("fail=0", "")
