"""scripts/check_live_coverage.py: the static part (map complete, files exist, live specs are run by a mandatory stage) and the runtime part
(every live pytest node id PASSED in this gate run's junit XML). The runtime cases use junit files written by a REAL pytest run in tmp_path."""
import json
import os
import subprocess
import sys

from tests.harness import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import check_live_coverage as clc  # noqa: E402

VERIFY = """#!/usr/bin/env bash
run "backend" python -m pytest
run "reality: live" env $NS -m reality tests/live --junitxml=$JU/live.xml
if [ -d frontend/node_modules ]; then
    run "browser e2e" bash -c 'cd frontend && npx playwright test'
    run "browser inbox" bash -c "cd frontend && INBOX_STAGE=1 npx playwright test inbox"
fi
[ "${RUN_CLAUDE_TESTS:-0}" = "1" ] && run "claude" env $NS -m claude_live tests/claude
[ "${RUN_JOURNEY_TESTS:-0}" = "1" ] && run "journeys" bash -c "cd frontend && npm run journeys"
[ "${RUN_POLICY:-0}" = "1" ] && run "policy only opt-in" bash -c "cd frontend && POLICY_STAGE=1 npx playwright test policy"
"""
LIVE = """import pytest
pytestmark = pytest.mark.reality

def test_ok():
    pass

def test_skips():
    pytest.skip("no server")

def test_xfails():
    pytest.xfail("flaky")

def test_fails():
    assert False

def test_early_return():
    return

@pytest.mark.parametrize("n", [1, 2])
def test_param(n):
    assert n == 1

@pytest.mark.parametrize("n", [1, 2])
def test_param_ok(n):
    pass

class TestK:
    def test_m(self):
        pass
"""


def _repo(tmp_path):
    for d in ("tests/live", "tests/claude", "frontend/e2e", "frontend/journeys", "scripts"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    (tmp_path / "scripts/verify.sh").write_text(VERIFY)
    (tmp_path / "tests/live/test_live.py").write_text(LIVE)
    (tmp_path / "tests/claude/test_c.py").write_text("def test_c():\n    pass\n")
    (tmp_path / "frontend/e2e/live.spec.ts").write_text('test("a", async () => {});\n')
    (tmp_path / "frontend/e2e/inbox.spec.ts").write_text('test.skip(process.env.INBOX_STAGE !== "1", "stage only");\ntest("b", async () => {});\n')
    (tmp_path / "frontend/e2e/policy.spec.ts").write_text('test.skip(process.env.POLICY_STAGE !== "1", "stage only");\ntest("c", async () => {});\n')
    (tmp_path / "frontend/e2e/orphan.spec.ts").write_text('test.skip(process.env.ORPHAN_STAGE !== "1", "stage only");\n')
    (tmp_path / "frontend/journeys/j1.spec.ts").write_text('test("j", async () => {});\n')
    return tmp_path


def _static(tmp_path, workflows) -> list[str]:
    root = _repo(tmp_path)
    m = root / "map.json"
    m.write_text(json.dumps({"workflows": workflows}))
    return clc.check_static(m, root / "scripts/verify.sh", root, required=tuple(workflows))


def _runtime(tmp_path, live: list[str]) -> list[str]:
    root = _repo(tmp_path)
    ju = root / "junit"
    ju.mkdir()
    (root / "pytest.ini").write_text("[pytest]\nmarkers =\n    reality: x\n")
    subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/live", f"--junitxml={ju / 'live.xml'}"], cwd=root,
                   capture_output=True, text=True, timeout=120, env={k: v for k, v in os.environ.items() if k != "SENTINEL_NO_SKIP"})
    m = root / "map.json"
    m.write_text(json.dumps({"workflows": {"O1": {"title": "t", "live": live}}}))
    return clc.check_runtime(m, ju)


# ---- static --------------------------------------------------------------------------------------------------------------------------------

def test_static_a_good_map_passes(tmp_path):
    assert _static(tmp_path, {
        "O1": {"title": "t", "live": ["frontend/e2e/live.spec.ts", "tests/live/test_live.py::test_ok"]},
        "O2": {"title": "t", "live": ["frontend/e2e/inbox.spec.ts"], "optional": ["frontend/journeys/j1.spec.ts", "tests/claude/test_c.py::test_c"]},
        "P1": {"title": "t", "live": [], "optional": ["tests/claude/test_c.py::test_c"], "gap": "needs a Docker daemon"},
    }) == []


def test_static_no_live_test_and_no_gap_fails_and_optional_alone_is_not_enough(tmp_path):
    errs = _static(tmp_path, {"O1": {"title": "t", "live": []}, "D4": {"title": "t", "live": [], "optional": ["tests/claude/test_c.py::test_c"]},
                              "P1": {"title": "t", "live": [], "gap": "  "}})
    assert {e.split(" ")[0] for e in errs if "no live test" in e} == {"O1", "D4", "P1"}, errs


def test_static_a_missing_file_fails_live_or_optional(tmp_path):
    errs = _static(tmp_path, {"O1": {"title": "t", "live": ["tests/live/test_nope.py::test_ok"], "optional": ["frontend/journeys/gone.spec.ts"]}})
    assert sum("does not exist" in e for e in errs) == 2, errs


def test_static_a_gated_spec_no_stage_filters_for_fails(tmp_path):
    errs = _static(tmp_path, {"O1": {"title": "t", "live": ["frontend/e2e/orphan.spec.ts"]}})
    assert any("no verify.sh stage runs" in e for e in errs), errs


def test_static_a_spec_only_an_opt_in_stage_runs_must_be_optional(tmp_path):
    errs = _static(tmp_path, {"O1": {"title": "t", "live": ["frontend/journeys/j1.spec.ts"]}, "O2": {"title": "t", "live": ["frontend/e2e/policy.spec.ts"]}})
    assert sum("opt-in" in e for e in errs) == 2, errs


def test_static_a_required_workflow_missing_from_the_map_fails(tmp_path):
    root = _repo(tmp_path)
    m = root / "map.json"
    m.write_text(json.dumps({"workflows": {"O1": {"title": "t", "live": ["frontend/e2e/live.spec.ts"]}}}))
    assert any("O2" in e and "missing" in e for e in clc.check_static(m, root / "scripts/verify.sh", root, required=("O1", "O2")))


def test_the_default_required_set_is_the_documented_workflow_list():
    assert set(clc.REQUIRED) == {"O1", "O2", "O3", "O4", "O5", "O6", "D1", "D2", "D3", "D4", "A1", "A2", "A3", "L1", "L2", "L3", "P1"}


# ---- runtime (junit) -----------------------------------------------------------------------------------------------------------------------

def test_runtime_passed_tests_pass_function_class_method_and_parametrised(tmp_path):
    assert _runtime(tmp_path, ["tests/live/test_live.py::test_ok", "tests/live/test_live.py::TestK::test_m", "tests/live/test_live.py::TestK",
                               "tests/live/test_live.py::test_param_ok", "tests/live/test_live.py::test_param_ok[1]", "frontend/e2e/live.spec.ts"]) == []


def test_runtime_skipped_xfail_failed_are_not_proof(tmp_path):
    errs = _runtime(tmp_path, ["tests/live/test_live.py::test_skips", "tests/live/test_live.py::test_xfails", "tests/live/test_live.py::test_fails"])
    assert len(errs) == 3 and all("must PASS" in e for e in errs), errs


def test_runtime_one_failing_parametrised_case_or_whole_file_fails(tmp_path):
    errs = _runtime(tmp_path, ["tests/live/test_live.py::test_param", "tests/live/test_live.py"])
    assert any("test_param[2] failed" in e for e in errs) and any("test_skips skipped" in e for e in errs), errs


def test_runtime_a_test_that_did_not_run_fails(tmp_path):
    errs = _runtime(tmp_path, ["tests/live/test_live.py::test_renamed", "tests/claude/test_c.py::test_c"])
    assert len(errs) == 2 and all("did not run" in e for e in errs), errs


def test_runtime_no_junit_at_all_fails(tmp_path):
    m = tmp_path / "map.json"
    m.write_text(json.dumps({"workflows": {"O1": {"title": "t", "live": ["tests/live/test_live.py::test_ok"]}}}))
    (tmp_path / "empty").mkdir()
    assert clc.check_runtime(m, tmp_path / "empty")


def test_runtime_limit_a_vacuous_pass_is_not_detectable(tmp_path):
    """Documented limit (docs/TESTING_REALITY.md): an early return passes. Review and mutants, not this check, catch that."""
    assert _runtime(tmp_path, ["tests/live/test_live.py::test_early_return"]) == []


def test_the_cli_exit_code_is_the_verdict(tmp_path):
    root = _repo(tmp_path)
    good, bad = root / "good.json", root / "bad.json"
    wf = {k: {"title": k, "live": ["frontend/e2e/live.spec.ts"]} for k in clc.REQUIRED}
    good.write_text(json.dumps({"workflows": wf}))
    bad.write_text(json.dumps({"workflows": {**wf, "O1": {"title": "x", "live": []}}}))
    cmd = [sys.executable, str(ROOT / "scripts/check_live_coverage.py"), "--root", str(root), "--verify", str(root / "scripts/verify.sh")]
    assert subprocess.run([*cmd, "--map", str(good)], capture_output=True, text=True).returncode == 0
    r = subprocess.run([*cmd, "--map", str(bad)], capture_output=True, text=True)
    assert r.returncode == 1 and "O1" in r.stdout
    (root / "ju").mkdir()
    assert subprocess.run([*cmd, "--map", str(good), "--junit", str(root / "ju")], capture_output=True, text=True).returncode == 1


def test_runtime_a_node_id_seen_twice_counts_its_worst_outcome(tmp_path):
    """The same test in two junit files (two stages, or a rerun): one skip or failure anywhere is not proof, whichever file is read last."""
    ok = '<testsuites><testsuite><testcase classname="tests.live.test_live" name="test_ok"/></testsuite></testsuites>'
    bad = '<testsuites><testsuite><testcase classname="tests.live.test_live" name="test_ok"><skipped/></testcase></testsuite></testsuites>'
    (tmp_path / "a.xml").write_text(ok)
    (tmp_path / "b.xml").write_text(bad)
    (tmp_path / "c.xml").write_text(ok)
    assert clc.junit_outcomes(tmp_path)["tests/live/test_live.py::test_ok"] == "skipped"
