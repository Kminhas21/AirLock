"""tests/no_skip_plugin.py: with SENTINEL_NO_SKIP=1 a skipped test is a FAILURE (the reality gate stages must really run, docs/TESTING_REALITY.md).
Each case runs a real pytest in a throwaway directory (its own pytest.ini, so the repo's addopts and markers do not apply)."""
import os
import subprocess
import sys

from tests.harness import ROOT

CASES = """
import pytest

def test_passes():
    assert True

def test_skips():
    pytest.skip("dependency missing")

@pytest.mark.xfail(reason="known", strict=False)
def test_xfails():
    assert False
"""


def _run(tmp_path, body: str, no_skip: str | None, *extra: str) -> subprocess.CompletedProcess:
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_case.py").write_text(body)
    env = {k: v for k, v in os.environ.items() if k != "SENTINEL_NO_SKIP"}
    env["PYTHONPATH"] = str(ROOT)
    if no_skip is not None:
        env["SENTINEL_NO_SKIP"] = no_skip
    return subprocess.run([sys.executable, "-m", "pytest", "-p", "tests.no_skip_plugin", "-q", "-p", "no:cacheprovider", *extra, str(tmp_path)],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)


def test_without_the_switch_a_skip_is_still_a_skip(tmp_path):
    r = _run(tmp_path, CASES, None)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "1 skipped" in r.stdout


def test_with_the_switch_a_skip_fails_the_run_and_names_the_test_and_reason(tmp_path):
    r = _run(tmp_path, CASES, "1")
    assert r.returncode == 1, r.stdout + r.stderr
    assert "test_skips" in r.stdout and "dependency missing" in r.stdout and "SENTINEL_NO_SKIP" in r.stdout
    assert "skipped" not in r.stdout.split("\n")[-2]                  # counted as failed, not as skipped


def test_with_the_switch_an_xfail_marker_fails_the_run(tmp_path):
    """An xfail lets a live test silently not prove anything: in a reality stage it is a failure too."""
    r = _run(tmp_path, CASES.replace("def test_skips", "def _not_a_test"), "1")
    assert r.returncode == 1 and "test_xfails" in r.stdout and "known" in r.stdout, r.stdout + r.stderr


def test_with_the_switch_an_imperative_xfail_fails_the_run(tmp_path):
    r = _run(tmp_path, "import pytest\n\ndef test_x():\n    pytest.xfail('server flaky')\n", "1")
    assert r.returncode == 1 and "server flaky" in r.stdout, r.stdout + r.stderr


def test_with_the_switch_an_unexpected_xpass_fails_the_run(tmp_path):
    r = _run(tmp_path, "import pytest\n\n@pytest.mark.xfail(reason='was broken')\ndef test_x():\n    pass\n", "1")
    assert r.returncode == 1 and "was broken" in r.stdout, r.stdout + r.stderr


def test_without_the_switch_xfail_is_still_xfail(tmp_path):
    r = _run(tmp_path, "import pytest\n\ndef test_x():\n    pytest.xfail('server flaky')\n", None)
    assert r.returncode == 0 and "1 xfailed" in r.stdout, r.stdout + r.stderr


def test_with_the_switch_a_module_level_skip_fails_the_run(tmp_path):
    r = _run(tmp_path, "import pytest\npytest.skip('no server', allow_module_level=True)\n\ndef test_x():\n    pass\n", "1")
    assert r.returncode != 0, r.stdout + r.stderr
    assert "no server" in r.stdout


def test_with_the_switch_a_skipif_marker_fails_the_run(tmp_path):
    r = _run(tmp_path, "import pytest\n\n@pytest.mark.skipif(True, reason='no claude cli')\ndef test_x():\n    pass\n", "1")
    assert r.returncode == 1 and "no claude cli" in r.stdout, r.stdout + r.stderr


def test_with_the_switch_a_skip_in_a_fixture_fails_the_run(tmp_path):
    body = "import pytest\n\n@pytest.fixture\ndef dep():\n    pytest.skip('fixture says no')\n\ndef test_x(dep):\n    pass\n"
    r = _run(tmp_path, body, "1")
    assert r.returncode == 1 and "fixture says no" in r.stdout, r.stdout + r.stderr


def test_switch_values_other_than_1_do_not_enable_it(tmp_path):
    assert _run(tmp_path, CASES, "0").returncode == 0


def test_nothing_collected_is_still_exit_code_5(tmp_path):
    """verify.sh's run() treats any non-zero exit as a failure; an empty reality stage must not turn green."""
    r = _run(tmp_path, "def helper():\n    pass\n", "1")
    assert r.returncode == 5, r.stdout + r.stderr
