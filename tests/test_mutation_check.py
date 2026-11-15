"""scripts/mutation_check.py --changed-since REF (GATE_TIER=pr, DECISIONS.md D30): only the mutants whose target file changed since REF
(committed on this branch, staged, unstaged or untracked) run; nothing changed = a quick pass that says so; a bad ref is an error."""
import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("mutation_check_under_test", ROOT / "scripts" / "mutation_check.py")
mc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mc)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                               "HOME": str(repo), "PATH": "/usr/bin:/bin:/usr/local/bin"}).stdout


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "r"
    (r / "pkg").mkdir(parents=True)
    for name in ("committed.py", "staged.py", "unstaged.py", "untouched.py", "on_base.py"):
        (r / "pkg" / name).write_text("x = 1\n")
    git(r, "init", "-q", "-b", "main")
    git(r, "add", ".")
    git(r, "commit", "-q", "-m", "base")
    git(r, "checkout", "-q", "-b", "feature")
    (r / "pkg" / "committed.py").write_text("x = 2\n")
    git(r, "commit", "-q", "-am", "feature change")
    git(r, "checkout", "-q", "main")                       # a change on the base AFTER the branch point is not this branch's change
    (r / "pkg" / "on_base.py").write_text("x = 3\n")
    git(r, "commit", "-q", "-am", "base moves on")
    git(r, "checkout", "-q", "feature")
    (r / "pkg" / "staged.py").write_text("x = 4\n")
    git(r, "add", "pkg/staged.py")
    (r / "pkg" / "unstaged.py").write_text("x = 5\n")
    (r / "pkg" / "new.py").write_text("x = 6\n")           # untracked
    return r


def test_changed_files_are_the_branch_commits_plus_the_working_tree(repo):
    assert mc.changed_files("main", repo) == {"pkg/committed.py", "pkg/staged.py", "pkg/unstaged.py", "pkg/new.py"}


def test_only_mutants_of_changed_files_are_selected():
    mutants = [("A", "pkg/committed.py", "o", "n", 1), ("B", "pkg/untouched.py", "o", "n", 1), ("C", "pkg/new.py", "o", "n", 1)]
    assert [m[0] for m in mc.select_changed(mutants, {"pkg/committed.py", "pkg/new.py", "README.md"})] == ["A", "C"]
    assert mc.select_changed(mutants, set()) == []


def test_a_changed_or_deleted_test_file_selects_every_mutant():
    """No cheap, reliable mutant -> killing-test mapping exists, so a change to anything a killer may live in (a test, a fixture, a helper,
    pytest.ini) re-runs every mutant: a weakened test must not slip through because its mutants' targets did not change."""
    mutants = [("A", "server/gate.py", "o", "n", 1), ("B", "scripts/gate_lib.sh", "o", "n", 1)]
    for f in ("tests/server/test_gate.py", "tests/e2e/fakes.py", "tests/e2e/data/policy_e2e.json", "pytest.ini"):
        assert [m[0] for m in mc.select_changed(mutants, {f})] == ["A", "B"], f


def test_a_changed_gate_test_selects_the_gate_script_mutants_it_kills():
    """The top-level tests/test_*.py are the killers of the gate-script mutants (scripts/*, tests/*.py): see run_suite."""
    mutants = [("A", "server/gate.py", "o", "n", 1), ("B", "scripts/gate_lib.sh", "o", "n", 1), ("C", "tests/no_skip_plugin.py", "o", "n", 1)]
    assert [m[0] for m in mc.select_changed(mutants, {"tests/test_gate_lib.py"})] == ["B", "C"]


def test_the_default_base_is_origins_default_branch_and_missing_is_an_error(repo):
    with pytest.raises(SystemExit) as e:
        mc.resolve_base("@origin", repo)
    assert "GATE_BASE" in str(e.value)
    git(repo, "update-ref", "refs/remotes/origin/main", "main")
    assert mc.resolve_base("@origin", repo) == "origin/main"
    git(repo, "update-ref", "refs/remotes/origin/trunk", "main")
    git(repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
    assert mc.resolve_base("@origin", repo) == "origin/trunk"
    assert mc.resolve_base("feature~1", repo) == "feature~1"          # an explicit ref is used as given


def test_an_unknown_ref_is_an_error_not_an_empty_selection(repo):
    with pytest.raises(SystemExit) as e:
        mc.changed_files("no-such-ref", repo)
    assert "no-such-ref" in str(e.value)


def test_nothing_changed_passes_quickly_and_says_so(monkeypatch, capsys):
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {"README.md"})
    monkeypatch.setattr(mc, "run_backend", lambda *a: pytest.fail("no mutant should run"))
    monkeypatch.setattr(mc, "run_frontend", lambda *a: pytest.fail("no mutant should run"))
    assert mc.main(["--changed-since", "origin/main"]) == 0
    assert "no mutant targets changed since origin/main" in capsys.readouterr().out


def test_changed_since_runs_exactly_the_selected_mutants(monkeypatch, capsys):
    backend = next(m for m in mc.MUTANTS if m[1] == "server/gate.py")
    frontend = mc.FRONTEND_MUTANTS[0]
    ran = []
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {"server/gate.py", frontend[1]})
    monkeypatch.setattr(mc, "run_backend", lambda ms, survivors, stale: ran.extend(m[0] for m in ms))
    monkeypatch.setattr(mc, "run_frontend", lambda ms, survivors, stale: ran.extend(m[0] for m in ms))
    assert mc.main(["--changed-since", "main"]) == 0
    assert backend[0] in ran and frontend[0] in ran
    assert set(ran) == {m[0] for m in mc.MUTANTS + mc.FRONTEND_MUTANTS if m[1] in ("server/gate.py", frontend[1])}


def _suite_calls(monkeypatch, tmp_path, rel, rcs):
    (tmp_path / "tests").mkdir(exist_ok=True)
    (tmp_path / "tests" / "test_gate_x.py").write_text("")
    calls, rcs = [], list(rcs)
    monkeypatch.setattr(mc.subprocess, "run", lambda cmd, **kw: calls.append(cmd[cmd.index("no:cacheprovider") + 1:]) or
                        subprocess.CompletedProcess(cmd, rcs.pop(0)))
    return mc.run_suite(tmp_path, rel), calls


def test_a_gate_script_mutant_meets_the_gate_tests_first_and_still_the_whole_suite(monkeypatch, tmp_path):
    assert _suite_calls(monkeypatch, tmp_path, "scripts/gate_lib.sh", [1]) == (1, [["tests/test_gate_x.py"]])     # killed in seconds
    assert _suite_calls(monkeypatch, tmp_path, "scripts/gate_lib.sh", [0, 0]) == (0, [["tests/test_gate_x.py"], []])  # survived both


def test_a_product_mutant_runs_the_whole_suite_once(monkeypatch, tmp_path):
    assert _suite_calls(monkeypatch, tmp_path, "server/gate.py", [1]) == (1, [[]])
