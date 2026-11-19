"""scripts/mutation_check.py --changed-since REF (GATE_TIER=pr, DECISIONS.md D30): only the mutants whose target file changed since REF
(committed on this branch, staged, unstaged or untracked) run; nothing changed = a quick pass that says so; a bad ref is an error."""
import importlib.util
import os
import re
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
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: None)
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {"README.md"})
    monkeypatch.setattr(mc, "run_backend", lambda *a: pytest.fail("no mutant should run"))
    monkeypatch.setattr(mc, "run_frontend", lambda *a: pytest.fail("no mutant should run"))
    assert mc.main(["--changed-since", "origin/main"]) == 0
    assert "no mutant targets changed since origin/main" in capsys.readouterr().out


def test_changed_since_runs_exactly_the_selected_mutants(monkeypatch, capsys):
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: None)
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
    assert _suite_calls(monkeypatch, tmp_path, "scripts/gate_lib.sh", [0, 0, 0]) == (0, [["tests/test_gate_x.py"], ["--deselect", mc.NESTED_SUITE_TEST],
                                                                                          [mc.NESTED_SUITE_TEST]])  # survived all three


def test_a_product_mutant_with_no_related_test_runs_the_whole_suite_once(monkeypatch, tmp_path):
    assert _suite_calls(monkeypatch, tmp_path, "server/unrelated.py", [1]) == (1, [["--deselect", mc.NESTED_SUITE_TEST]])


def test_a_product_mutant_meets_the_tests_that_name_its_module_first(monkeypatch, tmp_path):
    """The whole suite would run the e2e files before tests/server/test_gate.py: minutes per mutant, and a witness that is whatever sorts first.
    The tests that mention the module run first (-x), so the witness is the real unit test; the whole suite is still the fallback."""
    assert _suite_calls(monkeypatch, tmp_path, "server/gate.py", [1]) == (1, [["tests/test_gate_x.py"]])
    assert _suite_calls(monkeypatch, tmp_path, "server/gate.py", [0, 1]) == (1, [["tests/test_gate_x.py"], ["--deselect", mc.NESTED_SUITE_TEST]])


def test_candidate_files_run_one_directory_at_a_time_so_conftest_modules_never_collide():
    """tests/e2e/conftest.py and tests/proxy/conftest.py are both imported as `conftest`: one pytest run holding files of both directories made
    `from conftest import ROOT` fail to import, and the mutant read as KILLED by that collection error (a false kill)."""
    assert mc.group_by_dir(["tests/server/test_a.py", "tests/e2e/test_b.py", "tests/server/test_c.py", "tests/test_top.py"]) == [
        ["tests/server/test_a.py", "tests/server/test_c.py"], ["tests/e2e/test_b.py"], ["tests/test_top.py"]]


def test_a_mutant_with_candidates_in_two_directories_runs_each_directory_separately(monkeypatch, tmp_path):
    (tmp_path / "tests" / "e2e").mkdir(parents=True)
    (tmp_path / "tests" / "proxy").mkdir(parents=True)
    (tmp_path / "tests" / "e2e" / "test_gate.py").write_text("")
    (tmp_path / "tests" / "proxy" / "test_gate_more.py").write_text("")
    calls, rcs = [], [0, 0, 0, 0]
    monkeypatch.setattr(mc.subprocess, "run", lambda cmd, **kw: calls.append(cmd[cmd.index("no:cacheprovider") + 1:]) or subprocess.CompletedProcess(cmd, rcs.pop(0)))
    mc.run_suite_detail(tmp_path, "server/gate.py")
    assert calls[:2] == [["tests/e2e/test_gate.py"], ["tests/proxy/test_gate_more.py"]]


def test_candidate_tests_are_ranked_by_name_then_mention_and_skip_the_nested_and_support_files(tmp_path):
    t = tmp_path / "tests"
    for rel, body in {"server/test_gate.py": "", "proxy/test_other.py": "from gate import x", "proxy/test_none.py": "pass", "docker/test_image_context.py": "gate",
                      "server/helper.py": "gate", "e2e/test_ws.py": "import server.gate"}.items():
        (t / rel).parent.mkdir(parents=True, exist_ok=True)
        (t / rel).write_text(body)
    assert mc.candidate_tests(tmp_path, "server/gate.py") == ["tests/server/test_gate.py", "tests/e2e/test_ws.py", "tests/proxy/test_other.py"]
    assert mc.candidate_tests(tmp_path, "scripts/gate_lib.sh") == []          # gate scripts have their own quick pass


def test_the_nested_suite_test_runs_last_so_it_never_hides_the_real_killer(monkeypatch, tmp_path):
    """tests/docker/test_image_context.py re-runs a quarter of the suite in a nested tree: it sorts before the real unit tests, so with -x it
    would be the witness of nearly every mutant (and cost minutes per mutant). It still counts: it runs, alone, after the rest survive."""
    assert mc.NESTED_SUITE_TEST.startswith("tests/docker/test_image_context.py::")
    assert _suite_calls(monkeypatch, tmp_path, "server/unrelated.py", [0, 1]) == (1, [["--deselect", mc.NESTED_SUITE_TEST], [mc.NESTED_SUITE_TEST]])


# ---------------------------------------------------------------------------------------------------------------------------------------
# The per-mutant KILLER MAP (scripts/mutant_killers.json, DECISIONS.md D30 note): a PR that edits tests re-runs only the mutants whose
# witness test file it touched, instead of all of them. Every rule fails SAFE: when unsure, select MORE mutants, never fewer.
# ---------------------------------------------------------------------------------------------------------------------------------------
import json


@pytest.fixture(autouse=True)
def _clean_tree_is_green_unless_a_test_says_otherwise():
    """The real guard runs the whole suite (minutes); tests that exercise run_backend / build pretend the clean tree was already proven."""
    mc._CLEAN.update(rc=0, failed=[])
    yield
    mc._CLEAN.clear()


@pytest.fixture(autouse=True)
def _no_ambient_cap_proof(monkeypatch):
    """The PR job exports GATE_MUTATION_PROOF / GATE_HEAD_SHA once a full run of the commit is green; the cap tests must not inherit it (they
    passed locally and went red only in that job: the proof they were not meant to see lifted the cap)."""
    for k in ("GATE_MUTATION_PROOF", "GATE_HEAD_SHA"):
        monkeypatch.delenv(k, raising=False)


def _m(name, rel="server/a.py", old="o", new="n", count=1):
    return (name, rel, old, new, count)


def _map(mutants, killers=None, **kw):
    """A killer map for `mutants`; killers: name -> list of files (default: tests/x/test_<name>.py)."""
    killers = killers or {}
    return mc.new_killer_map({m[0]: mc.make_entry(m, killers.get(m[0], [f"tests/x/test_{m[0]}.py"]), **kw) for m in mutants})


def _names(ms):
    return [m[0] for m in ms]


def test_a_mutant_hash_covers_the_whole_definition():
    base = _m("A")
    assert mc.mutant_hash(base) == mc.mutant_hash(_m("A"))
    for changed in (_m("A2"), _m("A", rel="server/b.py"), _m("A", old="o2"), _m("A", new="n2"), _m("A", count=2)):
        assert mc.mutant_hash(changed) != mc.mutant_hash(base), changed


def test_weakening_the_only_killer_of_a_mutant_selects_that_mutant_and_no_other():
    """The whole point: the mutants are no longer ALL re-run, but the one whose killer was edited is."""
    ms = [_m("X"), _m("Y"), _m("Z", "scripts/s.py")]
    km = _map(ms, {"X": ["tests/server/test_a.py"], "Y": ["tests/server/test_b.py"], "Z": ["tests/server/test_a.py", "tests/proxy/test_c.py"]})
    assert _names(mc.select_changed(ms, {"tests/server/test_a.py"}, km)) == ["X", "Z"]
    assert _names(mc.select_changed(ms, {"tests/proxy/test_c.py"}, km)) == ["Z"]
    assert mc.select_changed(ms, {"tests/server/test_unrelated.py"}, km) == []       # a test that kills nothing selects nothing


def test_a_deleted_or_renamed_killer_selects_the_mutants_it_killed(repo):
    """Deletion weakens, and a rename is a delete (of the old path) plus an add: changed_files must list BOTH paths (git's default
    rename detection would list only the new one, and the old killer name would never be seen)."""
    (repo / "tests" / "server").mkdir(parents=True)
    (repo / "tests" / "server" / "test_a.py").write_text("def test_a(): pass\n")
    (repo / "tests" / "server" / "test_b.py").write_text("def test_b(): pass\n")
    git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "tests")
    git(repo, "checkout", "-q", "-b", "weakening")
    git(repo, "rm", "-q", "tests/server/test_a.py")
    git(repo, "mv", "tests/server/test_b.py", "tests/server/test_b_renamed.py")
    git(repo, "commit", "-q", "-m", "delete a, rename b")
    ch = mc.changed_files("feature", repo)
    assert {"tests/server/test_a.py", "tests/server/test_b.py", "tests/server/test_b_renamed.py"} <= ch
    ms = [_m("A"), _m("B"), _m("C")]
    km = _map(ms, {"A": ["tests/server/test_a.py"], "B": ["tests/server/test_b.py"], "C": ["tests/server/test_c.py"]})
    assert _names(mc.select_changed(ms, ch, km)) == ["A", "B"]


def test_a_mutant_with_no_entry_or_a_stale_entry_is_selected_even_when_no_test_changed():
    ms = [_m("A"), _m("B"), _m("C")]
    km = _map(ms)
    del km["mutants"]["A"]                                                    # no entry
    km["mutants"]["B"]["hash"] = "0" * 64                                     # the mutant definition changed since the map was built
    assert _names(mc.select_changed(ms, set(), km)) == ["A", "B"]
    assert _names(mc.select_changed(ms, {"server/other.py"}, km)) == ["A", "B"]
    km["mutants"]["C"]["killers"] = []                                        # an entry that names no killer proves nothing
    assert _names(mc.select_changed(ms, set(), km)) == ["A", "B", "C"]


@pytest.mark.parametrize("f", ["pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini", "conftest.py", "tests/conftest.py", "tests/no_skip_plugin.py",
                               "tests/harness.py", "tests/reality_fixtures.py", "tests/__init__.py"])
def test_a_file_that_affects_every_test_selects_every_pytest_mutant(f, monkeypatch):
    monkeypatch.setattr(mc, "_test_texts", lambda: {})
    ms = [_m("A"), _m("B", "scripts/gate_lib.sh")]
    assert _names(mc.select_changed(ms, {f}, _map(ms))) == ["A", "B"], f


TEXTS = {"tests/test_gate_tiers.py": 'VERIFY = ROOT / "scripts" / "verify.sh"; ci = ".github/workflows/ci.yml"',
         "tests/server/test_docs.py": 'open("DECISIONS.md"); open("docs/TESTING_REALITY.md")',
         "tests/proxy/test_boundary.py": "from fakes_proxy import agent",
         "tests/proxy/conftest.py": "",
         "tests/hostile/test_h.py": "import fakes as f; open('fakes.json')",
         "tests/e2e/test_e.py": "x = 1"}


def _scoped(monkeypatch):
    monkeypatch.setattr(mc, "_test_texts", lambda: TEXTS)
    ms = [_m("GT"), _m("DOC"), _m("PX"), _m("HO"), _m("E2"), _m("ANY")]
    km = _map(ms, {"GT": ["tests/test_gate_tiers.py"], "DOC": ["tests/server/test_docs.py"], "PX": ["tests/proxy/test_boundary.py"],
                   "HO": ["tests/hostile/test_h.py"], "E2": ["tests/e2e/test_e.py"], "ANY": ["*"]}, kind="single")
    km["mutants"]["ANY"]["kind"] = "combination"
    return ms, km


@pytest.mark.parametrize("f, expect", [
    ("DECISIONS.md", ["DOC", "ANY"]), ("docs/TESTING_REALITY.md", ["DOC", "ANY"]), ("scripts/verify.sh", ["GT", "ANY"]),
    (".github/workflows/ci.yml", ["GT", "ANY"]), ("README.md", []), ("docs/UNREAD.md", []),
     ("server/other.py", []),
    ("frontend/package.json", []), ("demo/scenario.json", [])])
def test_a_doc_or_data_file_selects_the_mutants_whose_witness_names_it(f, expect, monkeypatch):
    """B3: a one-line doc or CI edit used to select every mutant (any file a test named was 'shared'); now exactly the witnesses that read it."""
    ms, km = _scoped(monkeypatch)
    got = _names(mc.select_changed(ms, {f}, km))
    assert got == expect, (f, got)


def test_a_directory_conftest_selects_only_the_witnesses_of_that_test_directory(monkeypatch):
    ms, km = _scoped(monkeypatch)
    assert _names(mc.select_changed(ms, {"tests/proxy/conftest.py"}, km)) == ["PX", "ANY"]
    assert _names(mc.select_changed(ms, {"tests/e2e/conftest.py"}, km)) == ["E2", "ANY"]


def test_a_support_module_selects_its_directory_and_the_tests_that_name_it(monkeypatch):
    ms, km = _scoped(monkeypatch)
    got = _names(mc.select_changed(ms, {"tests/e2e/fakes.py"}, km))
    assert got == ["HO", "E2", "ANY"]                       # tests/hostile/test_h.py imports `fakes`, so its mutants are selected too
    assert _names(mc.select_changed(ms, {"tests/e2e/data/policy.json"}, km)) == ["E2", "ANY"]


def test_every_frontend_source_file_the_backend_tests_open_has_a_reader():
    """Self-maintaining: a tests/**/*.py that builds a path `... / "frontend" / "src" / ... / "<file>"` opens that file, so a change to it must
    select that test's mutants (the name is found in its text)."""
    opened = set()
    for f in (ROOT / "tests").rglob("*.py"):
        for mt in re.finditer(r'"frontend" / "src"((?: / "[^"]+")*)', f.read_text()):
            opened.add("frontend/src" + "".join("/" + q for q in re.findall(r'"([^"]+)"', mt.group(1))))
    assert {"frontend/src/types/contracts.ts", "frontend/src/lib/drift.ts"} <= opened
    texts = mc._test_texts()
    assert [f for f in sorted(opened) if "." in f.rsplit("/", 1)[-1] and not mc._readers(f, texts)] == []


def test_a_cap_on_the_selection_is_a_loud_red_never_a_silent_timeout(monkeypatch, capsys):
    ms = [_m(f"M{i}") for i in range(5)]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: None)
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {"tests/server/test_a.py"})        # no map: all five selected
    monkeypatch.setattr(mc, "run_backend", lambda *a: pytest.fail("a capped run must not start"))
    assert mc.main(["--changed-since", "main", "--max-selected", "3"]) == 1
    out = capsys.readouterr().out
    assert "too many mutants selected for the PR tier (5 > 3): run the nightly mutation workflow" in out
    ran = []
    monkeypatch.setattr(mc, "run_backend", lambda ms_, s, st: ran.extend(m[0] for m in ms_))
    monkeypatch.setattr(mc, "run_frontend", lambda *a: None)
    assert mc.main(["--changed-since", "main", "--max-selected", "5"]) == 0 and len(ran) == 5
    assert mc.main(["--changed-since", "main"]) == 0                       # no limit by default


def test_any_frontend_source_or_helper_change_selects_every_vitest_mutant_but_no_pytest_one():
    f1, p = _m("F1", "frontend/src/a.tsx"), _m("P", "server/a.py")
    km = mc.new_killer_map({"F1": mc.make_entry(f1, ["frontend/src/a.test.tsx"], runner="vitest"), "P": mc.make_entry(p, ["tests/x/test_P.py"])})
    for f in ("frontend/src/lib/helper.ts", "frontend/src/test/setup.ts", "frontend/src/components/Other.tsx", "frontend/eslint.config.js"):
        assert _names(mc.select_changed([f1, p], {f}, km)) == ["F1"], f


def test_a_mutant_killed_by_a_combination_is_selected_on_any_test_file_change():
    ms = [_m("A"), _m("B")]
    km = _map(ms, {"A": ["*"], "B": ["tests/x/test_B.py"]}, kind="combination")
    assert _names(mc.select_changed(ms, {"tests/anything/test_new_name.py"}, km)) == ["A"]
    assert mc.select_changed(ms, {"server/other.py", "notes/todo.py"}, km) == []   # but not a non-test change


def test_a_changed_gate_test_still_selects_the_gate_script_mutants():
    """The pre-map rule is kept ON TOP of the map (belt and braces): editing a top-level gate test selects every gate-script mutant."""
    ms = [_m("A"), _m("B", "scripts/gate_lib.sh"), _m("C", "tests/no_skip_plugin.py")]
    km = _map(ms, {"B": ["tests/x/test_other.py"], "C": ["tests/x/test_other.py"]})
    assert _names(mc.select_changed(ms, {"tests/test_gate_lib.py"}, km)) == ["B", "C"]


def test_a_changed_target_still_selects_its_mutants_whatever_the_map_says():
    ms = [_m("A", "server/a.py"), _m("B", "server/b.py")]
    assert _names(mc.select_changed(ms, {"server/b.py"}, _map(ms))) == ["B"]


# These read the COMMITTED map. Inside a mutation run (MUTATION_CHECK_RUN=1) they are skipped: a stale map must not make a SURVIVING mutant
# read as killed, and the clean-tree proof must be possible while the map is being (re)built.
needs_committed_map = pytest.mark.skipif(os.environ.get("MUTATION_CHECK_RUN") == "1", reason="inside a mutation-check run")


@needs_committed_map
def test_selection_is_a_superset_of_the_old_rule_for_source_file_changes():
    """Not-a-test changes (targets, docs, other source): the new selection contains everything the old one picked."""
    km = mc.load_killer_map()
    assert km is not None
    all_m = mc.MUTANTS + mc.FRONTEND_MUTANTS
    files = sorted({m[1] for m in all_m})
    sets = [{f} for f in files] + [set(files[:5]), set(files), {"README.md"}, {"server/not_a_target.py"}, set()]
    for ch in sets:
        old = {m[0] for m in all_m if m[1] in ch}
        new = {m[0] for m in mc.select_changed(all_m, ch, km)}
        assert old <= new, (sorted(ch)[:3], old - new)


def test_without_a_usable_map_every_test_change_still_selects_everything():
    ms = [_m("A"), _m("B")]
    good = _map(ms)
    for bad in (None, {}, {**good, "schema": 999}, {"schema": mc.KILLER_MAP_SCHEMA}, "garbage"):
        assert _names(mc.select_changed(ms, {"tests/server/test_a.py"}, bad)) == ["A", "B"], bad
        assert mc.select_changed(ms, {"README.md"}, bad) == []


def test_frontend_mutants_are_killed_by_vitest_files_only():
    f1, f2 = _m("F1", "frontend/src/a.tsx"), _m("F2", "frontend/src/b.ts")
    p = _m("P", "server/a.py")
    km = mc.new_killer_map({"F1": mc.make_entry(f1, ["frontend/src/a.test.tsx"], runner="vitest"),
                            "F2": mc.make_entry(f2, ["frontend/src/b.test.ts"], runner="vitest"),
                            "P": mc.make_entry(p, ["tests/server/test_a.py"])})
    ms = [f1, f2, p]
    assert _names(mc.select_changed(ms, {"frontend/src/b.test.ts"}, km)) == ["F2"]          # the vitest killer of F2: a gap in the old rule
    assert _names(mc.select_changed(ms, {"tests/server/test_a.py"}, km)) == ["P"]            # a pytest edit no longer re-runs vitest mutants
    for shared in ("frontend/vite.config.ts", "frontend/package.json", "frontend/package-lock.json", "frontend/tsconfig.app.json"):
        assert _names(mc.select_changed(ms, {shared}, km)) == ["F1", "F2"], shared


def test_check_reports_every_kind_of_stale_map():
    ms = [_m("A"), _m("B")]
    good = _map(ms)
    assert mc.killer_map_problems(ms, good, ROOT, check_files=False) == []
    probs = mc.killer_map_problems(ms + [_m("NEW")], good, ROOT, check_files=False)
    assert any("NEW" in p and "no entry" in p for p in probs)
    changed = [_m("A", new="different"), _m("B")]
    assert any("A" in p and "changed" in p for p in mc.killer_map_problems(changed, good, ROOT, check_files=False))
    assert any("B" in p and "no longer" in p for p in mc.killer_map_problems([_m("A")], good, ROOT, check_files=False))      # orphan
    assert any("schema" in p for p in mc.killer_map_problems(ms, {**good, "schema": 0}, ROOT, check_files=False))
    assert any("older" in p or "mutants_hash" in p for p in mc.killer_map_problems(ms, {**good, "mutants_hash": "0" * 64}, ROOT, check_files=False))
    assert mc.killer_map_problems(ms, None, ROOT, check_files=False)


def test_check_reports_a_killer_file_that_no_longer_exists(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_here.py").write_text("")
    ms = [_m("A"), _m("B")]
    km = _map(ms, {"A": ["tests/test_here.py"], "B": ["tests/test_gone.py"]})
    probs = mc.killer_map_problems(ms, km, tmp_path)
    assert len(probs) == 1 and "B" in probs[0] and "test_gone.py" in probs[0]


@needs_committed_map
def test_the_committed_killer_map_is_current():
    """The same check the push-tier stage `mutation_check.py --check-killer-map` runs: a new/changed mutant or a moved killer file fails
    here in seconds (`python scripts/mutation_check.py --build-killer-map` re-attributes only the stale entries)."""
    assert mc.killer_map_problems(mc.MUTANTS + mc.FRONTEND_MUTANTS, mc.load_killer_map(), ROOT) == []


@needs_committed_map
def test_the_committed_map_has_a_witness_for_every_mutant_and_names_its_kind():
    km = mc.load_killer_map()
    for name, e in km["mutants"].items():
        assert e["kind"] in ("single", "combination", "unknown"), name
        assert e["runner"] in ("pytest", "vitest"), name
        assert e["tier"] in ("push", "pr", "weekly", "unknown"), name
        assert e["killers"] and all(isinstance(k, str) for k in e["killers"]), name
        assert (e["killers"] == ["*"]) == (e["kind"] != "single"), name


def test_check_killer_map_exit_codes(monkeypatch, tmp_path, capsys):
    ms = [_m("A")]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "KILLER_MAP", tmp_path / "k.json")
    (tmp_path / "tests").mkdir()
    monkeypatch.setattr(mc, "ROOT", tmp_path)
    assert mc.main(["--check-killer-map"]) == 1                                  # no map at all
    (tmp_path / "tests" / "test_A.py").write_text("")
    mc.write_killer_map(_map(ms, {"A": ["tests/test_A.py"]}), tmp_path / "k.json")
    assert mc.main(["--check-killer-map"]) == 0
    monkeypatch.setattr(mc, "MUTANTS", [_m("A", new="edited")])
    assert mc.main(["--check-killer-map"]) == 1
    assert "--build-killer-map" in capsys.readouterr().out


def test_the_written_map_is_deterministic_and_sorted(tmp_path):
    ms = [_m("B"), _m("A")]
    km = _map(ms)
    mc.write_killer_map(km, tmp_path / "a.json"); mc.write_killer_map(json.loads(json.dumps(km)), tmp_path / "b.json")
    assert (tmp_path / "a.json").read_text() == (tmp_path / "b.json").read_text()
    assert list(json.loads((tmp_path / "a.json").read_text())["mutants"]) == ["A", "B"]


def test_failed_test_files_are_parsed_from_pytest_output():
    out = ("..F\n=========== short test summary info ===========\nFAILED tests/server/test_gate.py::test_x[a b] - assert 1 == 2\n"
           "ERROR tests/proxy/test_p.py - ImportError: boom\nFAILED tests/server/test_gate.py::test_y\n1 failed\n")
    assert mc.failed_nodes(out) == ["tests/server/test_gate.py::test_x[a b]", "tests/proxy/test_p.py", "tests/server/test_gate.py::test_y"]
    assert mc.node_file("tests/server/test_gate.py::test_x[a b]") == "tests/server/test_gate.py"
    assert mc.failed_nodes("") == [] and mc.failed_nodes(None) == []
    vit = " FAIL  src/lib/drift.test.ts > drift > x\n FAIL  src/components/Inbox.test.tsx [ src/components/Inbox.test.tsx ]\n"
    assert mc.failed_vitest_files(vit) == ["frontend/src/components/Inbox.test.tsx", "frontend/src/lib/drift.test.ts"]


def test_a_witness_is_recorded_only_when_it_kills_the_mutant_on_its_own():
    m = _m("A")
    nodes = ["tests/server/test_a.py::t1", "tests/server/test_a.py::t2"]
    e = mc.classify_kill(m, nodes, alone_fails=lambda f: True, tier_of=lambda n: "push")
    assert (e["kind"], e["killers"], e["tier"], e["runner"], e["hash"]) == ("single", ["tests/server/test_a.py"], "push", "pytest", mc.mutant_hash(m))
    # killed in the whole suite but the file passes alone: a combination (order / pollution): any test change selects it
    e = mc.classify_kill(m, nodes, alone_fails=lambda f: False, tier_of=lambda n: "pr")
    assert (e["kind"], e["killers"]) == ("combination", ["*"])
    # a failure that names no test file: unknown, treated like a combination
    e = mc.classify_kill(m, [], alone_fails=lambda f: True, tier_of=lambda n: "push")
    assert (e["kind"], e["killers"], e["tier"]) == ("unknown", ["*"], "unknown")
    # the lowest tier of the failing tests is recorded (the earliest stage that runs the witness)
    e = mc.classify_kill(m, ["tests/a.py::s", "tests/a.py::p"], alone_fails=lambda f: True, tier_of=lambda n: "pr" if n.endswith("s") else "push")
    assert e["tier"] == "push"


def test_build_reattributes_only_missing_or_stale_entries(monkeypatch, tmp_path):
    ms = [_m("A"), _m("B"), _m("C")]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "ROOT", tmp_path); monkeypatch.setattr(mc, "KILLER_MAP", tmp_path / "k.json")
    (tmp_path / "tests").mkdir()
    for n in "ABC":
        (tmp_path / "tests" / f"test_{n}.py").write_text("")
    km = _map(ms, {n: [f"tests/test_{n}.py"] for n in "ABC"})
    km["mutants"]["B"]["hash"] = "0" * 64
    del km["mutants"]["C"]
    mc.write_killer_map(km, tmp_path / "k.json")
    seen = []
    monkeypatch.setattr(mc, "attribute", lambda mutants, jobs, on_done=None: seen.extend(m[0] for m in mutants) or
                        {m[0]: mc.make_entry(m, ["tests/test_new.py"]) for m in mutants})
    assert mc.main(["--build-killer-map"]) == 0
    assert sorted(seen) == ["B", "C"]
    out = json.loads((tmp_path / "k.json").read_text())
    assert out["mutants"]["A"]["killers"] == ["tests/test_A.py"] and out["mutants"]["B"]["killers"] == ["tests/test_new.py"]
    seen.clear()
    assert mc.main(["--build-killer-map", "--rebuild-all"]) == 0
    assert sorted(seen) == ["A", "B", "C"]


def test_a_survivor_during_attribution_fails_the_build_but_keeps_the_good_entries(monkeypatch, tmp_path):
    """A mutant nobody kills is a hole in the suite: RED. The attributed entries are still saved (a missing entry just means that mutant is
    always selected, so a partial map is safe), so a long build is not lost to one survivor."""
    ms = [_m("A"), _m("B")]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "ROOT", tmp_path); monkeypatch.setattr(mc, "KILLER_MAP", tmp_path / "k.json")
    monkeypatch.setattr(mc, "attribute", lambda mutants, jobs, on_done=None: {m[0]: (None if m[0] == "B" else mc.make_entry(m, ["tests/test_a.py"])) for m in mutants})
    assert mc.main(["--build-killer-map"]) == 1
    saved = json.loads((tmp_path / "k.json").read_text())
    assert list(saved["mutants"]) == ["A"]
    assert mc.select_changed(ms, set(), saved) == [ms[1]]          # the survivor has no entry, so it is selected whatever changed


def test_changed_since_uses_the_map_and_reports_the_selection(monkeypatch, capsys):
    ms = [_m("A"), _m("B")]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: _map(ms, {"A": ["tests/x/test_a.py"], "B": ["tests/x/test_b.py"]}))
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {"tests/x/test_b.py"})
    ran = []
    monkeypatch.setattr(mc, "run_backend", lambda ms_, s, st: ran.extend(m[0] for m in ms_))
    monkeypatch.setattr(mc, "run_frontend", lambda ms_, s, st: ran.extend(m[0] for m in ms_))
    assert mc.main(["--changed-since", "main"]) == 0
    assert ran == ["B"]
    assert "1 of 2 mutants selected" in capsys.readouterr().out


def test_the_full_run_ignores_the_map(monkeypatch):
    """The nightly / weekly safety net: no flag = every mutant, whatever the map says."""
    ms = [_m("A"), _m("B")]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: pytest.fail("the full run must not read the map"))
    ran = []
    monkeypatch.setattr(mc, "run_backend", lambda ms_, s, st: ran.extend(m[0] for m in ms_))
    monkeypatch.setattr(mc, "run_frontend", lambda ms_, s, st: ran.extend(m[0] for m in ms_))
    assert mc.main([]) == 0 and ran == ["A", "B"]


# ---------------------------------------------------------------------------------------------------------------------------------------
# The UNMUTATED backend tree must be green. (A copy that lacked frontend/src made tests/contract fail in EVERY tree, so with `-x` every
# mutant read as KILLED by a test that failed for the wrong reason: a vacuous check.)
# ---------------------------------------------------------------------------------------------------------------------------------------
def _pytest_in(tree, *args):
    return subprocess.run([mc.sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *args], cwd=tree, capture_output=True,
                          text=True, timeout=600)


def test_the_unmutated_backend_tree_has_what_the_tests_read_and_passes_them():
    with mc.backend_tree() as tree:
        for rel in ("frontend/src/lib/drift.ts", "frontend/src/components/DriftMonitor.tsx", "frontend/src/types/contracts.ts"):
            assert (tree / rel).exists(), rel
        assert not (tree / "frontend" / "node_modules").exists() and not (tree / "frontend" / "dist").exists()
        p = _pytest_in(tree, "tests/contract", "tests/test_gate_lib.py", "tests/server/test_gate.py")
        assert p.returncode == 0, p.stdout[-2000:]


def test_a_tree_missing_frontend_src_is_red_so_the_guard_would_refuse_it():
    with mc.backend_tree() as tree:
        shutil_rmtree(tree / "frontend" / "src")
        assert _pytest_in(tree, "tests/contract").returncode != 0


def shutil_rmtree(p):
    import shutil
    shutil.rmtree(p)


def test_every_path_the_backend_tests_read_outside_tests_exists_in_the_tree():
    """Static cross-tree reads: any quoted repo-relative path to a top-level dir or file that the tests mention must exist in a clean copy."""
    import re
    wanted = set()
    for f in (ROOT / "tests").rglob("*.py"):
        for mt in re.finditer(r'["\'](frontend/src/[\w./-]+|docs/[\w./-]+\.md|DECISIONS\.md|scripts/[\w./-]+\.(?:py|sh)|\.github/[\w./-]+)["\']', f.read_text()):
            if (ROOT / mt.group(1)).exists():
                wanted.add(mt.group(1))
    with mc.backend_tree() as tree:
        missing = sorted(w for w in wanted if not (tree / w).exists())
    assert missing == []


def test_the_clean_tree_guard_refuses_a_red_tree_before_any_mutant_runs(monkeypatch):
    m = _m("A")
    mc._CLEAN.clear()
    monkeypatch.setattr(mc, "run_clean_suite", lambda tree: (1, "FAILED tests/contract/test_ui_threshold.py::t - assert 0"))
    monkeypatch.setattr(mc, "mutated_backend_tree", lambda m_: pytest.fail("no mutant may be applied on a red clean tree"))
    with pytest.raises(SystemExit) as e:
        mc.run_backend([m], [], [])
    assert "UNMUTATED" in str(e.value) and "test_ui_threshold" in str(e.value)
    mc._CLEAN.clear()
    with pytest.raises(SystemExit):
        mc._attribute_one(m, False, lambda n: "push")
    mc._CLEAN.clear()
    monkeypatch.setattr(mc, "MUTANTS", [m]); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "attribute", lambda *a: pytest.fail("no attribution on a red clean tree"))
    with pytest.raises(SystemExit):
        mc.build_killer_map(True, 1)
    mc._CLEAN.clear()


def test_the_clean_tree_guard_runs_once_per_run_and_lets_a_green_tree_through(monkeypatch):
    mc._CLEAN.clear()
    calls = []
    monkeypatch.setattr(mc, "run_clean_suite", lambda tree: calls.append(1) or (0, ""))
    mc.require_clean_backend_tree(); mc.require_clean_backend_tree()
    assert len(calls) == 1
    mc._CLEAN.clear()


def test_changed_since_with_no_selected_mutant_does_not_pay_for_the_clean_tree_check(monkeypatch):
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: None)
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {"README.md"})
    monkeypatch.setattr(mc, "require_clean_backend_tree", lambda: pytest.fail("nothing selected: no clean-tree run"))
    assert mc.main(["--changed-since", "main"]) == 0


def test_every_suite_run_of_the_mutation_check_is_marked_so_map_tests_skip(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(mc.subprocess, "run", lambda cmd, **kw: seen.append(kw.get("env")) or subprocess.CompletedProcess(cmd, 0, stdout=""))
    mc.run_suite_detail(tmp_path)
    mc.run_clean_suite(tmp_path)
    assert len(seen) == 3 and all(e and e.get("MUTATION_CHECK_RUN") == "1" for e in seen)


@pytest.mark.parametrize("jobs", [1, 3])
def test_run_backend_collects_survivors_and_stale_serially_and_in_parallel(monkeypatch, jobs):
    ms = [_m("K"), _m("S"), _m("T")]
    monkeypatch.setattr(mc, "_JOBS", jobs)
    monkeypatch.setattr(mc, "_run_one_backend", lambda m: {"K": ("killed", "KILLED  K"), "S": ("survived", "SURVIVED  S"), "T": ("stale", "T: stale")}[m[0]])
    surv, stale = [], []
    mc.run_backend(ms, surv, stale)
    assert surv == ["S"] and stale == ["T: stale"]


def test_a_resumable_run_logs_each_verdict_and_skips_recorded_mutants(monkeypatch, tmp_path):
    """A restart must not lose hours: every verdict is appended to the log as it completes; a rerun skips mutants whose (name, hash) is logged."""
    log = tmp_path / "v.jsonl"
    ms = [_m("K"), _m("S"), _m("N")]
    monkeypatch.setattr(mc, "_JOBS", 1); monkeypatch.setattr(mc, "_LOG", log)
    ran = []
    verdict = {"K": ("killed", "KILLED  K   [tests/a.py]"), "S": ("survived", "SURVIVED  S"), "N": ("killed", "KILLED  N")}
    monkeypatch.setattr(mc, "_run_one_backend", lambda m: ran.append(m[0]) or verdict[m[0]])
    surv, stale = [], []
    mc.run_backend(ms[:2], surv, stale)
    assert ran == ["K", "S"] and surv == ["S"]
    ran.clear(); surv.clear()
    mc.run_backend(ms, surv, stale)                         # resumed: K and S are in the log
    assert ran == ["N"] and surv == ["S"]                    # a logged survivor is still reported, not forgotten
    assert len(log.read_text().splitlines()) == 3
    ran.clear(); surv.clear()
    changed = [_m("K", new="edited"), ms[1], ms[2]]          # a changed definition invalidates its logged verdict
    mc.run_backend(changed, surv, stale)
    assert ran == ["K"]


def test_a_stale_mutant_is_never_logged_as_done(monkeypatch, tmp_path):
    monkeypatch.setattr(mc, "_JOBS", 1); monkeypatch.setattr(mc, "_LOG", tmp_path / "v.jsonl")
    monkeypatch.setattr(mc, "_run_one_backend", lambda m: ("stale", "stale!"))
    st = []
    mc.run_backend([_m("T")], [], st)
    assert st == ["stale!"] and not (tmp_path / "v.jsonl").exists()


def test_the_build_saves_the_map_as_attribution_proceeds_and_rebuild_all_starts_empty(monkeypatch, tmp_path):
    ms = [_m("A"), _m("B")]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "ROOT", tmp_path); monkeypatch.setattr(mc, "KILLER_MAP", tmp_path / "k.json")
    (tmp_path / "tests").mkdir()
    mc.write_killer_map(_map(ms, {"A": ["tests/old_a.py"], "B": ["tests/old_b.py"]}), tmp_path / "k.json")
    snapshots = []

    def fake_attribute(mutants, jobs, on_done=None):
        snapshots.append(sorted(json.loads((tmp_path / "k.json").read_text())["mutants"]))     # what is on disk BEFORE any attribution
        for m in mutants:
            on_done(m[0], mc.make_entry(m, ["tests/new.py"]))
            snapshots.append(sorted(json.loads((tmp_path / "k.json").read_text())["mutants"]))
        return {m[0]: mc.make_entry(m, ["tests/new.py"]) for m in mutants}
    monkeypatch.setattr(mc, "attribute", fake_attribute)
    assert mc.main(["--build-killer-map", "--rebuild-all"]) == 0
    assert snapshots == [[], ["A"], ["A", "B"]]              # the old (possibly wrong) map is gone at once; a restart resumes incrementally


@needs_committed_map
def test_every_witness_file_exists_and_is_collected_by_the_default_selection():
    """A witness that is deselected (reality/claude_live markers) or has no test would 'kill' nothing on the clean tree either: each file
    must yield at least one test under pytest.ini's default -m. (That they PASS on the clean tree is the clean-tree guard's whole-suite run.)"""
    km = mc.load_killer_map()
    files = sorted({k for e in km["mutants"].values() if e["runner"] == "pytest" for k in e["killers"] if k != mc.ANY_TEST})
    assert files
    for d in sorted({f.rsplit("/", 1)[0] for f in files}):                       # one run per directory (conftest module names collide)
        group = [f for f in files if f.rsplit("/", 1)[0] == d]
        p = subprocess.run([mc.sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *group], cwd=ROOT,
                           capture_output=True, text=True, timeout=300)
        assert p.returncode == 0, p.stdout[-1500:]
        collected = {line.split("::")[0] for line in p.stdout.splitlines() if "::" in line}
        collected |= {line.rsplit(":", 1)[0] for line in p.stdout.splitlines() if re.match(r"^\S+\.py: \d+$", line)}   # -q counts per file when many
        assert collected == set(group), sorted(set(group) - collected)


@needs_committed_map
def test_the_witnesses_are_spread_over_many_real_test_files_not_one_vacuous_failure():
    """A witness that kills a large part of all mutants is the signature of a test failing in EVERY tree (the old tests/contract failure kept
    223 of 277 mutants 'killed'). No file may be the witness of more than a fifth of the mutants, and there must be many witness files."""
    import collections
    km = mc.load_killer_map()
    c = collections.Counter(k for e in km["mutants"].values() if e["kind"] == "single" for k in e["killers"])
    assert len(c) >= 30, len(c)
    assert max(c.values()) <= len(km["mutants"]) // 5, c.most_common(3)


# ---------------------------------------------------------------------------------------------------------------------------------------
# --shard i/N: the full check does not fit one CI job (hours), so it is split by a stable hash of the mutant name.
# ---------------------------------------------------------------------------------------------------------------------------------------
def test_every_mutant_is_in_exactly_one_shard_and_the_split_is_stable():
    import hashlib
    names = [m[0] for m in mc.MUTANTS + mc.FRONTEND_MUTANTS]
    for n in (1, 2, 4, 7):
        shards = [[x for x in names if mc.in_shard(x, i, n)] for i in range(1, n + 1)]
        assert sorted(sum(shards, [])) == sorted(names), n                       # a partition: no mutant lost, none twice
        if n > 1:
            assert min(map(len, shards)) > 0 and max(map(len, shards)) <= 2 * len(names) // n + 5, [len(s) for s in shards]
    # stable across runs and machines (not Python's per-process hash()): defined by sha256 of the name
    assert mc.shard_of("B1 gate ignores node_id", 4) == int(hashlib.sha256(b"B1 gate ignores node_id").hexdigest(), 16) % 4
    assert mc.shard_of("B1 gate ignores node_id", 4) == mc.shard_of("B1 gate ignores node_id", 4)


def test_a_shard_argument_is_validated():
    for bad in ("0/4", "5/4", "x", "1/0", "2"):
        with pytest.raises(SystemExit):
            mc.main(["--shard", bad])


def test_a_sharded_full_run_runs_only_its_mutants_and_every_shard_together_run_all(monkeypatch):
    ms = [_m(f"M{i}") for i in range(10)]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: pytest.fail("the full run must not read the map"))
    seen = []
    monkeypatch.setattr(mc, "run_backend", lambda ms_, s, st: seen.append([m[0] for m in ms_]))
    monkeypatch.setattr(mc, "run_frontend", lambda *a: None)
    for i in (1, 2, 3):
        assert mc.main(["--shard", f"{i}/3"]) == 0
    assert sorted(sum(seen, [])) == sorted(m[0] for m in ms) and len(seen) == 3


# ---------------------------------------------------------------------------------------------------------------------------------------
# Second review: exit code 5 ("no tests collected") is NOT a kill; a kill needs a named failing test or a timeout; a hung mutant is killed.
# ---------------------------------------------------------------------------------------------------------------------------------------
def test_a_candidate_group_that_collects_nothing_is_not_a_kill(monkeypatch, tmp_path):
    """pytest exits 5 for a group made only of tests deselected by `-m "not reality and not claude_live"` (tests/live, hostile, ...): the mutant used
    to read KILLED in seconds and the later groups never ran."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_gate_x.py").write_text("")
    calls, rcs = [], [5, 0, 0]
    monkeypatch.setattr(mc.subprocess, "run", lambda cmd, **kw: calls.append(cmd[cmd.index("no:cacheprovider") + 1:]) or subprocess.CompletedProcess(cmd, rcs.pop(0)))
    assert mc.run_suite_detail(tmp_path, "server/gate.py")[0] == 0 and len(calls) == 3
    rcs[:] = [5, 5, 1]
    assert mc.run_suite_detail(tmp_path, "server/gate.py")[0] == 1                 # any OTHER non-zero code still stops the run as a kill


def test_a_real_group_of_only_deselected_tests_does_not_make_a_no_op_mutant_read_killed(tmp_path, monkeypatch):
    """Real pytest, real subprocesses: the candidate group (tests/live/test_gate_live.py) is entirely deselected by the default -m, exits 5, and
    the no-op mutant must read SURVIVED after the rest of the suite passes."""
    (tmp_path / "pytest.ini").write_text('[pytest]\naddopts = -q -m "not reality and not claude_live"\nmarkers =\n    reality: r\n    claude_live: c\n')
    (tmp_path / "tests" / "live").mkdir(parents=True)
    (tmp_path / "tests" / "docker").mkdir()
    (tmp_path / "server").mkdir()
    (tmp_path / "server" / "gate.py").write_text("X = 1\n")
    (tmp_path / "tests" / "live" / "test_gate_live.py").write_text("import pytest\n@pytest.mark.reality\ndef test_live():\n    assert False\n")
    (tmp_path / "tests" / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    name = mc.NESTED_SUITE_TEST.split("::")[1]
    (tmp_path / "tests" / "docker" / "test_image_context.py").write_text(f"def {name}():\n    assert True\n")
    rc, out = mc.run_suite_detail(tmp_path, "server/gate.py")
    assert rc == 0, out

    from contextlib import contextmanager

    @contextmanager
    def fake_tree(m):
        yield tmp_path
    monkeypatch.setattr(mc, "mutated_backend_tree", fake_tree)
    status, line = mc._run_one_backend(_m("NOOP", "server/gate.py"))
    assert status == "survived" and line.startswith("SURVIVED")


def test_a_mutant_reads_killed_only_with_a_named_failing_test_or_a_timeout(monkeypatch):
    from contextlib import contextmanager

    @contextmanager
    def fake_tree(m):
        yield Path("/nonexistent")
    monkeypatch.setattr(mc, "mutated_backend_tree", fake_tree)
    monkeypatch.setattr(mc, "run_suite_detail", lambda tree, rel: (4, "ERROR: usage: nothing named"))
    status, line = mc._run_one_backend(_m("A"))
    assert status == "stale" and "inconclusive" in line                                   # exit 4 with no failing test: not a kill
    monkeypatch.setattr(mc, "run_suite_detail", lambda tree, rel: (1, "FAILED tests/server/test_a.py::t - assert 0\n"))
    assert mc._run_one_backend(_m("A")) == ("killed", "KILLED    A   [tests/server/test_a.py]")


def test_a_hung_mutant_is_killed_by_its_timeout_and_a_logged_run_goes_on(monkeypatch, tmp_path):
    from contextlib import contextmanager

    @contextmanager
    def fake_tree(m):
        yield Path("/nonexistent")

    def hang(tree, rel):
        raise subprocess.TimeoutExpired("pytest", 1800)
    monkeypatch.setattr(mc, "mutated_backend_tree", fake_tree)
    monkeypatch.setattr(mc, "run_suite_detail", hang)
    status, line = mc._run_one_backend(_m("HUNG"))
    assert status == "killed" and "timeout" in line
    monkeypatch.setattr(mc, "_LOG", tmp_path / "v.jsonl"); monkeypatch.setattr(mc, "_JOBS", 1)
    surv, stale = [], []
    mc.run_backend([_m("HUNG"), _m("HUNG2")], surv, stale)
    assert surv == [] and stale == [] and len((tmp_path / "v.jsonl").read_text().splitlines()) == 2


def test_the_alone_run_of_a_witness_treats_exit_5_as_not_failing():
    assert mc.fails(1) and mc.fails(2) and mc.fails(4) and not mc.fails(0) and not mc.fails(5)


def test_run_clean_suite_returns_the_real_exit_code_of_a_red_tree():
    """S2: a failing test inside a backend_tree() copy must make run_clean_suite non-zero and name the test (forcing it to return 0 is caught)."""
    with mc.backend_tree() as tree:
        (tree / "tests" / "test_zz_red_tree.py").write_text("def test_red():\n    assert False\n")
        rc, out = mc.run_clean_suite(tree, ["tests/test_zz_red_tree.py"])
        assert rc != 0 and "test_zz_red_tree.py" in " ".join(mc.failed_nodes(out))
        (tree / "tests" / "test_zz_red_tree.py").write_text("def test_red():\n    assert True\n")
        assert mc.run_clean_suite(tree, ["tests/test_zz_red_tree.py"])[0] == 0


def test_a_file_named_only_in_a_docstring_or_a_comment_is_not_read_by_that_test():
    src = ('"""Module doc: see docs/GONE.md."""\n\n# also docs/GONE.md in a comment\n\ndef test_a():\n    """docstring names docs/GONE.md"""\n'
           '    open("docs/READ.md")  # trailing note about OTHER.md\n')
    out = mc._without_docstrings(src)
    assert "GONE.md" not in out and "OTHER.md" not in out and "docs/READ.md" in out
    assert mc._readers("docs/READ.md", {"tests/test_a.py": out}) == {"tests/test_a.py"}
    assert mc._readers("docs/GONE.md", {"tests/test_a.py": out}) == set()


def test_a_test_that_globs_a_directory_reads_every_file_in_it():
    t = {"tests/test_g.py": 'for f in (ROOT / "docs").glob("*.md"): pass', "tests/test_h.py": 'x = "docs are nice"'}
    assert mc._readers("docs/ANYTHING.md", t) == {"tests/test_g.py"}


IMPORT_TEXTS = {"tests/server/test_hub.py": "def helper(): pass", "tests/server/test_policy.py": "from test_hub import helper",
                "tests/server/test_deep.py": "from test_policy import x", "tests/server/test_other.py": "import unrelated",
                "tests/server/test_hubris.py": "x = 1  # test_hub_extra is only a prefix"}


def _importers(monkeypatch):
    monkeypatch.setattr(mc, "_test_texts", lambda: IMPORT_TEXTS)
    ms = [_m("HUB"), _m("POL"), _m("DEEP"), _m("OTH"), _m("PREF")]
    km = _map(ms, {"HUB": ["tests/server/test_hub.py"], "POL": ["tests/server/test_policy.py"], "DEEP": ["tests/server/test_deep.py"],
                   "OTH": ["tests/server/test_other.py"], "PREF": ["tests/server/test_hubris.py"]})
    return ms, km


def test_a_changed_test_module_also_selects_the_mutants_of_the_tests_that_import_it(monkeypatch):
    """Test modules import each other (`from test_inbox_hub import Rig, call`): weakening a helper there weakens every importing witness."""
    ms, km = _importers(monkeypatch)
    assert _names(mc.select_changed(ms, {"tests/server/test_hub.py"}, km)) == ["HUB", "POL", "DEEP"]      # transitive; a prefix name is not an import
    assert _names(mc.select_changed(ms, {"tests/server/test_policy.py"}, km)) == ["POL", "DEEP"]
    assert _names(mc.select_changed(ms, {"tests/server/test_other.py"}, km)) == ["OTH"]


def test_the_import_closure_is_depth_capped_but_never_drops_direct_importers(monkeypatch):
    chain = {f"tests/test_m{i}.py": (f"from test_m{i - 1} import x" if i else "") for i in range(8)}
    monkeypatch.setattr(mc, "_test_texts", lambda: chain)
    got = mc.import_closure({"tests/test_m0.py"}, chain)
    assert {"tests/test_m0.py", "tests/test_m1.py", "tests/test_m2.py", "tests/test_m3.py"} <= got and "tests/test_m7.py" not in got


def test_the_cap_message_says_what_actually_triggered_the_selection(monkeypatch, capsys):
    ms = [_m(f"M{i}", f"server/m{i}.py") for i in range(5)]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: _map(ms))
    monkeypatch.setattr(mc, "run_backend", lambda *a: pytest.fail("a capped run must not start"))
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {f"server/m{i}.py" for i in range(5)})
    assert mc.main(["--changed-since", "main", "--max-selected", "2"]) == 1
    out = capsys.readouterr().out
    assert "5 > 2" in out and "5 changed mutant target" in out and "shared test support" not in out
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {"pytest.ini"})
    assert mc.main(["--changed-since", "main", "--max-selected", "2"]) == 1
    assert "shared test support" in capsys.readouterr().out


# ---------------------------------------------------------------------------------------------------------------------------------------
# Ticket 1: a selection above the PR-tier cap is RED unless the SAME commit already has a green full (sharded) mutation run; dependency-only
# changes select a smoke subset instead of every mutant.
# ---------------------------------------------------------------------------------------------------------------------------------------
SHA = "a" * 40


def _capped(monkeypatch, capsys, env, argv_extra=()):
    ms = [_m(f"M{i}", f"server/m{i}.py") for i in range(5)]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: _map(ms))
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {f"server/m{i}.py" for i in range(5)})
    ran = []
    monkeypatch.setattr(mc, "run_backend", lambda ms_, s, st: ran.extend(m[0] for m in ms_))
    monkeypatch.setattr(mc, "run_frontend", lambda *a: None)
    for k in ("GATE_MUTATION_PROOF", "GATE_HEAD_SHA"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    rc = mc.main(["--changed-since", "main", "--max-selected", "2", *argv_extra])
    return rc, capsys.readouterr().out, ran


def test_a_capped_selection_without_proof_is_red_and_says_exactly_what_to_run(monkeypatch, capsys):
    rc, out, ran = _capped(monkeypatch, capsys, {})
    assert rc == 1 and ran == []
    assert "5 > 2" in out and "gh workflow run gate" in out and "-f tier=full" in out and "mutation" in out and "Run workflow" in out


def test_a_green_full_run_for_this_very_commit_lets_a_capped_selection_through_loudly(monkeypatch, capsys):
    rc, out, ran = _capped(monkeypatch, capsys, {"GATE_MUTATION_PROOF": f"123456:{SHA}", "GATE_HEAD_SHA": SHA})
    assert rc == 0 and ran == []                                  # nothing is re-run: the full run IS the check
    assert "PROOF" in out and "123456" in out and SHA[:12] in out and "5 > 2" in out


@pytest.mark.parametrize("proof, head", [(f"123456:{SHA}", "b" * 40), (f"123456:{SHA}", ""), ("garbage", SHA), ("123456:short", "short"),
                                        (f":{SHA}", SHA), ("", SHA)])
def test_a_proof_for_another_commit_or_a_malformed_one_is_still_red(monkeypatch, capsys, proof, head):
    rc, out, ran = _capped(monkeypatch, capsys, {"GATE_MUTATION_PROOF": proof, "GATE_HEAD_SHA": head})
    assert rc == 1 and ran == [] and "gh workflow run gate" in out


def test_no_cap_in_force_means_no_proof_is_needed(monkeypatch, capsys):
    ms = [_m("A")]
    monkeypatch.setattr(mc, "MUTANTS", ms); monkeypatch.setattr(mc, "FRONTEND_MUTANTS", [])
    monkeypatch.setattr(mc, "load_killer_map", lambda path=None: _map(ms))
    monkeypatch.setattr(mc, "changed_files", lambda ref, root=None: {"server/a.py"})
    monkeypatch.setattr(mc, "run_backend", lambda ms_, s, st: None); monkeypatch.setattr(mc, "run_frontend", lambda *a: None)
    assert mc.main(["--changed-since", "main", "--max-selected", "5"]) == 0


def _dep_map():
    ms = [_m(f"M{i}") for i in range(9)] + [_m("ANY"), _m("F", "frontend/src/a.tsx")]
    killers = {f"M{i}": [f"tests/x/test_{i // 3}.py"] for i in range(9)}                 # three witness files, three mutants each
    killers["ANY"] = ["*"]
    km = _map(ms, killers)
    km["mutants"]["ANY"]["kind"] = "combination"
    km["mutants"]["F"] = mc.make_entry(ms[-1], ["frontend/src/a.test.tsx"], runner="vitest")
    return ms, km


def test_a_dependency_only_change_selects_a_smoke_subset_one_mutant_per_witness_file(monkeypatch):
    """requirements*.txt cannot weaken a test the way an edit can: it can only change how the witnesses behave. Every witness file must still be
    exercised once (plus every `*` mutant), not all of the pytest mutants."""
    monkeypatch.setattr(mc, "_test_texts", lambda: {})
    ms, km = _dep_map()
    got = _names(mc.select_changed(ms, {"requirements-dev.txt"}, km))
    assert got == ["M0", "M3", "M6", "ANY"]                      # the first mutant of each witness file, and the combination mutant
    assert _names(mc.select_changed(ms, {"requirements.txt", "pytest.ini"}, km)) == [m[0] for m in ms if m[0] != "F"]    # pytest.ini wins: everything


@needs_committed_map
def test_the_real_map_dependency_smoke_subset_fits_under_the_pr_cap_and_covers_every_witness_file():
    km = mc.load_killer_map()
    allm = mc.MUTANTS + mc.FRONTEND_MUTANTS
    sel = {m[0] for m in mc.select_changed(allm, {"requirements-dev.txt"}, km)}
    files = {k for e in km["mutants"].values() if e["runner"] == "pytest" for k in e["killers"] if k != mc.ANY_TEST}
    got = {k for n in sel for k in km["mutants"][n]["killers"]}
    assert files <= got and len(sel) < len([m for m in allm if km["mutants"][m[0]]["runner"] == "pytest"])
