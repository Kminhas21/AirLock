"""GATE_TIER=push|pr|full|weekly (scripts/verify.sh, scripts/gate_lib.sh, DECISIONS.md D30, docs/TESTING_REALITY.md "CI tiers").

Two promises are checked here, from what verify.sh WOULD run (GATE_LIST=1 lists every stage of a tier with its command, runs nothing):
  * each tier runs exactly its stages: nothing the tier owns is dropped, nothing research leaks into full, and the tiers nest;
  * every collected pytest test is selected by at least one pytest stage of some tier (nothing orphaned), and the backend pytest stages
    of the tiers never select the same test twice.
"""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from _pytest.mark.expression import Expression

ROOT = Path(__file__).resolve().parent.parent
VERIFY = ROOT / "scripts" / "verify.sh"

# stage-name prefixes per tier, in addition to everything of the tier below it (each prefix must start exactly one stage)
PUSH = ["preflight", "mutation targets are current", "live coverage map, static", "backend pytest, fast", "seismograph legacy",
        "frontend typecheck", "frontend lint", "frontend unit tests", "frontend build"]
PR = ["backend pytest, slow", "reality: hostile", "reality: real MCP servers", "reality: hub under concurrent load",
      "reality: live workflows", "live coverage proven", "browser e2e", "browser replay parity: action_sim", "browser inbox (",
      "browser inbox policy", "browser operator UI", "browser boundary", "browser identity"]
PR_ONLY = ["mutation check, changed files only"]                 # full runs the whole mutation check instead
FULL = ["mutation check (tests must catch"]
FULL_OPT_IN = ["docker:", "user journeys", "claude code:"]        # full and weekly, only with RUN_DOCKER_TESTS / RUN_JOURNEY_TESTS / RUN_CLAUDE_TESTS
WEEKLY = ["backend pytest, research", "browser replay parity: learned", "browser replay parity: registry (", "browser replay parity: registry_learned (",
          "browser replay parity: registry_learned_e", "browser replay parity: union", "replay registry is current", "v3 replay registry is current",
          "browser registry UI (", "browser registry UI v3", "browser registry UI union"]
EXPECTED = {"push": PUSH, "pr": PUSH + PR + PR_ONLY, "full": PUSH + PR + FULL, "weekly": PUSH + PR + FULL + WEEKLY}
OPT_IN = {"RUN_DOCKER_TESTS": "1", "RUN_JOURNEY_TESTS": "1", "RUN_CLAUDE_TESTS": "1"}


def listed(tier: str | None, tmp_path: Path, **env) -> tuple[subprocess.CompletedProcess, list[tuple[str, list[str]]]]:
    """(result, [(stage name, argv)]) of `GATE_LIST=1 bash scripts/verify.sh`, run from a copy of the two gate scripts in tmp_path with a
    fake frontend/node_modules and a fake Chromium, so every branch is visible (the mutation check's tree copies have no frontend)."""
    tree = tmp_path / "tree"
    (tree / "scripts").mkdir(parents=True, exist_ok=True)
    for name in ("verify.sh", "gate_lib.sh"):
        (tree / "scripts" / name).write_text((VERIFY.parent / name).read_text())
    (tree / "frontend" / "node_modules").mkdir(parents=True, exist_ok=True)
    (tree / "frontend" / "package.json").write_text('{"scripts": {"test": "vitest run"}}')
    chromium = tmp_path / "chromium"
    chromium.write_text("#!/bin/sh\nexit 0\n")
    chromium.chmod(0o755)
    full = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", str(tmp_path)), "GATE_LIST": "1", "CHROMIUM_PATH": str(chromium),
            "GATE_BASE": "HEAD", "TMPDIR": str(tmp_path), **env}
    if tier is not None:
        full["GATE_TIER"] = tier
    r = subprocess.run(["bash", str(tree / "scripts" / "verify.sh")], capture_output=True, text=True, env=full, timeout=60)
    stages = []
    for line in r.stdout.splitlines():
        if line.startswith("STAGE "):
            name, _, cmd = line[len("STAGE "):].partition(" :: ")
            stages.append((name, shlex.split(cmd)))
    return r, stages


def _match(stages, keywords):
    names = [n for n, _ in stages]
    count = {k: sum(n.startswith(k) for n in names) for k in keywords}
    problems = [f"{k!r} starts {c} stages" for k, c in count.items() if c != 1]
    problems += [f"stage not owned by this tier: {n!r}" for n in names if not any(n.startswith(k) for k in keywords)]
    return problems


@pytest.mark.parametrize("tier", sorted(EXPECTED))
def test_each_tier_runs_exactly_its_stages_with_every_opt_in(tier, tmp_path):
    r, stages = listed(tier, tmp_path, **OPT_IN)
    assert r.returncode == 2 and "GATE: LISTED" in r.stdout and "GATE: GREEN" not in r.stdout, r.stdout + r.stderr
    opt = FULL_OPT_IN if tier in ("full", "weekly") else []
    assert _match(stages, EXPECTED[tier] + opt) == []


@pytest.mark.parametrize("tier", ["full", "weekly"])
def test_opt_in_stages_stay_opt_in(tier, tmp_path):
    _, stages = listed(tier, tmp_path)
    assert _match(stages, EXPECTED[tier]) == []


def test_the_default_tier_is_full(tmp_path):
    assert [n for n, _ in listed(None, tmp_path)[1]] == [n for n, _ in listed("full", tmp_path)[1]]


def test_an_unknown_tier_is_red_before_any_stage(tmp_path):
    r, stages = listed("nightly", tmp_path)
    assert r.returncode != 0 and stages == [] and "GATE_TIER" in r.stdout


def test_live_coverage_proof_runs_only_after_all_four_reality_stages(tmp_path):
    for tier in EXPECTED:
        names = [n for n, _ in listed(tier, tmp_path)[1]]
        proof = [i for i, n in enumerate(names) if n.startswith("live coverage proven")]
        reality = [i for i, n in enumerate(names) if n.startswith("reality:")]
        assert (proof == [] and reality == []) or (len(proof) == 1 and len(reality) == 4 and max(reality) < proof[0]), (tier, names)


def test_the_changed_files_mutation_stage_uses_the_base_ref_or_origins_default_branch(tmp_path):
    _, stages = listed("pr", tmp_path, GATE_BASE="origin/develop")
    argv = next(a for n, a in stages if n.startswith("mutation check, changed"))
    assert argv[-2:] == ["--changed-since", "origin/develop"]
    _, stages = listed("pr", tmp_path, GATE_BASE="")
    argv = next(a for n, a in stages if n.startswith("mutation check, changed"))
    assert argv[-2:] == ["--changed-since", "@origin"]


# ----------------------------------------------------------------------------- nothing orphaned
_COLLECT = r"""
import json, sys, pytest
class P:
    items = []
    @pytest.hookimpl(tryfirst=True)
    def pytest_collection_modifyitems(self, items):
        P.items = [(i.nodeid, sorted({m.name for m in i.iter_markers()})) for i in items]
rc = pytest.main(["--collect-only", "-q", "-m", "", "-p", "no:cacheprovider", "-p", "no:xdist"], plugins=[P()])
json.dump({"rc": int(rc), "items": P.items}, open(sys.argv[1], "w"))
"""


def _pytest_selections(stages):
    """(stage name, -m expression, paths) for every `python -m pytest` stage; no -m = pytest.ini's addopts expression."""
    default = next(l for l in (ROOT / "pytest.ini").read_text().splitlines() if l.startswith("addopts"))
    default = shlex.split(default.split("=", 1)[1])
    out = []
    for name, argv in stages:
        if "pytest" not in argv:
            continue
        args = argv[argv.index("pytest") + 1:]
        expr = next((args[i + 1] for i, a in enumerate(args) if a == "-m"), default[default.index("-m") + 1])
        skip = {"-m", "-n", "-p", "--junitxml"}
        paths = [a for i, a in enumerate(args) if not a.startswith("-") and (i == 0 or args[i - 1] not in skip)]
        out.append((name, expr, paths))
    return out


def test_every_collected_test_is_selected_by_a_tier_and_backend_stages_never_overlap(tmp_path):
    _, stages = listed("weekly", tmp_path, **OPT_IN)
    sel = _pytest_selections(stages)
    assert len(sel) >= 8, sel          # 3 backend stages + 4 reality stages + claude
    out = tmp_path / "items.json"
    subprocess.run([sys.executable, "-c", _COLLECT, str(out)], cwd=ROOT, capture_output=True, text=True, timeout=300)
    data = json.loads(out.read_text())
    assert data["rc"] == 0 and len(data["items"]) > 1000, data["rc"]
    orphans, twice = [], []
    for nodeid, markers in data["items"]:
        hits = [name for name, expr, paths in sel
                if Expression.compile(expr).evaluate(lambda m, *_, **__: m in markers)
                and (not paths or any(nodeid == p or nodeid.startswith(p.rstrip("/") + "/") or nodeid.startswith(p + "::") for p in paths))]
        if not hits:
            orphans.append(nodeid)
        if sum(h.startswith("backend pytest") for h in hits) > 1:
            twice.append((nodeid, hits))
    assert orphans == [], f"{len(orphans)} test(s) no tier runs, e.g. {orphans[:5]}"
    assert twice == [], twice[:5]


def test_research_and_slow_marks_are_where_the_tiers_say():
    """The shipped default's parity stays on PRs; the research detectors' parity is weekly (DECISIONS.md D30)."""
    mp = (ROOT / "tests/e2e/test_monitor_parity.py").read_text()
    assert 'marks=pytest.mark.slow if mode == "action_sim" else pytest.mark.research' in mp
    for f in ("test_registry_parity.py", "test_registry_parity_union.py", "test_registry_parity_v3.py"):
        assert "pytestmark = pytest.mark.research" in (ROOT / "tests/e2e" / f).read_text(), f


def test_the_ci_workflow_is_not_git_ignored(tmp_path):
    """.gitignore ignores every dotfile (`.*`): without an exception .github/workflows/ci.yml could never be committed."""
    assert (ROOT / ".github/workflows/ci.yml").is_file()
    repo = tmp_path / "r"
    (repo / ".github/workflows").mkdir(parents=True)
    (repo / ".gitignore").write_text((ROOT / ".gitignore").read_text())
    (repo / ".github/workflows/ci.yml").write_text("x")
    (repo / ".env").write_text("x")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    ignored = lambda p: subprocess.run(["git", "-C", str(repo), "check-ignore", "-q", p]).returncode == 0
    assert not ignored(".github/workflows/ci.yml")
    assert ignored(".env")                        # the exception does not un-ignore secrets


# ----------------------------------------------------------------------------- the opt-in non-root pass (GATE_AS_USER=1, scripts/run_nonroot.sh)
@pytest.mark.parametrize("tier", sorted(EXPECTED))
def test_the_nonroot_stage_is_not_in_any_default_tier(tier, tmp_path):
    _, stages = listed(tier, tmp_path, **OPT_IN)
    assert not [n for n, _ in stages if "non-root" in n] and not [a for _, a in stages if "run_nonroot.sh" in " ".join(a)]


@pytest.mark.parametrize("tier", sorted(EXPECTED))
def test_gate_as_user_adds_exactly_one_nonroot_stage_and_nothing_else(tier, tmp_path):
    _, base = listed(tier, tmp_path)
    r, with_user = listed(tier, tmp_path, GATE_AS_USER="1")
    assert r.returncode == 2 and "GATE: LISTED" in r.stdout
    base_names = [n for n, _ in base]
    extra = [s for s in with_user if s[0] not in base_names]          # argv holds a fresh mktemp dir per run: compare stage names
    assert len(extra) == 1 and [n for n in base_names if n not in [m for m, _ in with_user]] == []
    name, argv = extra[0]
    assert name.startswith("non-root pass") and argv[0] == "bash" and argv[1] == "scripts/run_nonroot.sh", extra
    assert (ROOT / argv[1]).is_file()


def test_gate_as_user_other_values_do_not_enable_it(tmp_path):
    for v in ("0", "", "yes", "true"):
        _, stages = listed("push", tmp_path, GATE_AS_USER=v)
        assert not [n for n, _ in stages if "non-root" in n], v
