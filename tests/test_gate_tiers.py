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
PUSH = ["preflight", "mutation targets are current", "mutant killer map is current", "live coverage map, static", "backend pytest, fast", "seismograph legacy",
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


def test_the_killer_map_staleness_check_runs_in_every_tier(tmp_path):
    """The map that lets a PR skip mutants must never be stale: a fast check in the push tier (so in every tier), not at the end of a long one."""
    for tier in ("push", "pr", "full", "weekly"):
        argv = next(a for n, a in listed(tier, tmp_path)[1] if n.startswith("mutant killer map is current"))
        assert argv[-2:] == ["scripts/mutation_check.py", "--check-killer-map"], (tier, argv)


def test_the_full_and_weekly_tiers_run_every_mutant_without_the_map(tmp_path):
    """The safety net behind the map's shortcut: the nightly (full) and weekly tiers run the whole mutation check, no --changed-since."""
    for tier in ("full", "weekly"):
        argv = next(a for n, a in listed(tier, tmp_path)[1] if n.startswith("mutation check ("))
        assert argv[-1] == "scripts/mutation_check.py" and "--changed-since" not in argv, (tier, argv)


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


# ----------------------------------------------------------------------------- the full mutation check in CI (its own sharded job)
CI = ROOT / ".github" / "workflows" / "ci.yml"


def test_with_the_external_flag_the_full_tier_delegates_the_mutation_check_and_names_the_ci_job(tmp_path):
    _, stages = listed("full", tmp_path, GATE_MUTATION_FULL="external")
    named = [(n, a) for n, a in stages if n.startswith("mutation check")]
    assert len(named) == 1 and "CI job `mutation`" in named[0][0] and named[0][1][-1] == "--check-targets"
    _, stages = listed("full", tmp_path)
    assert [a[-1] for n, a in stages if n.startswith("mutation check")] == ["scripts/mutation_check.py"]    # local default: the whole check, unsharded


def test_every_tier_from_pr_up_runs_the_mutation_check_or_names_the_job_that_does(tmp_path):
    for tier in ("pr", "full", "weekly"):
        for ext in ({}, {"GATE_MUTATION_FULL": "external"}):
            names = [n for n, _ in listed(tier, tmp_path, **ext)[1] if n.startswith("mutation check")]
            assert len(names) == 1, (tier, ext, names)
            if ext:
                assert "CI job `mutation`" in names[0] or tier == "pr"


def test_the_ci_workflow_has_a_sharded_resumable_mutation_job_and_the_gate_job_delegates_to_it():
    import yaml
    wf = yaml.safe_load(CI.read_text())
    jobs = wf["jobs"]
    assert set(jobs) >= {"gate", "mutation"}
    mut = jobs["mutation"]
    assert mut["strategy"]["matrix"]["shard"] == [1, 2, 3, 4] and mut["strategy"]["fail-fast"] is False
    # measured on GitHub (runs 44400641698 and 44414893564, 4 shards each): slowest shard job 46.5 min (mutation step 44.8), typical 30-41; 2.5x the slowest
    assert 2.5 * 46.5 <= mut["timeout-minutes"] <= 150, mut["timeout-minutes"]
    text = CI.read_text()
    assert "--shard ${{ matrix.shard }}/4" in text and "--log" in text and "--jobs 3" in text or "GATE_MUTATION_JOBS: \"3\"" in text
    assert "actions/cache" in text and "mutation-log" in text                                  # a rerun resumes from the verdict log
    cond = mut["if"]
    assert "schedule" in cond and "full" in cond and "weekly" in cond                            # nightly and weekly, never on a push or a PR
    steps = " ".join(str(s.get("run", "")) + str(s.get("env", "")) for s in jobs["gate"]["steps"])
    assert "GATE_MUTATION_FULL" in steps and "external" in steps
    assert "GATE_MUTATION_JOBS" in steps and "GATE_MUTATION_MAX" in steps                      # the pr tier: parallel and capped
    t = jobs["gate"]["timeout-minutes"]
    # measured: push 3.1 min; the full-tier gate job 25-29 min (without the mutation check); the pr tier up to 47 min with its mutants run serially
    assert "push' && 15" in t and t.rstrip(" }").endswith("|| 120"), t


def test_the_pr_tier_finds_a_green_full_mutation_run_for_the_pr_head_and_fails_closed_without_one():
    import yaml
    wf = yaml.safe_load(CI.read_text())
    assert wf["permissions"].get("actions") == "read"                    # the lookup lists workflow runs and their jobs
    steps = wf["jobs"]["gate"]["steps"]
    look = next(s for s in steps if "green full mutation run" in s.get("name", ""))
    assert "pull_request" in look["if"] and look["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    run = look["run"]
    for needle in ("GATE_HEAD_SHA=$HEAD_SHA", "GATE_MUTATION_PROOF=", "head_sha=$HEAD_SHA", "mutation (", "success"):
        assert needle in run, needle
    names = [s.get("name", "") for s in steps]
    assert names.index(look["name"]) < names.index("Gate")              # before the gate runs, so the check can use it
    gate_env = next(s for s in steps if s.get("name") == "Gate")["env"]
    assert gate_env["GATE_MUTATION_MAX"] == "150"                        # the cap itself is unchanged: only a proof for the same commit lifts it
