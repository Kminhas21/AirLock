"""Mutation check: proves the test suite is not vacuous.

For each known bug, re-introduce it into a THROWAWAY copy of the repo and run the backend
tests. The check passes only if the suite goes RED for every mutant. Also fails if a
mutation's target text is not found (a stale mutation would silently prove nothing).
"""
import shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IGNORE = shutil.ignore_patterns("node_modules", ".git", "__pycache__", "dist", ".pytest_cache", "frontend")

# (id, file, old, new, count) -- each re-introduces one bug from DECISIONS.md
MUTANTS = [
    ("B1 gate ignores node_id", "server/gate.py", 'or msg.get("node_id") != node_id', 'or False', 1),
    ("B1 gate fails open on garbage", "server/gate.py", 'return GateResult("deny", "invalid")', 'return GateResult("approve", "human")', 1),
    ("B2 timeout approves instead of denying", "server/gate.py", 'GateResult("deny", "timeout")', 'GateResult("approve", "timeout")', 2),
    ("B3 origin check removed", "server/auth.py", 'return AccessResult(False, "bad_origin")', 'pass', 1),
    ("B3 token check removed", "server/auth.py", 'return AccessResult(False, "bad_token")', 'pass', 1),
    ("B4 shared environment", "server/mock_environment.py", 'env = _ENV.get(None)\n    if env is None:\n        env = Environment()\n        _ENV.set(env)\n    return env',
     'global _SHARED\n    try:\n        return _SHARED\n    except NameError:\n        _SHARED = Environment()\n        return _SHARED', 1),
    ("B5 LLM retries disabled", "server/llm_call.py", 'retries=2,', 'retries=0,', 1),
    ("B6 circumvention only counted after decision", "server/agent_loop.py",
     '            await emit(*drift.observe_tool_call(tool_name, node_id))\n', '', 1),
    ("B1 deny path still executes", "server/agent_loop.py", 'if outcome.decision == "approve" and ledger.claim(node_id):', 'if True:', 1),
    ("B5 no terminal event on LLM error", "server/agent_loop.py", 'await emit(events.session_complete("llm_error", "The model API is unavailable."))\n            return', 'return', 1),
    ("B8 contract field renamed", "server/events.py", '"reason": reason, "message": message,', '"why": reason, "message": message,', 1),
    ("B14 replay requires model key", "server/main.py", 'if mode == "replay":', 'if mode == "replay_disabled":', 1),
    ("B15 exception text leaked", "server/main.py", 'events.error("Internal server error.")', 'events.error(f"Server error: {exc}")', 1),
    ("B20 replan never emitted", "server/agent_loop.py", '"replan" if last_was_denied else "tool_call"', '"tool_call"', 1),
    ("B17 default model not resolved", "server/providers.py", "return next(iter(registry))", 'return "claude-sonnet"', 1),
    ("B16 server not importable from server/ dir", "server/live_drift.py", "sys.path.append(_REPO_ROOT)", "pass", 1),
    ("B11 shrinkage removed", "seismograph/drift_detector.py", "shrinkage: float = 0.1", "shrinkage: float = 0.0", 1),
    ("B11 magic threshold restored", "seismograph/drift_detector.py", "CHI2_99_DF3 = 3.368", "CHI2_99_DF3 = 2.5", 1),
]


def run_suite(tree: Path) -> int:
    p = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider"],
                       cwd=tree, capture_output=True, text=True, timeout=600)
    return p.returncode


def main() -> int:
    survivors, stale = [], []
    for name, rel, old, new, count in MUTANTS:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "repo"
            shutil.copytree(ROOT, tree, ignore=IGNORE)
            # contracts.ts is read by the contract tests
            (tree / "frontend/src/types").mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / "frontend/src/types/contracts.ts", tree / "frontend/src/types/contracts.ts")
            f = tree / rel
            text = f.read_text()
            if text.count(old) != count:
                stale.append(f"{name}: expected {count} occurrence(s) of target in {rel}, found {text.count(old)}")
                continue
            if name.startswith("B15"):
                text = text.replace("except Exception:\n        # Details", "except Exception as exc:\n        # Details")
            f.write_text(text.replace(old, new))
            rc = run_suite(tree)
            print(f"{'KILLED  ' if rc != 0 else 'SURVIVED'}  {name}")
            if rc == 0:
                survivors.append(name)
    for s in stale:
        print("STALE   ", s)
    if survivors or stale:
        print(f"\nmutation check FAILED: {len(survivors)} survivor(s), {len(stale)} stale")
        return 1
    print(f"\nmutation check OK: all {len(MUTANTS)} re-introduced bugs were caught by the suite")
    return 0


if __name__ == "__main__":
    sys.exit(main())
