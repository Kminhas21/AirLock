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
     '            rules_alerts = drift.observe_tool_call(tool_name, node_id)\n', '            rules_alerts = []\n', 1),
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
    # destination-registry monitors (DECISIONS.md D9)
    ("R1 denied-party match ignored (denials never reach the registry detector)", "server/proposal_monitor.py",
     '            self._detector.register_decision({"tool": tool, "args": args}, decision)\n        except Exception:\n            log.exception("registry monitor: the DETECTOR failed',
     '            pass\n        except Exception:\n            log.exception("registry monitor: the DETECTOR failed', 1),
    ("R2 registry mode without a usable registry keeps running D8/D9 (fallback to action_sim removed)", "server/proposal_monitor.py",
     '    if registry is None:\n        return _fallback_registry(requested, why, env)',
     '    if registry is None:\n        from server.registry import default_registry\n        registry = default_registry()', 1),
    # frozen v3 monitors (DECISIONS.md D10): killed by tests/server/test_proposal_monitor_registry_v3.py
    ("R3 registry/frozen fallback lands on rules instead of action_sim", "server/proposal_monitor.py",
     '    base = _resolve_basic("action_sim", env)\n    return MonitorFactory(requested, base.mode, reason, base.model_path)',
     '    base = _resolve_basic("rules", env)\n    return MonitorFactory(requested, base.mode, reason, base.model_path)', 1),
    # /health hardening and union mode (DECISIONS.md D14 + this round)
    ("H1 /health public view still shows full paths", "server/health_view.py", 'out[key]["path"] = _name(out[key]["path"])', 'pass', 1),
    ("H2 /health detail shown to everyone", "server/health_view.py", 'return env.get("SENTINEL_HEALTH_DETAIL", "").strip() == "1"', 'return True', 1),
    ("H3 /health token never checked", "server/health_view.py", 'return hmac.compare_digest(supplied.encode(), expected.encode())', 'return True', 1),
    ("H4 /health leaks the fallback message", "server/health_view.py", 'out["last_session_fallback"] = _fallback_head(out["last_session_fallback"])', 'pass', 1),
    ("U1 union ignores the action-similarity member", "server/proposal_monitor.py", 'return act_alerts[:1]', 'return []', 1),
    # MCP proxy + inbox (DECISIONS.md D16)
    ("X1 inbox auto-approves without a working monitor", "server/inbox_hub.py", "if auto and working and not alerts:", "if auto and not alerts:", 1),
    ("X2 inbox ignores the monitor error counter", "server/inbox_hub.py", "if proposal_monitor.error_count() > errors_before:", "if False:", 1),
    ("X3 inbox sockets work without a token", "server/main.py", 'if not os.environ.get("SENTINEL_WS_TOKEN"):', "if False:", 1),
    ("X4 inbox accepts any decision value", "server/inbox_hub.py", 'or decision not in ("approve", "deny")):', "or False):", 1),
    ("X5 inbox turns every human decision into approve", "server/inbox_hub.py",
     'decision, reason = ("approve" if p.decision == "approve" else "deny"), p.reason or "invalid"', 'decision, reason = "approve", p.reason or "invalid"', 1),
    ("X6 proxy forwards a denied call", "sentinel_proxy/proxy.py", "if not decision.approved:", "if False:", 1),
    ("R4 denied-party match ignored when choosing the earlier denied proposal for the alert text", "server/proposal_monitor.py",
     'pool = [d for d in self._denied_props if party in d[2].reaches] or list(self._denied_props)',
     'pool = list(self._denied_props)', 1),
]

# Frontend mutants: killed by `vitest run` (frontend/src/**/*.test.{ts,tsx}), not by pytest.
FRONTEND_MUTANTS = [
    ("F1 drawer shows the raw (multi-line) tool name", "frontend/src/components/NodeDetail.tsx", "singleLine(data.toolName)", "String(data.toolName)", 1),
    ("F2 drawer colours drift against the old 2.5", "frontend/src/components/NodeDetail.tsx", "driftPoint.mahalanobisDistance > DRIFT_THRESHOLD", "driftPoint.mahalanobisDistance > 2.5", 1),
    ("F3 sanitiser removes nothing", "frontend/src/lib/safeText.ts", '.replace(UNSAFE, "")', '.replace(UNSAFE, "$&")', 1),
    ("F4 result panel is raw text again", "frontend/src/components/NodeDetail.tsx", "<AgentText text={data.result} />", "<pre className=\"detail-code\">{String(data.result)}</pre>", 1),
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
    for name, rel, old, new, count in FRONTEND_MUTANTS:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "repo"
            shutil.copytree(ROOT / "frontend", tree / "frontend",
                            ignore=shutil.ignore_patterns("node_modules", "dist", "e2e", ".results"))
            (tree / "frontend" / "node_modules").symlink_to(ROOT / "frontend" / "node_modules", target_is_directory=True)
            f = tree / rel
            text = f.read_text()
            if text.count(old) != count:
                stale.append(f"{name}: expected {count} occurrence(s) of target in {rel}, found {text.count(old)}")
                continue
            clean = subprocess.run(["npx", "vitest", "run"], cwd=tree / "frontend", capture_output=True, text=True, timeout=300)
            if clean.returncode != 0:      # a scratch copy that fails BEFORE the mutation would make every mutant look killed
                stale.append(f"{name}: the unmutated frontend copy does not pass vitest")
                continue
            f.write_text(text.replace(old, new))
            base = subprocess.run(["npx", "vitest", "run"], cwd=tree / "frontend", capture_output=True, text=True, timeout=300)
            rc = base.returncode
            print(f"{'KILLED  ' if rc != 0 else 'SURVIVED'}  {name}")
            if rc == 0:
                survivors.append(name)
    for s in stale:
        print("STALE   ", s)
    if survivors or stale:
        print(f"\nmutation check FAILED: {len(survivors)} survivor(s), {len(stale)} stale")
        return 1
    print(f"\nmutation check OK: all {len(MUTANTS) + len(FRONTEND_MUTANTS)} re-introduced bugs were caught by the suite")
    return 0


if __name__ == "__main__":
    sys.exit(main())
