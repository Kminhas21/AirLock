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
    ("X1 inbox auto-approves without a working monitor", "server/inbox_hub.py", "elif auto and working and not alerts and not secrets_used:", "elif auto and not alerts and not secrets_used:", 1),
    ("X2 inbox ignores the monitor error counter", "server/inbox_hub.py", "if proposal_monitor.error_count() > errors_before:", "if False:", 1),
    ("X3 inbox sockets work without a token", "server/main.py", 'if not os.environ.get("SENTINEL_WS_TOKEN"):', "if False:", 1),
    ("X4 inbox accepts any decision value", "server/inbox_hub.py", 'or decision not in ("approve", "deny")):', "or False):", 1),
    ("X5 inbox turns every human decision into approve", "server/inbox_hub.py",
     'decision, reason = ("approve" if p.decision == "approve" else "deny"), p.reason or "invalid"', 'decision, reason = "approve", p.reason or "invalid"', 1),
    ("X7 cancelled call is still sent to the monitor/proxy as a decision", "server/inbox_hub.py", "        if p.cancelled:                  # proxy_cancel: no proxy_decision, no monitor registration", "        if False:                  # proxy_cancel: no proxy_decision, no monitor registration", 1),
    ("X8 call cancelled while the monitor ran is still held", "server/inbox_hub.py", "        if call_id in session.cancelled_early:     # the proxy dropped it while the monitor ran: never hold or approve", "        if False:     # the proxy dropped it while the monitor ran: never hold or approve", 1),
    ("X9 proxy never tells the hub it abandoned a call", "sentinel_proxy/backend.py", 'frame = json.dumps({"event": "proxy_cancel", "call_id": call_id, "reason": reason})\n        task = asyncio.get_running_loop().create_task(self._send(ws, frame))', 'return\n        task = asyncio.get_running_loop().create_task(self._send(ws, frame))', 1),
    # policy engine (DECISIONS.md D18)
    ("Y1 a deny rule no longer beats allow/ask", "server/policy.py", '        deny = best("deny")', "        deny = None", 1),
    ("Y2 an alert no longer escalates an allow", "server/policy.py", 'if alerts and verdict == "allow":', "if False:", 1),
    ("Y3 a rule error no longer forces ask", "server/policy.py", '        if errors:\n            return Decision("ask", ask.id if ask else None', '        if False:\n            return Decision("ask", ask.id if ask else None', 1),
    ("Y4 the proxy auto flag is honoured in policy mode", "server/inbox_hub.py", "            auto = False\n            digest = session.policy.digest()", "            digest = session.policy.digest()", 1),
    ("Y5 a policy allow stands without a working monitor", "server/inbox_hub.py", 'if verdict == "allow" and working and not alerts:', 'if verdict == "allow":', 1),
    ("Y6 a failing policy evaluation allows", "server/inbox_hub.py", '                    logger.exception("inbox: policy evaluation failed; asking the human")\n                    verdict, rule_id = "ask", None', '                    logger.exception("inbox: policy evaluation failed; asking the human")\n                    verdict, rule_id = "allow", None', 1),
    ("Y7 the policy loader treats an int path as a file descriptor", "server/policy.py", "if isinstance(path, bool) or not isinstance(path, (str, os.PathLike)):", "if False:", 1),
    # durable event log (DECISIONS.md D19)
    ("Z1 event log: a broken hash link is no longer reported", "server/eventlog.py", "            if prev != prev_seen_hash:", "            if False:", 1),
    ("Z2 event log: secret keys are no longer redacted", "server/eventlog.py", "out[key] = REDACTED if _secret_key(key) else _clean(val, b, depth + 1)", "out[key] = _clean(val, b, depth + 1)", 1),
    ("Z3 hub: an approve whose record cannot be written still goes out", "server/inbox_hub.py", '            if decision == "approve":\n                decision, reason, actor = "deny", "log_unavailable", "system"', '            if False:\n                decision, reason, actor = "deny", "log_unavailable", "system"', 1),
    ("Z4 hub: runs unlogged when the log is unusable", "server/inbox_hub.py", "        if self.log_unusable:\n            return await reject(\"log_unavailable\")", "        if False:\n            return await reject(\"log_unavailable\")", 1),
    ("Z5 hub: alert messages are logged unscrubbed", "server/inbox_hub.py", '"message": eventlog.scrub(a.get("message"), secrets)', '"message": a.get("message")', 1),
    ("Z6 hub: tool output is stored by default", "server/inbox_hub.py", 'if os.environ.get("SENTINEL_LOG_RESULTS") == "1":', "if True:", 1),
    ("Z7 a UI is registered for broadcasts before its snapshot is sent", "server/inbox_hub.py", "        async with ui._lock:\n            self._uis.append(ui)\n            recent: list = []", "        self._uis.append(ui)\n        async with asyncio.Lock():\n            recent: list = []", 1),
    # operator UI (DECISIONS.md D20)
    ("O1 hub: a standing rule is written without the explicit confirm", "server/inbox_hub.py", '            if frame.get("confirm") is not True:', "            if False:", 1),
    ("O2 hub: the operator note is attached to approvals too", "server/inbox_hub.py", 'note = p.note if (decision == "deny" and reason == "human") else None      # never a note on an approve', "note = p.note      # never a note on an approve", 1),
    ("O3 drift_update no longer carries the active threshold", "server/events.py", '        out["threshold"] = float(threshold)', "        pass", 1),
    ("O4 hub: standing rules are offered although the policy is not writable", "server/inbox_hub.py", 'return {"policy_writable": writable, "event_log": self.store is not None}', 'return {"policy_writable": True, "event_log": self.store is not None}', 1),
    # enforcement boundary (DECISIONS.md D21)
    ("B1 sandbox: Landlock is built but never applied", "sentinel_proxy/sandbox.py", "        if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ctypes.c_int(rfd), ctypes.c_uint32(0)) != 0:", "        if False:", 1),
    ("B2 proxy: every secret goes to every tool of the worker", "sentinel_proxy/config.py", "return [n for n, s in self.secrets.items() if tool in s[\"tools\"]]", "return [n for n, s in self.secrets.items()]", 1),
    ("B3 proxy: secret values are no longer scrubbed", "sentinel_proxy/config.py", '        text = text.replace(v, "[REDACTED]")', "        text = text", 1),
    ("B4 hub: a call that receives credentials may be auto-approved by the legacy flag", "server/inbox_hub.py", "elif auto and working and not alerts and not secrets_used:", "elif auto and working and not alerts:", 1),
    ("B5 hub: the live session-open event hides the sandbox boundary", "server/inbox_hub.py", '"servers": session.servers, "boundary": session.boundary}))', '"servers": session.servers}))', 1),
    # identity, tenancy, escalation (DECISIONS.md D22)
    ("I1 identity: JWT audience is no longer verified", "server/identity.py", '"verify_iss": True, "verify_aud": True})', '"verify_iss": True, "verify_aud": False})', 1),
    ("I2 identity: token digests compared with == (timing)", "server/identity.py", "hmac.compare_digest(rec.digest, digest)", "(rec.digest == digest)", 1),
    ("I3 identity: a viewer may decide", "server/identity.py", 'need = {"view": 1, "decide": 2, "rules": 3}[action]', 'need = {"view": 1, "decide": 1, "rules": 3}[action]', 1),
    ("I4 hub: broadcasts reach the UIs of every tenant", "server/inbox_hub.py", "uis = [u for u in self._uis if u.principal is not None and tenant is not None and u.principal.tenant == tenant]", "uis = list(self._uis)", 1),
    ("I5 notify: redirects are followed", "server/notify.py", "follow_redirects=False", "follow_redirects=True", 1),
    ("X6 proxy forwards a denied call", "sentinel_proxy/proxy.py", "if not decision.approved:", "if False:", 1),
    ("R4 denied-party match ignored when choosing the earlier denied proposal for the alert text", "server/proposal_monitor.py",
     'pool = [d for d in self._denied_props if party in d[2].reaches] or list(self._denied_props)',
     'pool = list(self._denied_props)', 1),
]

# Frontend mutants: killed by `vitest run` (frontend/src/**/*.test.{ts,tsx}), not by pytest.
FRONTEND_MUTANTS = [
    ("F1 drawer shows the raw (multi-line) tool name", "frontend/src/components/NodeDetail.tsx", "singleLine(data.toolName)", "String(data.toolName)", 1),
    ("F2 drawer colours drift against the old 2.5", "frontend/src/components/NodeDetail.tsx", "driftPoint.mahalanobisDistance > pointThreshold(driftPoint.threshold)", "driftPoint.mahalanobisDistance > 2.5", 1),
    ("F7 the UI ignores the threshold carried by the event", "frontend/src/lib/drift.ts", "threshold > 0 ? threshold : DRIFT_THRESHOLD", "threshold > 0 ? DRIFT_THRESHOLD : DRIFT_THRESHOLD", 1),
    ("F3 sanitiser removes nothing", "frontend/src/lib/safeText.ts", '.replace(UNSAFE, "")', '.replace(UNSAFE, "$&")', 1),
    ("F5 the standing-rule frame is built without confirm=true semantics (unknown verdicts are offered)", "frontend/src/lib/inboxView.ts", "confirm: true as const", "confirm: false as unknown as true", 1),
    ("F6 the UI offers standing rules although the hub says it is not writable", "frontend/src/lib/inboxRoute.ts", "policy_writable: isRec(event.capabilities) && event.capabilities.policy_writable === true,", "policy_writable: true,", 1),
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
