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
    ("O4 hub: standing rules are offered although the policy is not writable", "server/inbox_hub.py", '        caps = {"policy_writable": writable, "event_log": self.store is not None}', '        caps = {"policy_writable": True, "event_log": self.store is not None}', 1),
    # enforcement boundary (DECISIONS.md D21)
    ("B1 sandbox: Landlock is built but never applied", "sentinel_proxy/sandbox.py", "        if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ctypes.c_int(rfd), ctypes.c_uint32(0)) != 0:", "        if False:", 1),
    ("B2 proxy: every secret goes to every tool of the worker", "sentinel_proxy/config.py", "return [n for n, s in self.secrets.items() if tool in s[\"tools\"]]", "return [n for n, s in self.secrets.items()]", 1),
    ("B3 proxy: secret values are no longer scrubbed", "sentinel_proxy/config.py", '        text = text.replace(v, "[REDACTED]")', "        text = text", 1),
    ("B4 hub: a call that receives credentials may be auto-approved by the legacy flag", "server/inbox_hub.py", "elif auto and working and not alerts and not secrets_used:", "elif auto and working and not alerts:", 1),
    ("B5 hub: the live session-open event hides the sandbox boundary", "server/inbox_hub.py", '"servers": session.servers, "boundary": session.boundary}, session.tenant))', '"servers": session.servers}, session.tenant))', 1),
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
    # found by running hostile models / real servers (DECISIONS.md D25)
    ("H1 effects: the file-name pattern is quadratic again (one 200 KB argument froze the hub)", "eval/effects.py", r"[\w./\-]{0,255}\w\.(?:csv", r"[\w./\-]*\w\.(?:csv", 1),
    ("H2 effects: the whole hostile argument is scanned, not a bounded window", "eval/effects.py", "_FILE_RE.findall(t[:_SCAN_LIMIT])", "_FILE_RE.findall(t)", 1),
    ("H3 agent loop: a response with no choices raises IndexError", "server/agent_loop.py", 'if not getattr(response, "choices", None):', "if False:", 1),
    ("H4 agent loop: list-of-parts content is passed through un-normalised", "server/agent_loop.py", "        content = _content_text(message.content)", "        content = message.content or \"\"", 1),
    ("H5 proxy: an oversize call is sent anyway (the hub drops the whole link)", "sentinel_proxy/backend.py", "if len(frame.encode()) > MAX_FRAME_BYTES:", "if False:", 1),
    ("H6 proxy and hub disagree about the frame limit", "sentinel_proxy/backend.py", "MAX_FRAME_BYTES = 1_000_000 ", "MAX_FRAME_BYTES = 2_000_000 ", 1),
    ("H7 hub: a call whose proxy closed while the monitor ran is dropped BEFORE call_proposed (vanishes from the audit trail)", "server/inbox_hub.py", "        # (a session closed while the monitor ran is NOT dropped here: call_proposed is written first, then denied/disconnected below)\n", "        if session.closed:\n            return\n", 1),
    ("H8 replay ignores the logged denials (denied-effect alerts never fire)", "server/eventlog_cli.py", '            mon.register_decision(c["tool"], c["args"], c["decision"])', '            pass', 1),
    ("H9 verify --previous does not compare the archive head with log_continues", "server/eventlog_cli.py", 'if (p.get("head_seq"), p.get("head_hash")) != (seq, h):', 'if False:', 1),
    ("H10 a failed hello_ack abandons the connection (a call queued in the same instant is never read nor logged)", "server/inbox_hub.py", '            return session\n        # a UI that is already open learns', '            await self.proxy_closed(session)\n            return None\n        # a UI that is already open learns', 1),
    ("H11 hub: a call on a peer already known to be dead is held or auto-approved instead of denied", "server/inbox_hub.py", "if session.closed or session.conn.dead:", "if session.closed:", 1),
    ("H12 denied_effect_match downgrade not applied (a note-named retry stays critical)", "server/inbox_hub.py", 'if b.get("severity") == "critical":', "if False:", 1),
    ("H13 same-directory safety rail removed (a basename in the note blesses any directory)", "server/alert_note.py", 'dir_new == _split(old[path].lower())[0] and ', '', 1),
    ("H19 decoy: a NEW key at which the denied call had nothing is allowed to earn the label", "server/alert_note.py", 'or path not in old or old[path] == v:', 'or old.get(path) == v:', 1),
    ("H14 starter: the sensitive-path rule is an allow instead of an ask", "server/policies/starter.json", '{"id": "ask-sensitive-path", "verdict": "ask",', '{"id": "ask-sensitive-path", "verdict": "allow",', 1),
    ("H14b engine: a matching ask rule no longer beats an allow", "server/policy.py",
     '        if ask is not None:\n            return Decision("ask", ask.id, ids, f"rule:{ask.id}", False)\n        allow = best("allow")',
     '        if False and ask is not None:\n            return Decision("ask", ask.id, ids, f"rule:{ask.id}", False)\n        allow = best("allow")', 1),
    ("H15 unknown builtin policy loads as allow-all instead of failing closed", "server/policy.py", '            return None, _unknown_builtin(path)',
     '            return Policy({"version": 1, "default": "allow", "rules": []}), ""', 1),
    ("H15b resolver returns an empty path instead of None for an unknown builtin", "server/policy.py", 'name in _BUILTIN_NAMES else None', 'name in _BUILTIN_NAMES else ""', 1),
    ("H16 icontains_any is case-sensitive", "server/policy.py", '    f = text.casefold()', '    f = text', 1),
    ("H17 icontains_any ignores list arguments", "server/policy.py", '    elif isinstance(v, (list, tuple)):\n        if len(v) > MAX_ICASE_ITEMS:',
     '    elif isinstance(v, tuple):\n        if len(v) > MAX_ICASE_ITEMS:', 1),
    ("H18 icontains_any: an over-long element no longer counts as a match", "server/policy.py", 'len(it) > MAX_ICASE_STR:\n            return True',
     'len(it) > MAX_ICASE_STR * 99:\n            return False', 1),
    ("H20 icontains_any: path normalisation removed (only the as-written text is tested)", "server/policy.py", '    yield f\n    n = f.replace(', '    yield f\n    return\n    n = f.replace(', 1),
    ("H21 icontains_any: non-string list entries are skipped instead of matching", "server/policy.py", '        if not isinstance(it, str) or len(it) > MAX_ICASE_STR:',
     '        if not isinstance(it, str):\n            continue\n        if len(it) > MAX_ICASE_STR:', 1),
    ("H22 the :// needle is removed from the path rule (a URL read is auto-allowed again)", "server/policies/starter.json", '".git-credentials", "://"]}]}},\n {"id": "ask-sensitive-paths"', '".git-credentials"]}]}},\n {"id": "ask-sensitive-paths"', 1),
    ("H23 the ask-url-flag rule is an allow (isUrl:true fetches unattended again)", "server/policies/starter.json", '{"id": "ask-url-flag", "verdict": "ask",', '{"id": "ask-url-flag", "verdict": "allow",', 1),
    # B3 / B4 (DECISIONS D29): allow rules bound to the real argument names; symlink-resolved paths evaluated too
    ("H24 engine: when.arg_keys is ignored (a read tool with an extra flag is auto-allowed again)", "server/policy.py",
     "    if rule.arg_keys is not None and not _keys_within(ctx.args, rule.arg_keys, rule.verdict):", "    if False:", 1),
    ("H25 engine: arg_keys on args that are not an object matches an allow rule", "server/policy.py",
     '        return verdict != "allow"\n    return all(k in keys for k in args)', '        return True\n    return all(k in keys for k in args)', 1),
    ("H26 starter: the read rule lists isUrl (Desktop Commander's URL fetch is auto-allowed again)", "server/policies/starter.json",
     '"arg_keys": ["path", "head", "tail", "offset", "length"]', '"arg_keys": ["path", "head", "tail", "offset", "length", "isUrl"]', 1),
    ("H27 icontains_any: an object / scalar in a path slot is false again (paths: {..} slips past the ask rule)", "server/policy.py",
     "        return True                                       # an object / scalar where a path is expected: fail closed",
     "        return None", 1),
    ("H28 starter: read_multiple_files allowed on any `paths` value, not only a non-empty list", "server/policies/starter.json",
     '"args": [{"path": "paths.0", "op": "exists"}]', '"args": [{"path": "paths", "op": "exists"}]', 1),
    ("H29 hub: the proxy's symlink resolution is ignored (notes.txt -> .env is auto-allowed)", "server/inbox_hub.py",
     '        resolved, resolved_bad = resolved_args.parse(frame.get("resolved"), args, frame.get("resolved_incomplete", False))',
     '        resolved, resolved_bad = [], False', 1),
    ("H30 hub: the resolved form REPLACES the written one instead of the stricter of both (a resolution can loosen)", "server/resolved_args.py",
     "            d = _policy.stricter(d, policy.evaluate(server, tool, substitute(args, m), **kw))",
     "            d = policy.evaluate(server, tool, substitute(args, m), **kw)", 1),
    ("H31 hub: a malformed or incomplete resolution no longer floors an allow at ask", "server/resolved_args.py",
     '        if invalid and d.verdict == "allow":', "        if False:", 1),
    ("H32 hub: a malformed resolution map is accepted", "server/resolved_args.py",
     "        if not all(_check_map(m, args) for m in value):", "        if False:", 1),
    ("H33 proxy: the resolution is not sent in proxy_call", "sentinel_proxy/proxy.py", "        frame.update(await _resolution(args, sc))", "        pass", 1),
    ("H34 proxy: relative paths are not resolved against the downstream's directories", "sentinel_proxy/resolve.py",
     '    joined = [(None, v)] if v.startswith("/") else [(b, os.path.join(b, v)) for b in bases]', '    joined = [(None, v)] if v.startswith("/") else []', 1),
    ("H35 proxy: an exhausted lookup budget is not reported as incomplete", "sentinel_proxy/resolve.py",
     "    if budget.left < 2:\n        budget.incomplete = True\n", "    if budget.left < 2:\n", 1),
    ("H36 proxy: only the kernel order is resolved ('..' after a symlinked dir reaches .env through the server's lexical order)", "sentinel_proxy/resolve.py",
     "        node = os.path.realpath(lexical)", "        node = os.path.realpath(joined)", 1),
    ("H37 proxy: a path-slot name that exists nowhere is not incomplete (the server's Unicode-equivalent mapping reaches .env)", "sentinel_proxy/resolve.py",
     "        if slot and missing and (b is None or b in map_bases)", "        if False and (b is None or b in map_bases)", 1),
    ("H38 proxy: '~' is expanded with the proxy's home although the server gets its own", "sentinel_proxy/resolve.py",
     "        if not home:\n            budget.incomplete = True", "        if False:\n            budget.incomplete = True", 1),
    ("H39 proxy: M1 also counts the kernel-order path (a decoy the server never reads hides a Unicode-mapped name)", "sentinel_proxy/resolve.py",
     "        missing = not os.path.lexists(lexical)", "        missing = not (os.path.lexists(lexical) or os.path.lexists(joined))", 1),
    ("H40 proxy: a relative value with more bases than the hub accepts is resolved against the first ones only (a dropped base reaches .env)",
     "sentinel_proxy/resolve.py", '    if not v.startswith("/") and len(bases) > MAX_BASES:\n        budget.incomplete = True',
     '    bases = bases[:MAX_BASES]\n    if False:\n        budget.incomplete = True', 1),
    ("H41 proxy: M1 needs the name missing in EVERY allowed dir (a harmless copy in another dir hides the first dir's Unicode mapping)",
     "sentinel_proxy/resolve.py", "if slot and missing and (b is None or b in map_bases) and _inside(os.path.normpath(j), map_bases):",
     "if slot and missing and (b is None or b == bases[-1]) and _inside(os.path.normpath(j), map_bases):", 1),
    # live tests actually happen (DECISIONS.md D28): the no-skip plugin and the live coverage check
    ("L1 no-skip: SENTINEL_NO_SKIP=1 is ignored (a skipped live test passes the stage)", "tests/no_skip_plugin.py",
     'return os.environ.get("SENTINEL_NO_SKIP") == "1"', "return False", 1),
    ("L2 no-skip: an xfail passes the stage again", "tests/no_skip_plugin.py",
     '    if hasattr(rep, "wasxfail"):', "    if False:", 1),
    ("L3 coverage: a workflow with no live test and no gap passes", "scripts/check_live_coverage.py",
     "        if not live and not gap:", "        if False:", 1),
    ("L4 coverage: a skipped / xfail / failed live test counts as proof", "scripts/check_live_coverage.py",
     '                if o != "passed":', "                if False:", 1),
    ("L5 coverage: a spec only an opt-in stage runs counts as live", "scripts/check_live_coverage.py",
     "                elif all(hits) and not is_opt:", "                elif False:", 1),
    ("L6 coverage: a live test absent from the junit files counts as proof", "scripts/check_live_coverage.py",
     "            if not cases:\n", "            if False:\n", 1),
    ("L7 coverage: a node id in two junit files keeps its LAST outcome (a skip hides behind a later pass)", "scripts/check_live_coverage.py",
     '            if out.get(node, "passed") == "passed":', "            if True:", 1),
    # gate failure notifications + preflight (scripts/gate_lib.sh, tests/test_gate_lib.py)
    ("G1 preflight: an HTTPS proxy without the Docker build CA passes (the build then fails hours later)", "scripts/gate_lib.sh",
     '[ "${SENTINEL_DOCKER_FORWARD_PROXY:-}" != 1 ]; then', '[ "${SENTINEL_DOCKER_FORWARD_PROXY:-}" != 1 ] && false; then', 1),
    ("G2 a failed stage writes no FAIL event (a watcher never hears of it)", "scripts/gate_lib.sh",
     'gate_event FAIL "$name" $((SECONDS - t0))', ':', 1),
    ("G3 fail-fast keeps running after a failure", "scripts/gate_lib.sh",
     'echo "GATE: RED (fail-fast at: $name)"; exit 1;', 'echo "GATE: RED (fail-fast at: $name)";', 1),
    ("G4 verify.sh runs on (and goes GREEN) when scripts/gate_lib.sh cannot be loaded", "scripts/verify.sh",
     'source scripts/gate_lib.sh || { echo "GATE: RED (scripts/gate_lib.sh could not be loaded: no stage ran)"; exit 1; }', 'source scripts/gate_lib.sh', 1),
    ("G5 DONE says GREEN even when the gate aborted", "scripts/gate_lib.sh",
     '[ $rc -eq 0 ] && echo GREEN || echo RED', 'echo GREEN', 1),
    ("G6 preflight: a loopback proxy passes without host networking", "scripts/gate_lib.sh",
     '          if [ "${SENTINEL_DOCKER_NETWORK_HOST:-}" != 1 ]; then', '          if false; then', 1),
    ("G7 preflight: a directory passes as the build CA", "scripts/gate_lib.sh",
     '[ ! -f "$ca" ] || ', '', 1),
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


def check_targets() -> int:
    """Fast check (no test is run): every mutant's target text occurs exactly the expected number of times in its file. A STALE mutant
    means a refactor moved the code it guards; this catches it in a second instead of at the end of a 45-minute gate."""
    stale = []
    for name, rel, old, new, count in MUTANTS + FRONTEND_MUTANTS:
        try:
            n = (ROOT / rel).read_text().count(old)
        except OSError as e:
            stale.append(f"{name}: cannot read {rel} ({e})")
            continue
        if n != count:
            stale.append(f"{name}: expected {count} occurrence(s) of the target in {rel}, found {n}")
    for s_ in stale:
        print("STALE   ", s_)
    print(f"mutation targets: {len(MUTANTS) + len(FRONTEND_MUTANTS) - len(stale)} current, {len(stale)} stale")
    return 1 if stale else 0


def main() -> int:
    if "--check-targets" in sys.argv[1:]:
        return check_targets()
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
