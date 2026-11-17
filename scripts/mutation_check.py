"""Mutation check: proves the test suite is not vacuous.

For each known bug, re-introduce it into a THROWAWAY copy of the repo and run the backend
tests. The check passes only if the suite goes RED for every mutant. Also fails if a
mutation's target text is not found (a stale mutation would silently prove nothing).

    python scripts/mutation_check.py                          every mutant (GATE_TIER=full)
    python scripts/mutation_check.py --check-targets          only check that every target is current (seconds; no test runs)
    python scripts/mutation_check.py --changed-since REF      only the mutants whose target file changed since REF: committed on this
                                                              branch (git diff REF...HEAD) plus staged, unstaged and untracked files
                                                              (GATE_TIER=pr, DECISIONS.md D30); none changed = a quick pass that says so
"""
import argparse, shutil, subprocess, sys, tempfile
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
    # kernel confinement of auto-allowed path calls (DECISIONS.md D31; replaced the path prediction mutants H29-H41)
    ("C1 grant walk follows symlinks (openat2 without RESOLVE_NO_SYMLINKS: a link names its target)", "sentinel_proxy/sandbox.py",
     "RESOLVE_GRANT = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS", "RESOLVE_GRANT = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS", 1),
    ("C2 grant walk may leave its base (RESOLVE_BENEATH dropped: '..' escapes)", "sentinel_proxy/sandbox.py",
     "RESOLVE_GRANT = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS", "RESOLVE_GRANT = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS", 1),
    ("C3 the confined spec keeps the server's read/write directories", "sentinel_proxy/confine.py",
     "    out.update(read=[], write=[], require=True, grants=grants)", "    out.update(require=True, grants=grants)", 1),
    ("C4 a list grant also grants READ_FILE beneath the directory", "sentinel_proxy/sandbox.py",
     '"list": FS_READ_DIR, "write"', '"list": FS_READ_DIR | FS_READ_FILE, "write"', 1),
    ("C5 the proxy runs a confined call in the session process", "sentinel_proxy/proxy.py",
     "        if per_call or decision.confine:", "        if per_call:", 1),
    ("C6 the worker status check is skipped (call_tool on an unproven worker)", "sentinel_proxy/proxy.py",
     "                            unconfined = not (confine.status_ok(tap.status) and confine.write_status_ok(tap.status, snaps))", "                            unconfined = False", 1),
    ("C7 hub ignores confinable=false (path allows of an unsandboxed server are auto-allowed)", "server/inbox_hub.py",
     "session.policy.evaluate_call, server, tool, args, confinable=confinable,", "session.policy.evaluate_call, server, tool, args, confinable=True,", 1),
    ("C8 hub omits confine in proxy_decision", "server/inbox_hub.py", '            msg["confine"] = confine', "            pass", 1),
    ("C9 an allow rule without confine is not floored at ask", "server/policy.py",
     "    if d.confine is None:\n        if d.rule_id is not None or slots:", "    if d.confine is None:\n        if False:", 1),
    ("C10 a path-slot argument outside confine is not floored at ask", "server/policy.py",
     "    if slots - set(d.confine):", "    if False:", 1),
    ("C11 proxy belt removed (a policy approval of a path call without confine runs unconfined)", "sentinel_proxy/proxy.py",
     '        if decision.reason == "policy" and not decision.confine and confine.has_path_values(args):', "        if False:", 1),
    ("C12 a failed grant falls back to granting its base directory", "sentinel_proxy/sandbox_exec.py",
     "            if fd is None:\n                continue", "            if fd is None:\n                fd = os.open(base, os.O_PATH | os.O_CLOEXEC)", 1),
    ("C13 hub reads a missing confinable as true (an old proxy's path calls are auto-allowed)", "server/inbox_hub.py",
     '        confinable = frame.get("confinable") is True', '        confinable = frame.get("confinable", True) is not False', 1),
    ("C14 a too-broad sandbox.runtime is accepted at config validation", "sentinel_proxy/sandbox.py",
     "    if why := runtime_problem(spec):\n        raise SandboxSpecError(why)", "    pass", 1),
    ("C15 server_confinable does not fail closed on a too-broad runtime", "sentinel_proxy/confine.py",
     "    if why := sandbox.runtime_problem(sc.sandbox):", "    if False:", 1),
    ("C16 precheck drops the lexical resolution (the card shows only the kernel-order decoy)", "sentinel_proxy/confine.py",
     "                            if lex != links[label]:", "                            if False:", 1),
    ("C17 lint is silent about a path-like argument under an empty confine", "server/policy.py",
     "                    if like:\n", "                    if False:\n", 1),
    ("C19 hub drops links_lexical from the pending card", "server/inbox_hub.py",
     '            if p.links_lexical:\n', '            if False:\n', 1),
    ("C18 a standing rule for a directory-listing tool confines it with read", "server/policy_writer.py",
     'right = "list" if tool in P.LIST_TOOLS else "read"', 'right = "read"', 1),
    # phase 1 of the narrow write right: what is pinned BEFORE `write` exists (rights arithmetic, refusal at every layer, failure paths, guards)
    ("WR1 grants: the right string is no longer validated (a `write` grant is accepted by the spec)", "sentinel_proxy/sandbox.py",
     "        if not isinstance(right, str) or right not in GRANT_RIGHTS:", "        if False:", 1),
    ("WR2 grants: a NUL byte in a value is accepted by the spec (the C-string truncation is then the worker's problem)", "sentinel_proxy/sandbox.py",
     'or len(value) > MAX_PATH_LEN or "\\x00" in value:', "or len(value) > MAX_PATH_LEN:", 1),
    ("WR3 the write grant also grants EXECUTE (a written file could be run)", "sentinel_proxy/sandbox.py",
     '"write": FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE}', '"write": FS_EXECUTE | FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE}', 1),
    ("WR4 a read grant also grants WRITE_FILE on the named file", "sentinel_proxy/sandbox.py",
     'GRANT_RIGHTS = {"read": FS_READ_FILE,', 'GRANT_RIGHTS = {"read": FS_READ_FILE | FS_WRITE_FILE,', 1),
    ("WR5 rule_access: a directory-only right is no longer masked off for a file", "sentinel_proxy/sandbox.py",
     "    allowed = rights & fs_mask(abi)\n    if not is_dir:\n        allowed &= _FILE_RIGHTS\n    return allowed", "    allowed = rights & fs_mask(abi)\n    return allowed", 1),
    ("WR6 rule_access: rights are no longer limited to what the ABI handles (a bit the kernel does not know is passed on)", "sentinel_proxy/sandbox.py",
     "    allowed = rights & fs_mask(abi)\n", "    allowed = rights\n", 1),
    ("WR7 the operator's write set gains EXECUTE (a written file could be run)", "sentinel_proxy/sandbox.py",
     "_WRITE_RIGHTS = (FS_READ_FILE | FS_READ_DIR | FS_WRITE_FILE", "_WRITE_RIGHTS = (FS_EXECUTE | FS_READ_FILE | FS_READ_DIR | FS_WRITE_FILE", 1),
    ("WR8 fs_rules gives the operator's read directories the write rights", "sentinel_proxy/sandbox.py",
     '    rules += [(p, _READ_RIGHTS) for p in spec["read"]]', '    rules += [(p, _WRITE_RIGHTS) for p in spec["read"]]', 1),
    ("WR9 open_grant no longer checks the kind (a read grant may cover a directory, a list grant a file)", "sentinel_proxy/sandbox.py",
     '        elif stat.S_ISDIR(st.st_mode) == (right == "list"):', "        elif True:", 1),
    ("WR10 open_grant leaks the descriptor of a wrong-kind object", "sentinel_proxy/sandbox.py",
     "    os.close(fd)\n    return None", "    return None", 1),
    ("WR11 the number of grants in a worker spec is no longer capped", "sentinel_proxy/sandbox.py",
     "    if not isinstance(v, list) or len(v) > MAX_GRANTS:", "    if not isinstance(v, list):", 1),
    ("WR12 the wire accepts an unknown right in a policy approval's confine map", "sentinel_proxy/backend.py",
     'x in ("read", "list", "write") for k, x in v.items()', 'x in ("read", "list", "write", "append") for k, x in v.items()', 1),
    ("WR13 policy accepts an unknown right as a confine right", "server/policy.py",
     'CONFINE_RIGHTS = ("read", "list", "write")', 'CONFINE_RIGHTS = ("read", "list", "write", "append")', 1),
    ("WR14 a standing rule built from a call confines its path arguments with `write`", "server/policy_writer.py",
     'right = "list" if tool in P.LIST_TOOLS else "read"', 'right = "list" if tool in P.LIST_TOOLS else "write"', 1),
    ("WR15 precheck: an escape from the base (EXDEV) is confinable again", "sentinel_proxy/confine.py",
     "                    elif e.errno != errno.ENOENT and e.errno != errno.ENOTDIR:", "                    elif False:", 1),
    ("WR16 precheck: a name beneath a file (ENOTDIR) is no longer a plain missing name", "sentinel_proxy/confine.py",
     "                    elif e.errno != errno.ENOENT and e.errno != errno.ENOTDIR:", "                    elif e.errno != errno.ENOENT:", 1),
    ("WR17 a home-relative value is walked (confinable) instead of refused", "sentinel_proxy/confine.py",
     '    if not value or value.startswith("~"):', "    if not value:", 1),
    ("WR18 a timed-out confined worker is reported as a denial", "sentinel_proxy/proxy.py",
     '            return _error(f"Downstream server {sc.name!r}: worker timed out")', '            return _denied("timeout")', 1),
    ("WR19 a failed confined worker is reported to the hub as ok", "sentinel_proxy/proxy.py",
     '                await self._send_result(call_id, "error", f"worker failed: {type(e).__name__}", snaps, sent)', '                await self._send_result(call_id, "ok", f"worker failed: {type(e).__name__}", snaps, sent)', 1),
    ("WR20 a session downstream whose transport failed is not marked dead (later calls still go to the hub)", "sentinel_proxy/proxy.py",
     "            d.dead = True\n            log(f\"downstream", "            pass\n            log(f\"downstream", 1),
    ("WR21 a confined worker's result summary is not scrubbed of the call's secrets", "sentinel_proxy/proxy.py",
     'await self._send_result(call_id, "error" if res.is_error else "ok", scrub(_summary(res), vals), snaps, sent)', 'await self._send_result(call_id, "error" if res.is_error else "ok", _summary(res), snaps, sent)', 1),
    ("WR22 a required sandbox that reported no status is accepted at startup", "sentinel_proxy/proxy.py",
     '            if sc.sandbox["require"]:\n                raise SandboxRefused(f"server {sc.name!r}: the sandbox reported no status', '            if False:\n                raise SandboxRefused(f"server {sc.name!r}: the sandbox reported no status', 1),
    ("WR23 a required sandbox with a missing layer is accepted at startup", "sentinel_proxy/proxy.py",
     '        if st.get("missing") and sc.sandbox["require"]:', "        if False:", 1),
    ("WR24 hub: a policy resolution that raises turns the policy OFF (legacy auto-approve) instead of broken", "server/inbox_hub.py",
     'session.policy_mode, session.policy, session.policy_registry = True, None, None', 'session.policy_mode, session.policy, session.policy_registry = False, None, None', 1),
    ("WR25 hub: an unexpected error while handling a call approves it", "server/inbox_hub.py",
     'logger.exception("inbox: unexpected error handling call %r; denying", call_id)\n            session.pending.pop(call_id, None)\n            await self._reply(session, call_id, "deny", "invalid")',
     'logger.exception("inbox: unexpected error handling call %r; denying", call_id)\n            session.pending.pop(call_id, None)\n            await self._reply(session, call_id, "approve", "invalid")', 1),
    ("WR26 hub: a verdict outside allow/deny/ask is trusted", "server/inbox_hub.py",
     '                    if verdict not in ("allow", "deny", "ask"):', "                    if False:", 1),
    ("WR27 hub: identity mode accepts a UI frame without a principal", "server/inbox_hub.py",
     "        if self.identity_mode and principal is None:\n            logger.warning(\"inbox: ignoring a UI frame from an unauthenticated connection\")",
     "        if False:\n            logger.warning(\"inbox: ignoring a UI frame from an unauthenticated connection\")", 1),
    ("WR28 hub: an authentication that blows up is not refused as unauthorized", "server/inbox_hub.py",
     'logger.exception("inbox: authentication failed unexpectedly")\n        return None, "unauthorized"', 'logger.exception("inbox: authentication failed unexpectedly")\n        return None, "ok"', 1),
    ("WR29 policy_writer: the written file is no longer checked to reload to the digest reported", "server/policy_writer.py",
     "        if P.Policy(P._parse_bytes(text, p)).digest() != after.digest():", "        if False:", 1),
    ("WR30 policy_writer: the size of the resulting policy is no longer limited", "server/policy_writer.py",
     "    if len(text) > P.MAX_FILE_BYTES:\n        raise _fail(\"invalid_policy\", \"resulting policy file would be too large\")", "    if False:\n        raise _fail(\"invalid_policy\", \"resulting policy file would be too large\")", 1),
    ("WR31 policy_writer: an unexpected exception's text (a path, a secret) is passed on to the hub", "server/policy_writer.py",
     'raise _fail("write_failed", type(e).__name__) from None', 'raise _fail("write_failed", str(e)) from None', 1),
    ("WR32 policy_writer: a file that is no longer a regular file after the open is read anyway", "server/policy_writer.py",
     "        if not stat.S_ISREG(os.fstat(fd).st_mode):\n            raise _fail(\"write_failed\", \"not a regular file\")", "        if False:\n            raise _fail(\"write_failed\", \"not a regular file\")", 1),
    ("WR33 policy_writer: an Always-allow with a path-like argument that is not a confine slot is built (confine {} runs it unconfined)", "server/policy_writer.py",
     "        if any(isinstance(k, str) and P.is_path_like(k) and k not in confine for k in args):", "        if False:", 1),
    ("WR34 precheck: a NUL in a value is no longer noticed (the walk truncates it, the call is auto-allowed)", "sentinel_proxy/confine.py",
     '            if walks is None or "\\x00" in value:', "            if walks is None:", 1),
    ("WR35 grants: an unhashable right raises TypeError instead of SandboxSpecError", "sentinel_proxy/sandbox.py",
     "        if not isinstance(right, str) or right not in GRANT_RIGHTS:", "        if right not in GRANT_RIGHTS:", 1),
    ("WR36 proxy: a closed-pipe MCP error does not mark the session downstream dead", "sentinel_proxy/proxy.py",
     "            if _is_closed(e):", "            if False:", 1),
    ("WR37 proxy: any MCP error from a session downstream marks it dead (an ordinary tool error kills the server)", "sentinel_proxy/proxy.py",
     "            if _is_closed(e):", "            if True:", 1),
    ("WR38 proxy: a worker's ExceptionGroup is not unwrapped (the real MCP message is lost)", "sentinel_proxy/proxy.py",
     "    while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:", "    while False:", 1),
    # the narrow write right (DECISIONS.md D32): every decision that keeps an auto-allowed write to ONE existing plain file with a before-image
    ("WW1 write grant: a second name (nlink > 1) no longer refuses the grant", "sentinel_proxy/sandbox.py",
     "stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and not", "stat.S_ISREG(st.st_mode) and not", 1),
    ("WW2 write grant: an exec bit no longer refuses the grant", "sentinel_proxy/sandbox.py",
     " and not st.st_mode & 0o111 and st.st_size <= WRITE_MAX_BYTES)", " and st.st_size <= WRITE_MAX_BYTES)", 1),
    ("WW3 write grant: a directory, FIFO or device may carry it", "sentinel_proxy/sandbox.py",
     "    return (stat.S_ISREG(st.st_mode) and st.st_nlink == 1", "    return (st.st_nlink == 1", 1),
    ("WW4 write grant: the size cap is gone (no before-image can be kept)", "sentinel_proxy/sandbox.py",
     " and not st.st_mode & 0o111 and st.st_size <= WRITE_MAX_BYTES)", " and not st.st_mode & 0o111)", 1),
    ("WW5 write grant drops TRUNCATE (O_TRUNC of the granted file fails)", "sentinel_proxy/sandbox.py",
     '"write": FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE}', '"write": FS_READ_FILE | FS_WRITE_FILE}', 1),
    ("WW6 write grant adds MAKE_REG (it can create files beside the granted one)", "sentinel_proxy/sandbox.py",
     '"write": FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE}', '"write": FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE | FS_MAKE_REG}', 1),
    ("WW7 open_grant walks an absolute write value from `/` (the write-directory ceiling is lost)", "sentinel_proxy/sandbox.py",
     '    if right == "write" and (value.startswith("/") or ".." in value.split("/")):\n        return None\n    try:',
     '    try:', 1),
    ("WW8 the spec accepts an absolute or `..` write value", "sentinel_proxy/sandbox.py",
     '        if right == "write" and (value.startswith("/") or ".." in value.split("/")):\n            raise SandboxSpecError(',
     '        if False:\n            raise SandboxSpecError(', 1),
    ("WW9 the trampoline applies a write grant below Landlock ABI 3 (truncate is not mediated there)", "sentinel_proxy/sandbox_exec.py",
     '        if any(g[2] == "write" for g in grants or []) and not sandbox.write_abi_ok(abi):', "        if False:", 1),
    ("WW10 the proxy treats Landlock ABI < 3 as able to confine a write", "sentinel_proxy/confine.py",
     " or not sandbox.write_abi_ok(sandbox.landlock_abi()):", ":", 1),
    ("WW11 the worker does not report the inode and link count of its write grant", "sentinel_proxy/sandbox_exec.py",
     '                write_granted.append({"value": value, "dev": o.st_dev, "ino": o.st_ino, "nlink": o.st_nlink})', "                pass", 1),
    ("WW12 a worker with a write grant keeps the operator's file-size limit (a granted file can grow without bound)", "sentinel_proxy/confine.py",
     'rl["fsize_mb"] = min(rl.get("fsize_mb", WRITE_FSIZE_MB), WRITE_FSIZE_MB)', 'rl["fsize_mb"] = rl.get("fsize_mb", 10 ** 6)', 1),
    ("WW13 precheck: a second name (nlink > 1) is confinable", "sentinel_proxy/confine.py",
     '        if st.st_nlink != 1:\n            return False, "hard_link"', '        if False:\n            return False, "hard_link"', 1),
    ("WW14 precheck: an exec bit is confinable", "sentinel_proxy/confine.py",
     '        if st.st_mode & 0o111:\n            return False, "executable"', '        if False:\n            return False, "executable"', 1),
    ("WW15 precheck: the walk starts at `/` instead of the write directory (a symlinked ancestor is judged, the ceiling is lost)", "sentinel_proxy/confine.py",
     "            fd = sandbox.open_beneath(base, rel)\n        except ValueError:", '            fd = sandbox.open_beneath("/", value)\n        except ValueError:', 1),
    ("WW16 precheck: a file past the size cap is confinable", "sentinel_proxy/confine.py",
     '        if st.st_size > WRITE_MAX_BYTES:\n            return False, "too_large"', '        if False:\n            return False, "too_large"', 1),
    ("WW17 write_target accepts an unnormalised value (`..`, `//`, `/./`)", "sentinel_proxy/confine.py",
     "    if posixpath.normpath(value) != value:\n        return None\n    best = None", "    best = None", 1),
    ("WW18 precheck: no before-image is needed for an auto-allow", "sentinel_proxy/confine.py",
     "        if not _undo_ok(undo_dir, sc, st.st_size):", "        if False:", 1),
    ("WW19 the proxy takes no before-image although it grants the write", "sentinel_proxy/proxy.py",
     "                    snaps = await asyncio.to_thread(self._take_snapshots, write_grants, args, call_id)", "                    snaps = []", 1),
    ("WW20 the write status check is dropped (a swapped inode or a second name is not noticed)", "sentinel_proxy/proxy.py",
     "                            unconfined = not (confine.status_ok(tap.status) and confine.write_status_ok(tap.status, snaps))",
     "                            unconfined = not confine.status_ok(tap.status)", 1),
    ("WW21 the proxy's own check of a write decision is removed (a forged write approval runs)", "sentinel_proxy/proxy.py",
     '            if set(decision.confine) != {"path"} or frame.get("write_confinable") is not True or not d.confinable:', "            if False:", 1),
    ("WW22 a write decision with no write grant still starts a worker", "sentinel_proxy/proxy.py",
     '            if ("write" in confine_map.values()) != bool(write_grants):', "            if False:", 1),
    ("WW23 a before-image that cannot be taken no longer stops the call", "sentinel_proxy/proxy.py",
     '                    if os.environ.get(confine.FORCE_ENV) != "force_true":       # test knob', "                    if False:       # test knob", 1),
    ("WW24 the before-image is world-readable", "sentinel_proxy/confine.py",
     "os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)", "os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)", 1),
    ("WW25 write_status_ok compares only the number of grants (any inode passes)", "sentinel_proxy/confine.py",
     '    return sorted(rows) == sorted((s["value"], s["dev"], s["ino"]) for s in snaps)', "    return len(rows) == len(snaps)", 1),
    ("WW26 write_status_ok ignores the link count", "sentinel_proxy/confine.py",
     'isinstance(g.get("value"), str) and g.get("nlink") == 1 and type(g.get("nlink")) is int', 'isinstance(g.get("value"), str)', 1),
    ("WW27 hub floor: a write allow stands although the proxy did not vouch for it", "server/policy.py",
     '    if "write" in d.confine.values() and write_confinable is not True:', "    if False:", 1),
    ("WW28 hub reads a missing write_confinable as true (an old proxy's writes are auto-allowed)", "server/inbox_hub.py",
     '        write_confinable = frame.get("write_confinable") is True', '        write_confinable = frame.get("write_confinable", True) is not False', 1),
    ("WW29 hub ignores what the proxy said about the write (always confinable)", "server/inbox_hub.py",
     "                                                  write_confinable=write_confinable,", "                                                  write_confinable=True,", 1),
    ("WW30 policy: a write rule need not bound what is written (max_len)", "server/policy.py",
     '    if not any(a.op == "max_len" and len(a.path) == 1 and a.path[0] in ("content", "edits") for a in args):', "    if False:", 1),
    ("WW31 policy: a write rule need not narrow `path` with a glob", "server/policy.py",
     '    if not any(a.op == "glob" and a.path == ("path",) and _narrow_glob(a) for a in args):', "    if False:", 1),
    ("WW32 policy: write is accepted for any argument and next to others", "server/policy.py",
     '    if set(c) != {"path"}:\n        bad =', '    if False:\n        bad =', 1),
    ("WW33 policy: a write rule may leave out the tool", "server/policy.py",
     '    if tool is None:\n        errs.append(f"{where}.confine: a write rule needs when.tool', '    if False:\n        errs.append(f"{where}.confine: a write rule needs when.tool', 1),
    ("WW34 starter: the write ask rule for sensitive paths is an allow", "server/policies/starter.json",
     '{"id": "ask-sensitive-write-path", "verdict": "ask",', '{"id": "ask-sensitive-write-path", "verdict": "allow",', 1),
    ("WW35 starter: .github/ is no longer a sensitive write path", "server/policies/starter.json",
     '".git/", ".github/", ".gitlab-ci"', '".git/", ".gitlab-ci"', 1),
    ("WW36 starter: python files are doc extensions", "server/policies/starter.json",
     '"*.log"]}, {"path": "content", "op": "glob"', '"*.log", "*.py"]}, {"path": "content", "op": "glob"', 1),
    ("WW37 starter: the write allow takes any extra argument (Desktop Commander's `mode`)", "server/policies/starter.json",
     '"arg_keys": ["path", "content"], "args": [{"path": "path", "op": "glob"', '"arg_keys": ["path", "content", "mode"], "args": [{"path": "path", "op": "glob"', 1),
    ("WW38 hub: the card carries no write finding", "server/inbox_hub.py",
     '        if p.write is not None:\n            d["write"] = p.write', '        if False:\n            d["write"] = p.write', 1),
    ("WW39 hub: the writes the proxy reports are not logged", "server/inbox_hub.py",
     '                rec["writes"] = writes ', '                pass ', 1),
    ("WW40 hub: a reason outside the closed set reaches the card", "server/inbox_hub.py",
     'frame["write_why"] in WRITE_WHYS and not write_confinable', 'not write_confinable', 1),
    ("WW41 proxy: a timed out worker's write is not reported", "sentinel_proxy/proxy.py",
     "        if snaps and sent:\n", '        if snaps and sent and summary != "worker timed out":\n', 1),
    ("WW42 config: a write directory may contain the undo store", "sentinel_proxy/config.py",
     "            if _covers(n, undo) or _covers(undo, n):", "            if False:", 1),
    ("WW43 config: a write directory may contain the proxy's config file", "sentinel_proxy/config.py",
     "            if config_path and any(_covers(n, c) for c in config_path):", "            if False:", 1),
    ("WW44 precheck: an undo directory inside a write directory is fine", "sentinel_proxy/confine.py",
     "    for d in write_dirs(sc):\n        if any(_covers(d, x)", "    for d in []:\n        if any(_covers(d, x)", 1),
    ("WW45 a write the proxy cannot confine is reported with the wrong reason (always unsupported)", "sentinel_proxy/proxy.py",
     '            out["write_why"] = why if why in confine.WRITE_WHYS else "unsupported"', '            out["write_why"] = "unsupported"', 1),
    ("WW46 the after-image never says the name leads elsewhere", "sentinel_proxy/confine.py",
     '        return {"size_after": n, "sha256_after": h.hexdigest(), "replaced": (st.st_dev, st.st_ino) != (snap["dev"], snap["ino"])}',
     '        return {"size_after": n, "sha256_after": h.hexdigest(), "replaced": False}', 1),
    ("WW47 an undo copy may be overwritten by a second snapshot of the same call", "sentinel_proxy/confine.py",
     "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW", "os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW", 1),
    ("WW48 expired before-images are never removed from the undo store", "sentinel_proxy/proxy.py",
     "            confine.prune_undo(self.cfg.undo_dir, protect=call_id)", "            (lambda *a, **k: None)(self.cfg.undo_dir, protect=call_id)", 1),
    ("WW49 eventlog show hides what an auto-written call wrote", "server/eventlog_cli.py",
     '        for w in p.get("writes") if isinstance(p.get("writes"), list) else []:', '        for w in []:', 1),
    ("WW50 glob list: a list of patterns matches only its first pattern", "server/policy.py",
     "        return any(fnmatchcase(v, x) for x in val) if isinstance(val, tuple) else fnmatchcase(v, val)", "        return fnmatchcase(v, val[0] if isinstance(val, tuple) else val)", 1),
    # review round of D32
    ("WW51 starter: requirements files are no longer a sensitive write path", "server/policies/starter.json",
     '".env", "requirements", "constraints"', '".env", "constraints"', 1),
    ("WW52 starter: agent skill and rule directories (.windsurf) are no longer sensitive write paths", "server/policies/starter.json",
     '"conventions.md", ".windsurf", ".clinerules"', '"conventions.md", ".clinerules"', 1),
    ("WW53 precheck: the size of the edits is not bounded (one 10M-character edit is confinable)", "sentinel_proxy/confine.py",
     '    if isinstance(args, dict) and "edits" in args and edits_chars(args["edits"]) > WRITE_EDITS_MAX_CHARS:', "    if False:", 1),
    ("WW54 undo store: a full store (too many calls) still has room, so a later write can push nothing out but also never asks", "sentinel_proxy/confine.py",
     "    return calls < UNDO_MAX_CALLS and used + size <= UNDO_MAX_BYTES", "    return used + size <= UNDO_MAX_BYTES", 1),
    ("WW55 undo store: the size of the store is never limited", "sentinel_proxy/confine.py",
     "    return calls < UNDO_MAX_CALLS and used + size <= UNDO_MAX_BYTES", "    return calls < UNDO_MAX_CALLS", 1),
    ("WW56 undo directory: an owner other than the proxy user is accepted", "sentinel_proxy/confine.py",
     "st.st_uid == os.geteuid() and not st.st_mode & 0o022", "not st.st_mode & 0o022", 1),
    ("WW57 undo directory: a group- or world-writable directory is accepted", "sentinel_proxy/confine.py",
     "st.st_uid == os.geteuid() and not st.st_mode & 0o022", "st.st_uid == os.geteuid()", 1),
    ("WW58 snapshot: a full store does not stop the copy", "sentinel_proxy/confine.py",
     "        if not undo_has_room(undo_dir, len(data)):", "        if False:", 1),
    ("WW59 config guard: a symlinked config file is judged by the link's own place only", "sentinel_proxy/config.py",
     "os.path.abspath(config_path), os.path.realpath(config_path)", "os.path.abspath(config_path), os.path.abspath(config_path)", 1),
    ("WW60 retention: everything is pruned whatever its age (the original before-image goes first)", "sentinel_proxy/confine.py",
     "and now - e.stat(follow_symlinks=False).st_mtime > max_age_s:", "and True:", 1),
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
    # CI tiers (DECISIONS.md D30; tests/test_gate_tiers.py, tests/test_mutation_check.py)
    ("T1 a tier drops its own stages (rank compared with > instead of >=)", "scripts/gate_lib.sh",
     '[ "$(gate_tier_rank "${GATE_TIER:-full}")" -ge "$(gate_tier_rank "$1")" ]', '[ "$(gate_tier_rank "${GATE_TIER:-full}")" -gt "$(gate_tier_rank "$1")" ]', 1),
    ("T2 an unknown GATE_TIER runs anyway (as nothing beyond push)", "scripts/gate_lib.sh",
     'if [ "$(gate_tier_rank "${GATE_TIER:-full}")" = 0 ]; then', 'if false; then', 1),
    ("T3 the default tier is push, not full (a bare verify.sh silently runs less)", "scripts/gate_lib.sh",
     '[ "$(gate_tier_rank "${GATE_TIER:-full}")" -ge', '[ "$(gate_tier_rank "${GATE_TIER:-push}")" -ge', 1),
    ("T4 slow tests are selected by no tier", "scripts/gate_lib.sh",
     "GATE_PYTEST_PR='slow and not research", "GATE_PYTEST_PR='slow and research", 1),
    ("T5 research tests also run in the push stage (selected twice)", "scripts/gate_lib.sh",
     "GATE_PYTEST_PUSH='not reality and not claude_live and not slow and not research'", "GATE_PYTEST_PUSH='not reality and not claude_live and not slow'", 1),
    ("T6 the research browser stages run on every PR", "scripts/verify.sh",
     "    if at_tier weekly; then\n", "    if at_tier pr; then\n", 1),
    ("T7 the reality stages and the live-coverage proof are skipped at pr", "scripts/verify.sh",
     'if at_tier pr; then\n  run "reality: hostile', 'if at_tier full; then\n  run "reality: hostile', 1),
    ("T8 full runs only the changed-files mutants", "scripts/verify.sh",
     'if at_tier full; then\n  run "mutation check (tests must', 'if at_tier weekly; then\n  run "mutation check (tests must', 1),
    ("T9 a stage listing exits 0 (could pass for a green gate)", "scripts/verify.sh",
     'nothing ran)"; exit 2; fi', 'nothing ran)"; exit 0; fi', 1),
    # T10-T14 mutate this file: their targets are split into adjacent literals so this list does not contain them a second time
    ("T10 changed-since ignores the branch's commits", "scripts/mutation_check.py",
     'return (_git(root, "diff", "--name-only", f"{ref}.' '..HEAD") | ', 'return (', 1),
    ("T11 changed-since ignores untracked files", "scripts/mutation_check.py",
     '            | _git(root, "ls-files", "--others", ' '"--exclude-standard"))', '            )', 1),
    ("T12 changed-since counts the base branch's own later commits (two-dot diff)", "scripts/mutation_check.py",
     'f"{ref}.' '..HEAD"', 'f"{ref}..HEAD"', 1),
    ("T13 changed-since selects every mutant", "scripts/mutation_check.py",
     "    return [m for m in mutants if m[1] in changed or (gate_tests and m[1].startswith(GATE_" "SCRIPTS))]", "    return list(mutants)", 1),
    ("T14 an unknown ref selects nothing and passes", "scripts/mutation_check.py",
     '        raise SystemExit(f"mutation ' 'check: git', '        return set()\n        raise SystemExit(f"mutation ' 'check: git', 1),
    ("T15 gate-script mutants run the whole serial suite before the gate's own tests (minutes per mutant instead of seconds)",
     "scripts/mutation_check.py", 'if rel.startswith(GATE_' 'SCRIPTS) else []', 'if False else []', 1),
    ("T16 a changed test file selects only the mutants whose target changed (a weakened killer slips through)", "scripts/mutation_check.py",
     "    if tests - gate_" "tests:\n        return list(mutants)\n", "", 1),
    ("T17 a changed gate test selects none of the gate-script mutants it kills", "scripts/mutation_check.py",
     "(gate_tests and m[1].startswith(GATE_" "SCRIPTS))", "False", 1),
    ("T18 no origin default branch silently diffs against HEAD (nothing selected) instead of failing", "scripts/mutation_check.py",
     '    raise SystemExit("mutation check: no origin/' 'HEAD', '    return "HEAD"\n    raise SystemExit("mutation check: no origin/' 'HEAD', 1),
    ("T19 the sandbox trampoline ignores TMPDIR (the boundary leak checks would look in the wrong place)", "sentinel_proxy/sandbox_exec.py",
     'home = tempfile.mkdtemp(prefix="sentinel-sbx-")', 'home = tempfile.mkdtemp(prefix="sentinel-sbx-", dir="/tmp")', 1),
    ("T20 sandbox tests skip silently although SENTINEL_SANDBOX_REQUIRED=1 (CI)", "tests/no_skip_plugin.py",
     'missing and os.environ.get("SENTINEL_SANDBOX_' 'REQUIRED") != "1"', "missing", 1),
    ("T21 the Claude key stays in the environment of every stage", "scripts/gate_lib.sh", "  unset SENTINEL_CLAUDE_API_KEY\n", "", 1),
]

# Frontend mutants: killed by `vitest run` (frontend/src/**/*.test.{ts,tsx}), not by pytest.
FRONTEND_MUTANTS = [
    ("FW1 the card does not show that a held call is a write", "frontend/src/components/Inbox.tsx",
     "      {call.write && (", "      {false && call.write && (", 1),
    ("FW2 the resolved row hides what an auto-allowed write wrote", "frontend/src/components/Inbox.tsx",
     "      {item.result?.writes && (", "      {false && item.result?.writes && (", 1),
    ("FW3 a reason outside the closed set is shown as the proxy's own text", "frontend/src/lib/inboxRoute.ts",
     '(WRITE_WHYS as readonly string[]).includes(v.why) ? (v.why as WriteWhy) : undefined', '(typeof v.why === "string" ? (v.why as WriteWhy) : undefined)', 1),
    ("F8 the card shows only one resolution of a link (the lexical one is dropped)", "frontend/src/components/Inbox.tsx",
     "${l.lexical ? ` (or ${l.lexical}, depending", "${false ? ` (or ${l.lexical}, depending", 1),
    ("F1 drawer shows the raw (multi-line) tool name", "frontend/src/components/NodeDetail.tsx", "singleLine(data.toolName)", "String(data.toolName)", 1),
    ("F2 drawer colours drift against the old 2.5", "frontend/src/components/NodeDetail.tsx", "driftPoint.mahalanobisDistance > pointThreshold(driftPoint.threshold)", "driftPoint.mahalanobisDistance > 2.5", 1),
    ("F7 the UI ignores the threshold carried by the event", "frontend/src/lib/drift.ts", "threshold > 0 ? threshold : DRIFT_THRESHOLD", "threshold > 0 ? DRIFT_THRESHOLD : DRIFT_THRESHOLD", 1),
    ("F3 sanitiser removes nothing", "frontend/src/lib/safeText.ts", '.replace(UNSAFE, "")', '.replace(UNSAFE, "$&")', 1),
    ("F5 the standing-rule frame is built without confirm=true semantics (unknown verdicts are offered)", "frontend/src/lib/inboxView.ts", "confirm: true as const", "confirm: false as unknown as true", 1),
    ("F6 the UI offers standing rules although the hub says it is not writable", "frontend/src/lib/inboxRoute.ts", "policy_writable: isRec(event.capabilities) && event.capabilities.policy_writable === true,", "policy_writable: true,", 1),
    ("F4 result panel is raw text again", "frontend/src/components/NodeDetail.tsx", "<AgentText text={data.result} />", "<pre className=\"detail-code\">{String(data.result)}</pre>", 1),
]


def run_suite(tree: Path, rel: str = "") -> int:
    """The default suite, serial, stopping at the first failure. A mutant of a gate script (scripts/*, tests/*.py) first meets the top-level
    tests/test_*.py, the gate's own tests (seconds): its only killers sit at the END of the collection order, so the whole suite would
    otherwise run before them. A mutant that survives that quick pass still has to survive the whole suite. (Not pytest-xdist: with
    workers, -x does not stop early, each worker drains its queue.)"""
    quick = [str(f.relative_to(tree)) for f in sorted((tree / "tests").glob("test_*.py"))] if rel.startswith(GATE_SCRIPTS) else []
    for paths in ([quick] if quick else []) + [[]]:
        p = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", *paths],
                           cwd=tree, capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            return p.returncode
    return 0


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


def _git(root: Path, *args: str) -> set[str]:
    p = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"mutation check: git {' '.join(args)} failed: {p.stderr.strip()}")
    return {line for line in p.stdout.splitlines() if line}


def changed_files(ref: str, root: Path = ROOT) -> set[str]:
    """Files (repo-relative) changed on this branch since its merge base with `ref`, plus staged, unstaged and untracked ones.
    An unknown ref is an error (SystemExit), never an empty set: a typo must not turn into "nothing to check"."""
    return (_git(root, "diff", "--name-only", f"{ref}...HEAD") | _git(root, "diff", "--name-only", "HEAD")
            | _git(root, "ls-files", "--others", "--exclude-standard"))


def resolve_base(ref: str, root: Path = ROOT) -> str:
    """`@origin` = origin's default branch (refs/remotes/origin/HEAD, else origin/main); any other ref is used as given. No such branch is an
    error (SystemExit), never "nothing changed": set GATE_BASE."""
    if ref != "@origin":
        return ref
    for args in (["symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"], ["rev-parse", "-q", "--verify", "--abbrev-ref", "origin/main"]):
        p = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout.strip()
    raise SystemExit("mutation check: no origin/HEAD and no origin/main to diff against (git fetch origin, or set GATE_BASE to a ref)")


GATE_SCRIPTS = ("scripts/", "tests/")   # mutants of these are killed by the top-level tests/test_*.py (the gate's own tests)


def _is_gate_test(f: str) -> bool:
    return f.startswith("tests/test_") and f.endswith(".py") and "/" not in f[len("tests/"):]


def select_changed(mutants: list, changed: set[str]) -> list:
    """Mutants whose target changed. A changed or deleted test file, fixture, helper or pytest.ini can weaken any mutant's killer and there
    is no cheap, reliable mutant -> killer mapping, so it selects EVERY mutant; a changed top-level gate test (tests/test_*.py) selects the
    gate-script mutants it kills."""
    tests = {f for f in changed if f.startswith("tests/") or f == "pytest.ini"}
    gate_tests = {f for f in tests if _is_gate_test(f)}
    if tests - gate_tests:
        return list(mutants)
    return [m for m in mutants if m[1] in changed or (gate_tests and m[1].startswith(GATE_SCRIPTS))]


def run_backend(mutants: list, survivors: list, stale: list) -> None:
    for name, rel, old, new, count in mutants:
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
            rc = run_suite(tree, rel)
            print(f"{'KILLED  ' if rc != 0 else 'SURVIVED'}  {name}")
            if rc == 0:
                survivors.append(name)


def run_frontend(mutants: list, survivors: list, stale: list) -> None:
    for name, rel, old, new, count in mutants:
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="re-introduce known bugs; the suite must catch every one")
    ap.add_argument("--check-targets", action="store_true", help="only check that every mutant's target text is current")
    ap.add_argument("--changed-since", metavar="REF", help="only the mutants whose target file (or any test) changed since REF (plus the "
                    "working tree); @origin = origin's default branch")
    a = ap.parse_args(argv)
    if a.check_targets:
        return check_targets()
    backend, frontend = MUTANTS, FRONTEND_MUTANTS
    if a.changed_since:
        base = resolve_base(a.changed_since)
        changed = changed_files(base)
        backend, frontend = select_changed(MUTANTS, changed), select_changed(FRONTEND_MUTANTS, changed)
        if not backend and not frontend:
            print(f"mutation check: no mutant targets changed since {base} ({len(changed)} file(s) changed): nothing to run")
            return 0
        tests = sorted(f for f in changed if f.startswith("tests/") or f == "pytest.ini")
        print(f"mutation check: {len(backend) + len(frontend)} of {len(MUTANTS) + len(FRONTEND_MUTANTS)} mutants selected by the changes "
              f"since {base} (targets: {sorted({m[1] for m in backend + frontend} & changed)}; tests changed: {tests[:10]}"
              f"{' ...' if len(tests) > 10 else ''})")
    survivors, stale = [], []
    run_backend(backend, survivors, stale)
    run_frontend(frontend, survivors, stale)
    for s in stale:
        print("STALE   ", s)
    if survivors or stale:
        print(f"\nmutation check FAILED: {len(survivors)} survivor(s), {len(stale)} stale")
        return 1
    print(f"\nmutation check OK: all {len(backend) + len(frontend)} re-introduced bugs were caught by the suite")
    return 0


if __name__ == "__main__":
    sys.exit(main())
