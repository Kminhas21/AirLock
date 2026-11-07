# Plan: operator UI (docs/PROPOSALS.md #8), first iteration

Goal: the human who approves a held call can see WHY it was flagged, WHAT the agent has already done, can DENY WITH A REASON the agent receives, and can turn a decision into a STANDING RULE in two clicks. The UI and backend can never disagree about the drift threshold again.

## Decisions
- Scope: the proxy Inbox (the product direction) plus the threshold fix for the session view. The built-in loop's UI keeps its current panels.
- Alert evidence: no new monitor output. The UI shows what alerts already carry (`trigger`, `severity`, `drift_score`, `threshold`, `message`) as a score-vs-threshold bar plus the session's earlier DENIED calls (hub data), which is the evidence the message text refers to.
- Operator note on a denial reaches the agent (it is the human's text, sanitised, single line, <= 200 chars): "Denied by SENTINEL: human (operator note: use /project instead)". Notes are also logged and shown in the Inbox history.
- Standing rules WRITE to the policy file, so they are OFF unless the operator sets `SENTINEL_POLICY_WRITABLE=1` (and `SENTINEL_POLICY` is a usable file). The browser never sends a rule: it asks for a (verdict, scope) on a call the hub has seen and the HUB builds the rule from that call. Two-step confirm in the UI. Rules take effect for NEW proxy sessions (policy is pinned per session).

## Protocol additions (all optional fields; old peers keep working)
- `inbox_snapshot.capabilities`: `{"policy_writable": bool, "event_log": bool}`.
- `inbox_pending` gains: `session_summary` `{approved, denied, auto, policy}` (counts of resolved calls of this session, not counting this one),
  `session_history` (newest first, max 10) items `{call_id, server, tool, args_preview, decision, reason, rule_id, note, ts}`,
  `earlier_denied` (newest first, max 5, same item shape, only denials). `args_preview` = one line, <= 120 chars, secret-looking keys redacted (use `eventlog.sanitize_payload`), control/bidi stripped.
  The hub keeps a bounded ring (50) of resolved calls per session in memory (including full args, needed for rule building; never sent in full).
- `inbox_decision` gains optional `note` (string; the hub cleans it: single line, control/bidi removed, <= 200 chars; empty => absent). Stored in the `decision` event payload (`note`), echoed in `inbox_resolved.note`, and sent to the proxy in `proxy_decision.note` for human DENIALS only.
- Proxy: a deny with reason `human` and a note is reported to the agent as `Denied by SENTINEL: human (operator note: <note>)`; the proxy sanitises the note again (single line, <= 200, no control/bidi); other reasons never carry a note.
- `inbox_rule_request` (UI -> hub): `{"event":"inbox_rule_request","session_id","call_id","verdict":"allow"|"deny"|"ask","scope":"exact"|"tool_under"|"tool","confirm":true}`. Hub: needs `policy_writable`, `confirm === true`, a call it has seen in that session (pending or ring), builds the rule with `policy_writer.build_rule`, appends it with `policy_writer.append_rule`, answers ALL UIs with `{"event":"inbox_rule_result","ok":bool,"rule_id":str|null,"reason":str,"policy_digest":str|null,"applies":"new_sessions"}`. Reasons are a closed set: `ok|not_writable|not_confirmed|unknown_call|scope_not_allowed|cannot_build|invalid_policy|write_failed|log_unavailable`.
  Write-ahead: with an event log the `policy_rule_added` event (new kind; payload `{rule, digest_before, digest_after, session_id, call_id}`) is appended BEFORE the file is replaced; if that append fails nothing is written (`log_unavailable`).
- Drift threshold: `drift_update` gains optional `threshold` (number) = the detector's active breach threshold. The UI uses the latest point's threshold for the chart line and the drawer colour; recorded replays without it fall back to the constant `DRIFT_THRESHOLD` (contract test stays).

## server/policy_writer.py (pure, no FastAPI)
- `build_rule(verdict, scope, server, tool, args, *, note="") -> dict`: `exact` = server + tool + one `equals` condition per top-level scalar arg (str/int/bool, <= 20; any non-scalar => ValueError `cannot_build`);
  `tool_under` = server + tool + one `under` condition on the first arg whose key is in `path file filename dir directory target` with an absolute string value, using its parent directory (a parent of `/` or no such arg => ValueError `cannot_build`);
  `tool` = server + tool only. Scope rules: `allow` may use `exact` or `tool_under` only; `deny`/`ask` may use any scope. Rule id `ui-<verdict>-<8 hex of sha256(canonical rule)>`; `note` <= 200 chars. Server/tool names with control/bidi characters => `cannot_build`.
- `append_rule(path, rule) -> {"rule_id","digest_before","digest_after"}`: read the file once (same size limits as policy.py), refuse duplicates of an existing identical rule (idempotent: returns the existing id), append to the dict, validate the WHOLE result with `policy.load_policy` (errors => `PolicyWriteError("invalid_policy")`), write `<path>.tmp` (0600) + fsync + `os.replace`, keep `<path>.bak` of the previous bytes, fsync the directory. Raises `PolicyWriteError(reason)`; never leaves a half-written file. Serialise concurrent writers with an in-process lock and a `.lock` file (`fcntl.flock`).

## UI (Inbox cards)
- **Why flagged**: for each alert: trigger, severity, a score-vs-threshold bar (from the alert's `drift_score`/`threshold`), the alert message; below it "Earlier denied in this session" (from `earlier_denied`).
- **Session so far**: counters from `session_summary` and the last 10 calls (`session_history`: tool, server, args preview, outcome, rule id, note) as an expandable panel.
- **Deny with reason**: a text input (max 200) next to Deny; the note is sent with the decision; resolved rows show the note.
- **Make it standing**: only when `capabilities.policy_writable`; buttons "Always allow like this" (scope choice: exact | this tool under the same folder), "Always deny", "Always ask"; a confirm step showing the exact scope in words and the warning "applies to new sessions"; the result (`inbox_rule_result`) is shown as a toast/line; `tool` scope offered only for deny/ask.

## Tickets
| Id | Area | Files |
|---|---|---|
| OP1 | threshold in drift_update | `server/events.py`, `server/live_drift.py`, `frontend/src/types/contracts.ts`, store, DriftMonitor, NodeDetail, `tests/contract`, tests |
| OP2 | hub: history, note, capabilities | `server/inbox_hub.py`, `server/main.py` (capabilities), tests |
| OP3 | policy_writer | `server/policy_writer.py`, `tests/server/test_policy_writer.py` |
| OP4 | hub: standing rules (after OP2, OP3) | `server/inbox_hub.py`, `server/eventlog.py` (new kind only), tests |
| OP5 | proxy note | `sentinel_proxy/`, tests |
| OP6 | Inbox UI | `frontend/src/**` |
| OP7 | e2e, gate stage, mutants, docs/operator-ui.md, DECISIONS D20 | tests/e2e, frontend/e2e, scripts, docs |

Non-goals: monitor-side structured evidence, editing or deleting rules from the UI, rule expiry, per-operator identity (needs #6), the built-in loop's UI.
