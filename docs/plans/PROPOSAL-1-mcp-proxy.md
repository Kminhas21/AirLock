# Plan: monitor agents you didn't write (PROPOSALS.md #1), first version

## Decisions made with the owner
| Question | Answer |
|---|---|
| First target | MCP-based agents (Claude Code, Claude Desktop, Cursor, any MCP client) |
| Enforcement | BLOCK until a human decides (existing Airlock semantics: only exact "approve" approves; 300 s timeout then deny) |
| Approval UX | the existing web UI becomes an approval inbox for external sessions |
| Deployment | local developer tool: one user, localhost, smallest threat model |

## Answers to the open questions (owner)
1. Transport: **stdio only** (downstream servers are spawned by the proxy; the agent talks to the proxy over stdio).
2. Tool coverage: every tool is held for a human, EXCEPT tools the operator lists in `auto_approve` (config allowlist). The downstream
   server's own `readOnlyHint` is NOT trusted by default (a malicious server could claim it); `trust_read_only_hint: true` per server is an
   explicit opt-in. An auto-approved call that a monitor alerts on is HELD for the human (auto-approve never silences an alert).
3. Session identity: a **simple id**: `--session-id`/config `session_id`, default `proxy-<6 hex>`; must match `^[A-Za-z0-9._-]{1,40}$`;
   a second live proxy with the same id is rejected.
4. Monitors: call-based only (`SENTINEL_MONITOR` modes action_sim / registry family / union; `learned` also works without text). No reasoning
   text exists, so the monitor gets `agent_text=""`; Seismograph drift is not run for proxied sessions.

## Architecture
```
agent (MCP client) --stdio--> sentinel-proxy --stdio--> downstream MCP server(s)
                                  |  WebSocket /proxy/ws
                                  v
                          backend InboxHub  <--WebSocket /inbox/ws-->  web UI (Inbox)
```
Fail-closed everywhere: backend unreachable, hub restarted, proxy disconnected, UI absent, timeout (SENTINEL_GATE_TIMEOUT_S, default 300 s)
or any malformed message => the call is DENIED and the agent gets an MCP tool error ("denied by SENTINEL: <reason>"). Only the exact string
"approve" approves; decisions are once-only per call_id.

## Wire protocol (JSON text frames; all ids are strings; unknown `event` => ignored with a logged warning, never a crash)
Access control for both sockets = the existing `check_ws_access` (Origin allow-list for browsers; `?token=` when SENTINEL_WS_TOKEN is set).

### Proxy -> backend (`/proxy/ws`)
- `{"event":"proxy_hello","session_id":S,"servers":["fs","git"],"auto_approve":["fs:read_file","git:*"]}` must be the first frame.
- `{"event":"proxy_call","call_id":C,"server":"fs","tool":"write_file","args":{...},"auto":false}`; `auto:true` = the operator allow-listed it.
- `{"event":"proxy_result","call_id":C,"status":"ok"|"error","summary":"<=300 chars"}` after forwarding (display only).
### Backend -> proxy
- `{"event":"hello_ack","session_id":S}` or `{"event":"hello_reject","reason":"duplicate_session_id"|"bad_session_id"|"bad_hello"}` then close.
- `{"event":"proxy_decision","call_id":C,"decision":"approve"|"deny","reason":"human"|"auto"|"timeout"|"invalid"|"disconnected"|"duplicate"}`
  For `auto:true` calls the reply is `approve`/`auto` unless a monitor alerted, in which case the call is held for the human.
### Backend -> UI (`/inbox/ws`)
- `{"event":"inbox_snapshot","sessions":[{"session_id":S,"servers":[...],"pending":[<inbox_pending without event>]}]}` on connect.
- `{"event":"inbox_pending","session_id":S,"call_id":C,"server":..,"tool":..,"args":{..},"auto":bool,"alerts":[<alignment_alert dicts>],"deadline_s":300}`
- `{"event":"inbox_alert", ...alignment_alert fields..., "session_id":S,"call_id":C}` (alerts are computed BEFORE inbox_pending is sent, so
  normally they ride inside it; inbox_alert is for completeness).
- `{"event":"inbox_resolved","session_id":S,"call_id":C,"decision":"approve"|"deny","reason":..}`
- `{"event":"inbox_session","session_id":S,"state":"open"|"closed"}`
### UI -> backend
- `{"event":"inbox_decision","session_id":S,"call_id":C,"decision":"approve"|"deny"}`; `session_id` is REQUIRED (review finding: a call_id alone is ambiguous across
  sessions). Unknown/already-resolved (session_id, call_id) => ignored (once-only ledger). A frame without session_id is ignored.

## Components and tickets
| Ticket | Owner area | Files |
|---|---|---|
| P1 InboxHub + routes | backend | `server/inbox_hub.py`, `/proxy/ws` + `/inbox/ws` in `server/main.py`, `tests/server/test_inbox_hub*.py` |
| P2 Proxy process | proxy | `sentinel_proxy/` (package), `tests/proxy/` |
| P3 UI inbox | frontend | `frontend/src/components/Inbox.tsx`, `stores/inboxStore.ts`, `lib/inboxRoute.ts`, vitest |
| P4 Integration + e2e | all | real stdio fake downstream server + proxy + backend + Playwright inbox spec; verify.sh stages; mutants |
| P5 Docs | all | README, docs/proxy.md, DECISIONS D16 |

## Non-goals v1
HTTP/SSE downstream, OpenTelemetry observe-only, multi-user, hosted deployment, reasoning-based drift for proxied sessions.

## Review-driven amendments (security review of the first build)
1. `/inbox/ws` and `/proxy/ws` REQUIRE `SENTINEL_WS_TOKEN` (non-empty). Unset => both sockets refuse every connection (fail closed; logged once with the fix).
   Honest limit: a token stops a process that cannot read your environment/config; software on the same user account with full file access cannot be stopped by this.
2. An auto-approved call is also HELD when the monitor is degraded: no detector (rules fallback / failed build), or the monitor's error counter
   (`proposal_monitor.error_count()`) rose during the call. Auto-approve only applies when a working monitor looked at the call and stayed silent.
3. The hub reserves a call_id synchronously (before any await) and keys everything by (session_id, call_id).
4. The UI never lets a human approve content they did not see: arguments over the display limit show a loud TRUNCATED banner and Approve is disabled
   (Deny stays enabled); tool names are shown up to 200 chars (the hub's limit).
5. A failed/slow UI peer is closed (so the browser reconnects and gets a fresh snapshot), sends are concurrent with a per-peer timeout, and a dead
   proxy peer is closed. `seen` call ids are bounded.
6. Known and accepted for v1: no `proxy_cancel` frame (if the agent cancels, a stale card can sit until its timeout and a late approve is logged
   although nothing ran; the proxy forwards nothing).
