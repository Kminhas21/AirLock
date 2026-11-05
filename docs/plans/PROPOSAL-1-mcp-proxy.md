# Plan: monitor agents you didn't write (PROPOSALS.md #1), first version

## Decisions made with the owner
| Question | Answer |
|---|---|
| First target | MCP-based agents (Claude Code, Claude Desktop, Cursor, any MCP client) |
| Enforcement | BLOCK until a human decides (existing Airlock semantics: only exact "approve" approves; 300 s timeout then deny) |
| Approval UX | the existing web UI becomes an approval inbox for external sessions |
| Deployment | local developer tool: one user, localhost, smallest threat model |

## Open questions (to settle before tickets are cut)
1. Transport: stdio MCP servers only, or also HTTP/SSE?
2. Tool coverage: intercept every tool of every downstream server, or allow marking read-only tools auto-approved?
3. Session identity: how to tell agent sessions apart when several connect to one proxy?
4. Monitor inputs: a proxy sees tool calls and arguments, NOT the agent's reasoning. Proposed: use only call-based monitors (action_sim, registry
   modes, union) and drop reasoning-based drift for proxied sessions. Accept?

## Sketch (to be ticketed after the answers)
- T1 proxy core: speak MCP to the agent, forward approved calls to the real servers (config file lists downstream servers).
- T2 gate adapter: each `tools/call` becomes a `tool_pending` held by the existing gate; the result/deny goes back as an MCP result/error.
- T3 session model: proxy session id -> UI session; inbox view for pending calls.
- T4 monitors: feed the call into the proposal monitors; alerts appear in the inbox before the human decides.
- T5 tests: a scripted fake MCP client and fake downstream server; parity with the existing gate tests; mutation mutants for the gate path;
  Playwright inbox test; hostile tool names/arguments through the whole path.
- Non-goals v1: OpenTelemetry observe-only mode, multi-user, hosted deployment.
