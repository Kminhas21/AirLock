# From demo to an actual agent-monitoring system: proposals

Grounded in what the live browser run showed (see DECISIONS.md D4/D4b/D5). Ordered by how much each one
changes whether the tool is *real*. Effort: S (days) / M (weeks) / L (months).

## 1. Monitor agents you didn't write (L, highest leverage)
Today the product bundles its own toy agent: the monitor *is* the agent loop, and tools are dict mutations. A monitoring
system sits **between an existing agent and its tools**. Build the Airlock as an interception layer with two adapters:
an **MCP proxy** (agent points at SENTINEL as its MCP server; SENTINEL forwards approved calls to the real servers) and an
**SDK/middleware hook** for in-process frameworks. Ingest **OpenTelemetry GenAI traces** for passive (observe-only) mode.
Keep the current loop only as a reference agent and test fixture.

## 2. A policy engine, so humans are the exception (M)
Every call is gated today (`risk_level` is only colour), which does not scale past a demo and trains operators to click Approve.
Add declarative policy (allow / deny / ask) over tool, arguments, resource, risk and drift state: e.g. auto-allow reads under
`/project`, auto-deny writes outside it, ask for anything that sends data out. Humans see only the ambiguous residue. Policies are
versioned, testable (`policy test` against recorded traces), and every decision records which rule fired.

## 3. Durable, tamper-evident event log as the source of truth (M)
All state is process memory; a disconnect abandons the session. Make an append-only log (Postgres/SQLite first, hash-chained
for audit) the source of truth, with the WebSocket as a *view*. That buys: reconnect and rehydrate with the pending action
re-presented, restart safety, replay of any real session (replacing hand-made cached runs), idempotency keys, and an audit trail.

## 4. Treat drift detection as a measured classifier, not a feature (M)
Evidence: the live path's circumvention alert is a rule (same resource category after a denial) and works; the Mahalanobis
embedding drift is **unvalidated** (stub embedder in tests, real model never run here; N=3 baseline; fixed threshold).
- Build a labelled dataset of aligned/adversarial/benign-shift traces and report precision/recall/ROC per detector.
- Embed **actions** (tool + normalised arguments + target), not only prose; prose is the easiest thing for an agent to vary.
- Learn per-agent/per-task baselines from history instead of the first 3 steps; use a proper cutoff and online updates.
- Detect *goal persistence* with outcome tracking (did the same information leave through another channel?), not keywords.
- Ship the detector's calibration with the product and alert on its own false-positive rate.

## 5. Real enforcement boundary (L)
"Denied" currently means "the mock did not run", which is only true because nothing is real. For real tools: run them in a
sandbox (gVisor/Firejail/container per session), mint **scoped, short-lived credentials per approved call**, and make the
monitor the only path to those credentials. Otherwise an agent can bypass the gate with any tool the monitor does not know.

## 6. Identity, tenancy and escalation (M)
One shared WebSocket with an optional static token is not an operations tool. Add real auth (SSO), per-agent identities,
RBAC for who may approve what, per-tenant isolation, approval queues with SLAs, escalation when nobody answers, and
notifications (Slack/PagerDuty/email) so a pending action finds a human instead of waiting for a browser tab.

## 7. Scale and operate the monitor itself (M)
Stateless gateway + queue + worker for embeddings (the model load and per-step embedding must not run on the request path);
many agents per operator console, filter/search/triage views; structured logs, metrics (pending-approval age, LLM latency/cost,
drift-breach rate, reconnects), health/readiness, and containers with versioned rollback.

## 8. Make the UI answer operator questions (S-M)
Show *why* an alert fired (rule, evidence, linked nodes), what the agent has already done (blast radius so far), and let the
operator deny-with-reason and set a standing rule from one click. Carry the active threshold in the event so UI and backend
can never disagree again (B18 was exactly that).

## Suggested order
(2) policy + (3) event log first: both are small, make the existing demo honest, and every later item needs them.
Then (1) the proxy, which turns it from a demo into a product. Then (4) in parallel, because without measurement every
"it detects drift" claim stays unproven.
