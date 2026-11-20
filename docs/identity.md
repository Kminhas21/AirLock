# Identity, tenancy and escalation (opt-in; MCP proxy + Inbox)

Without `SENTINEL_IDENTITY_FILE` nothing changes: one shared `SENTINEL_WS_TOKEN`, one implicit tenant. With it, the hub knows WHO is asking (agents) and WHO is deciding (operators), keeps tenants apart, enforces roles, escalates unanswered approvals and records who did what.

## Set up
```
cd server
export SENTINEL_IDENTITY_FILE=/etc/sentinel/identity.json        # or pass --file <path> AFTER the subcommand
python -m identity_cli add-operator alice --tenant acme --role admin --create-tenant      # prints alice's token ONCE
python -m identity_cli add-operator bob --tenant acme --role approver --servers 'fs,git*'
python -m identity_cli add-operator vera --tenant acme --role viewer
python -m identity_cli add-agent ci-bot --tenant acme --servers fs                        # prints the agent token ONCE
python -m identity_cli list; python -m identity_cli lint
SENTINEL_IDENTITY_FILE=/etc/sentinel/identity.json uvicorn main:app --port 8080
```
The file stores only SHA-256 digests of tokens (0600, atomic writes, `.bak`). Lose a token => `rotate <id>`; leaver => `revoke <id>`; `lint` checks the file. Full schema: `docs/plans/IDENTITY.md`.
- **Agents (proxies)**: set `SENTINEL_AGENT_TOKEN` in the proxy's environment; it is sent as `Authorization: Bearer ...` (never in the URL).
- **Operators (Inbox)**: the Inbox shows a Sign in panel; paste your token (or a JWT from your SSO tooling). It is sent as the first frame of the websocket, kept in memory and `sessionStorage` only, cleared on Sign out.
- **JWT operators**: add `"jwt": {"issuer", "audience", "algorithms": ["RS256"], "public_key_file" | "jwks_file"}` and give the operator `"jwt_sub"`. Verified offline: algorithm allowlist (never `none`/HS*), `exp`, `iss`, `aud` required. Use short expiries: there is no revocation list for JWTs.

## Roles and tenants
`viewer` sees; `approver` approves/denies; `admin` also creates standing rules. A tenant's operators see ONLY their tenant's sessions, calls, alerts, history and rule results; a decision on another tenant's call is silently ignored. Operator `servers` globs limit which downstream servers they may decide for; agent `servers` globs limit what a proxy may declare (`forbidden_server`). Session ids are scoped per tenant. Per tenant you can set `policy_file` and `gate_timeout_s`.

## Escalation and notifications
`escalation.levels: [{"after_s": 60, "notify": ["oncall"]}, ...]`: when a held call is still unanswered at each level its card is marked Escalated and the named channels are notified (an empty `notify` only marks the card). The gate timeout (deny) still applies at the end.
Channels are webhooks (`json` or `slack` body), https only (plain http to loopback only with `allow_http_loopback: true`), optional `secret_env` for an HMAC signature header (an unavailable secret means the channel does not send, never unsigned), redirects off, private addresses refused unless `allow_private`, 5 s timeout, 2 retries, circuit breaker.
Notifications carry tenant, agent, server, tool, call id, age and a link, **never arguments** (unless the channel sets `include_args`, then a redacted preview). Set `SENTINEL_PUBLIC_URL` for the link.

## Audit
Decisions record `operator` and `tenant`; hellos record `agent_id` and `tenant`; failed sign-ins (`auth_failed`, no credential material, rate-limited) and notifications (`notification`) are logged when the event log is on (`docs/eventlog.md`). After 5 failed sign-ins from one address in 60 s that address is refused for 60 s.

## Fail closed
An unusable identity file refuses EVERY inbox and proxy connection (with an ERROR in the log) instead of falling back to open access.

## Limits (read this)
No SSO login redirect, MFA, SCIM or JWT revocation; the identity file and the event log are plaintext on the host (admins of the host see everything); tokens are only as safe as the machines that hold them; approval scopes are per server, not per argument; one hub process (no clustering). See DECISIONS D22.
