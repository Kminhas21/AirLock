# Plan: identity, tenancy and escalation (docs/PROPOSALS.md #6), first iteration

Goal: a shared token becomes real operators and agents with roles, tenants and an audit trail; pending approvals find a human (escalation + notifications) instead of waiting for a browser tab. Fail closed everywhere. Legacy single-token behaviour stays when no identity file is configured.

## Decisions (defaults; change here before building if you disagree)
- Identities live in a JSON file `SENTINEL_IDENTITY_FILE` (strict schema, token SHA-256 digests only, edited with `identity_cli`). Unset => legacy mode exactly as today (`SENTINEL_WS_TOKEN`, one implicit tenant `default`, operator role `admin`).
- Operators authenticate with a static API token OR a JWT (RS256/ES256, verified offline against a PEM public key or JWKS FILE named in the identity file; `exp`, `iss`, `aud` required; algorithm allowlist; `none`/HS* never accepted; leeway <= 30 s). No network fetch, no browser redirect login in v1 (an OIDC login flow is a follow-up: operators paste a token from their SSO tooling). Agents authenticate with a static token.
- Credentials never travel in URLs when an identity file is configured: `Authorization: Bearer <cred>` header (proxy, scripts) or a FIRST FRAME `{"event":"auth","token":"<cred>"}` within 5 s (browser). `?token=` is accepted only in legacy mode.
- Roles: `viewer` (read), `approver` (+ approve/deny), `admin` (+ standing rules, sees policy). Agents have role `agent` and may only open proxy sessions. Optional `servers` glob allowlists on operators (which downstream servers they may decide for) and agents (which servers they may declare).
- Tenancy: every operator/agent belongs to one tenant; the hub filters EVERYTHING (snapshot, pending, resolved, alerts, history, sessions) by tenant; an operator can never see or decide another tenant's call. Per-tenant optional `policy_file` and `gate_timeout_s`.
- Escalation: per tenant `escalation.levels: [{after_s, notify: [channel,...]}]`; at each level the card is marked escalated and notifications go out. The gate timeout (deny) is unchanged and still the backstop. Channels: webhook (`json` or `slack` body), optional HMAC-SHA256 signature header from an env-named secret; https only (http only to loopback for tests), redirects off, 5 s timeout, <= 2 retries with backoff, per-channel circuit breaker, private/link-local destinations refused unless `allow_private: true`. Notification bodies carry tenant, agent, server, tool, call id, age and a link; NEVER arguments (opt-in `include_args: true`, redacted previews only).
- Audit: decisions record `operator` and `tenant`; hellos record `agent_id` and `tenant`; failed authentications are logged (`auth_failed`, no credential material, rate-limited); notifications are logged (`notification`).
- Throttle: after 5 failed authentications from one remote address in 60 s, that address is refused for 60 s (in-memory).

## Identity file
```json
{"version": 1,
 "tenants": {"acme": {"name": "Acme", "policy_file": "/etc/sentinel/acme-policy.json", "gate_timeout_s": 300,
    "escalation": {"levels": [{"after_s": 60, "notify": ["oncall"]}, {"after_s": 180, "notify": ["manager"]}]},
    "channels": {"oncall": {"type": "webhook", "url": "https://hooks.example.com/x", "format": "slack", "secret_env": "ONCALL_HMAC", "include_args": false},
                 "manager": {"type": "webhook", "url": "https://hooks.example.com/y", "format": "json"}}}},
 "operators": [{"id": "alice", "tenant": "acme", "role": "admin", "token_sha256": "<hex>"},
               {"id": "bob", "tenant": "acme", "role": "approver", "servers": ["fs", "git*"], "jwt_sub": "bob@acme.example"}],
 "agents": [{"id": "ci-bot", "tenant": "acme", "token_sha256": "<hex>", "servers": ["fs"]}],
 "jwt": {"issuer": "https://sso.example.com", "audience": "sentinel", "algorithms": ["RS256"], "public_key_file": "/etc/sentinel/sso.pem",
         "leeway_s": 10}}
```
Ids `^[A-Za-z0-9._@-]{1,64}$`; unknown keys rejected; duplicate ids rejected; a tenant of an operator/agent must exist; `token_sha256` XOR `jwt_sub` per operator (an operator may have both); an operator with neither is invalid.

## API: `server/identity.py` (pure, no FastAPI)
```python
@dataclass(frozen=True) class Principal: kind, id, tenant, role, servers (tuple|None), via ("token"|"jwt"|"legacy")
class IdentityError(Exception): .messages
class IdentityStore:
    @classmethod load(cls, path, *, env=os.environ, clock=time.time) -> "IdentityStore"      # raises IdentityError(ALL messages)
    def authenticate(self, kind, credential, *, remote=None) -> Principal | None            # never raises; constant-time; throttle; no credential in any log
    def tenant(self, tenant_id) -> TenantConfig | None; def digest(self) -> str; def lint(self) -> list[str]
@dataclass(frozen=True) class TenantConfig: id, name, policy_file, gate_timeout_s, levels (tuple of Level(after_s, notify)), channels (dict name -> Channel)
def can(principal, action, *, server=None) -> bool          # actions: "view" | "decide" | "rules"; role order viewer < approver < admin; servers allowlist applies to decide/rules
def load_identity(env) -> tuple["IdentityStore | None", str]   # SENTINEL_IDENTITY_FILE (cached by content hash) else legacy store if SENTINEL_WS_TOKEN else (None, reason); never raises
def hash_token(token) -> str                                # sha256 hex
```
`identity_cli`: `add-operator|add-agent <id> --tenant T --role R [--servers g,..]` (prints the token ONCE, stores only the digest), `rotate <id>`, `revoke <id>`, `list`, `lint`, `mint-test-jwt` (test helper). Atomic writes, 0600, `.bak`, flock (same discipline as policy_writer).

## Protocol additions (all new fields optional; legacy mode unchanged)
- Both sockets with an identity file: after accept, credential from header or first frame `{"event":"auth","token":...}`; reply on `/inbox/ws`: `{"event":"auth_ok","principal":{"id","tenant","role"}}`; failure: `{"event":"auth_error","reason":"unauthorized"|"throttled"}` then close 1008. `/proxy/ws` failure => `hello_reject` reason `unauthorized` (or `forbidden_server`), then close.
- `inbox_snapshot.principal` = `{"id","tenant","role"}`; `capabilities` = `{"policy_writable": admin && writable, "can_decide": role >= approver, "event_log": bool}`.
- A `viewer`'s `inbox_decision`/`inbox_rule_request`, or any attempt outside the tenant or server allowlist, gets `{"event":"inbox_forbidden","action":"decide"|"rules","reason":"role"|"server"}` to that connection only and changes nothing.
- `inbox_pending` gains `agent_id`, `tenant`, `escalation_level` (int), `age_s`; `inbox_resolved` gains `operator` (id, null for non-human); new `inbox_escalated {session_id, call_id, level, after_s}` to the tenant's UIs.
- Event log: `decision.payload` gains `operator`, `tenant`; `proxy_hello.payload` gains `agent_id`, `tenant`; new closed kinds `auth_failed` (`{kind, reason, remote_hash}`) and `notification` (`{channel, level, ok, status}`).

## Tickets
| Id | Area | Files |
|---|---|---|
| ID1 | identity store, JWT, throttle, CLI | `server/identity.py`, `server/identity_cli.py`, `tests/server/test_identity*.py` |
| ID2 | notifier + escalation planner | `server/notify.py`, `server/escalation.py`, `tests/server/test_notify.py`, `tests/server/test_escalation.py` |
| ID3 | proxy credentials | `sentinel_proxy/*`, `tests/proxy` |
| ID4 | UI: sign-in, identity chip, read-only, escalation, operator on rows | `frontend/src/**` |
| ID5 | hub: auth, RBAC, tenancy filtering, per-tenant policy/timeout, audit, escalation wiring | `server/inbox_hub.py`, `server/main.py`, `server/eventlog.py` (new kinds), `server/health_view.py`, tests |
| ID6 | e2e (two tenants, roles, JWT, escalation to a local webhook), browser stage, mutants, docs/identity.md, D22 | tests/e2e, frontend/e2e, scripts, docs |

## Threat model (docs/identity.md)
Protects against: shared-secret sprawl (per-person revocable credentials), one team seeing or deciding another's calls, a viewer approving, an agent impersonating another agent or declaring servers it may not use, credentials in URLs/logs, brute force of tokens, forged/expired/wrong-audience JWTs and algorithm confusion, pending approvals going unnoticed, notification SSRF.
Does NOT: provide SSO login redirects, MFA, session revocation lists for JWTs (use short `exp`), protect tokens on a compromised operator machine, hide data from `admin`s or the host operator (the identity file and event log are plaintext on the host), or give fine-grained per-argument approval scopes.
Non-goals now: OIDC browser flow, SCIM/user provisioning, per-tenant registries, multi-node hub, notification channels other than webhooks.
