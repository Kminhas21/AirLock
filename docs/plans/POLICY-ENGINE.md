# Plan: policy engine (GitHub issue #3), first iteration

Goal: declarative `allow` / `deny` / `ask` rules so humans only see the ambiguous residue; every decision records which rule fired. Fail closed everywhere.

## Decisions (defaults chosen for the open questions in the issue; change them here before building if you disagree)
- Format: **JSON** (same as the destination registry; no new dependency). One global file via `SENTINEL_POLICY=/path/policy.json`, content-hash cached,
  re-read at every proxy session start (a running session keeps the policy it started with; its digest is recorded).
- First consumer: the **MCP proxy hub** (`server/inbox_hub.py`). When a policy is configured the hub decides; the proxy's static `auto_approve` flag is
  ignored (one source of truth; the proxy is not trusted to grant allows). Without a policy the legacy `auto_approve` behaviour is unchanged.
  Built-in agent loop integration and drift-state inputs are a follow-up ticket (documented, not built).
- No regex in rules (ReDoS); glob (fnmatch on single path segments) and prefix operators only.

## Policy file
```json
{"version": 1, "default": "ask",
 "rules": [
  {"id": "read-project", "verdict": "allow", "note": "reads under /project are routine",
   "when": {"server": "fs", "tool": ["read_*", "list_*"], "args": [{"path": "path", "op": "under", "value": "/project"}]}},
  {"id": "no-writes-outside", "verdict": "deny", "when": {"tool": "write_*", "args": [{"path": "path", "op": "not_under", "value": "/project"}]}},
  {"id": "external-needs-human", "verdict": "ask", "when": {"destination": "external"}}
 ]}
```
- Top level keys: `version` (must be 1), `default` (allow|deny|ask, default `ask`), `rules` (list, max 500). Unknown keys anywhere => `PolicyError`.
- Rule: `id` (unique, `^[A-Za-z0-9._-]{1,60}$`), `verdict`, optional `note` (<=200 chars), `when` (object). ALL present conditions must hold (AND); an empty/absent
  `when` matches everything.
- `when` keys: `server` (string or list; fnmatch glob, case-sensitive), `tool` (same), `args` (list of `{path, op, value}`), `destination`
  (`internal`|`external`|`relay`|`none`|`any`; resolved with `server/registry.py` using the supplied registry, else `default_registry()`: `external` = the
  registry says the call reaches an outside party (unknown destinations count as external), `relay` = reaches via a registered relay entry, `internal` = has
  destination tokens and none reach outside, `none` = no destination token), `party` (string or list; registry party slug reached), `alert` (bool: whether a
  monitor alert is present on the call).
- `args[].path`: dotted keys into the args object (`a.b.c`); no wildcards/indexes in v1 (list indexes as decimal keys `items.0.path` ARE allowed).
  `op` in: `equals`, `not_equals`, `in` (value list), `not_in`, `glob`, `not_glob`, `under` (path prefix), `not_under`, `contains` (substring), `exists`, `not_exists`,
  `max_len` (string/list length <=). `value` required except for `exists`/`not_exists`.
- Path ops (`under`/`not_under`): lexical normalisation with `posixpath.normpath` after rejecting NUL; a relative path never counts as under an absolute prefix;
  `..` that escapes the prefix is outside; the match is on whole segments (`/project2` is NOT under `/project`). Symlinks cannot be known: documented.
- Uncertainty rule (the fail-closed core): a condition that cannot be evaluated (path missing, wrong type, value not a string for a path op) is
  FALSE for positive ops (`equals`, `in`, `glob`, `under`, `contains`, `exists`, `max_len`) and TRUE for negative ops (`not_equals`, `not_in`, `not_glob`,
  `not_under`, `not_exists`). `lint` WARNS when an `allow` rule uses a negative op (it would allow on unknowns).

## Evaluation
`evaluate(server, tool, args, *, registry=None, alerts_present=False) -> Decision`
1. Every rule is evaluated. A rule that raises is recorded as an error: if no `deny` rule matched, the verdict becomes `ask` (reason `rule_error:<id>`); a matched `deny` still wins.
2. Matched verdict classes: any `deny` => deny; else any `ask` => ask; else any `allow` => allow; else `default`.
3. The reported rule is the most specific matching rule of the winning class (more `when` conditions = more specific; tie = first listed). `matched` lists all matching ids.
4. Alerts: if `alerts_present` and the verdict is `allow`, it is ESCALATED to `ask` (`escalated=true`, reason `alert`); `deny` is unchanged. The `alert` condition above also sees it.
5. Inputs are data only: tool names, args and server names never become code, patterns or regexes; oversize/deep args are bounded (depth 12, 2000 items per container, strings cut at 20,000 chars) and never raise.
`Decision(verdict, rule_id, matched, reason, escalated)`; `policy.digest()` = first 16 hex of sha256 of the canonical JSON.
API (module `server/policy.py`): `load_policy(path_or_dict) -> Policy` (raises `PolicyError` with ALL messages), `Policy.lint() -> list[str]` warnings,
`Policy.digest()`, `Policy.evaluate(...)`. Cached by content hash like the registry.

## Hub integration (server/inbox_hub.py)
At `proxy_hello` the hub resolves the policy for the session (digest recorded); if `SENTINEL_POLICY` is set but unusable (missing/invalid) => policy mode is
ON with a "broken" policy: EVERY call is `ask` (never legacy auto-approve), logged loudly once. For each `proxy_call` (after the monitor ran, so `alerts_present` is known):
- `deny` => immediate `proxy_decision` deny, reason `policy`, `inbox_resolved` (decision deny, reason `policy`, rule_id), the monitor is told `deny`.
- `allow` => requires the same preconditions as today's auto-approve (working monitor, no error, no alert) else `ask`; then `proxy_decision` approve, reason `policy`, `inbox_resolved` with rule_id.
- `ask` => held for the human as today; the pending item carries the matched `rule_id` (or null for the default) and `policy_digest`.
Protocol additions: `proxy_decision.reason` and `inbox_resolved.reason` gain `policy`; `inbox_pending`/`inbox_resolved` gain optional `rule_id` (string|null) and `policy_digest` (string|null). UI: label "auto-allowed by rule <id>" / "denied by rule <id>" / pending card "held by rule <id>" (rule ids are policy-file data: render as text, single line, <=60 chars). Proxy: accept reason `policy` in its closed set ("Denied by SENTINEL: policy").
`/health` detail view reports `policy: {path, digest, rules}`; the public view only `{digest, rules}`.

## CLI (server/policy_cli.py; `cd server && python -m policy_cli ...`)
- `lint <policy.json>`: exit 0 ok (warnings printed), 1 errors, 2 unreadable.
- `explain <policy.json> --server S --tool T --args '{...}' [--registry reg.json] [--alert]`: prints the Decision and every matched rule.
- `test <policy.json> --traces <traces.json> [--registry reg.json] [--server NAME]`: replays the recorded proposals of an eval trace file (`eval/final_v3/traces.json`: each step's `proposal` has `tool`, `args`, `label` ok|violation) and prints a table: verdict counts overall and by label, which rule fired how often, and the two numbers that matter: violating proposals the policy would ALLOW (must be 0 for a safe policy) and benign proposals it would ASK (the human burden).

## Tickets
| Id | Area | Files |
|---|---|---|
| PE1 | engine | `server/policy.py`, `tests/server/test_policy*.py` |
| PE2 | CLI + replay | `server/policy_cli.py`, `tests/server/test_policy_cli.py`, example `docs/examples/policy.example.json` |
| PE3 | hub integration | `server/inbox_hub.py`, `server/main.py` (health), tests |
| PE4 | proxy reason + UI labels | `sentinel_proxy/`, `frontend/src/**` |
| PE5 | e2e + gate + mutants + docs | tests/e2e, frontend/e2e, scripts, `docs/policy.md`, DECISIONS D18 |

Non-goals now: built-in agent loop, drift-state inputs, per-session policy overrides, regex, YAML, hot reload inside a running session.
