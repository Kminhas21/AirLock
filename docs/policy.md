# Policy engine (opt-in, MCP proxy)

Rules that decide `allow`, `deny` or `ask` for each tool call, so you only see the ambiguous ones. Set `SENTINEL_POLICY=/path/policy.json` on the backend.
Without it nothing changes (the proxy's `auto_approve` list still applies). With it, **the policy decides and `auto_approve` is ignored.**

## Example
See `docs/examples/policy.example.json`; a small one:
```json
{"version": 1, "default": "ask",
 "rules": [
  {"id": "read-project", "verdict": "allow", "when": {"tool": "read_file", "args": [{"path": "path", "op": "under", "value": "/project"}]}},
  {"id": "no-writes-outside", "verdict": "deny", "when": {"tool": "write_file", "args": [{"path": "path", "op": "not_under", "value": "/project"}]}},
  {"id": "external-needs-human", "verdict": "ask", "when": {"destination": "external"}}
 ]}
```
Conditions in `when` are ANDed: `server`, `tool` (glob), `args` (`path` = dotted keys, `op`, `value`), `destination` (`internal|external|relay|none|any`,
resolved with your destination registry, `SENTINEL_REGISTRY`), `party`, `alert`. Operators: `equals not_equals in not_in glob not_glob under not_under contains exists not_exists max_len`.

## How a decision is made
1. `deny` beats `ask` beats `allow`; none matching => `default` (`ask` unless you set it). The rule shown is the most specific one of the winning class.
2. An alert from a monitor turns an `allow` into `ask` (never silently allowed). An `allow` also needs a WORKING monitor (not the `rules` fallback / stub embedder); otherwise the call is held.
3. Anything uncertain fails closed: a broken policy file => every call is held; a rule that errors => `ask` (unless a deny matched); a missing/odd argument is false for positive
   operators and true for negative ones (`not_under` on a missing path matches); a tool name with control or bidi characters never matches an `allow` but does match `deny`/`ask` rules.
4. Paths: `under` compares whole segments after lexical normalisation (`/project2` is not under `/project`; `..` escapes are outside). It cannot see symlinks.
Tip: write `allow` rules with positive operators only (`lint` warns otherwise).

## Tools
`cd server && python -m policy_cli lint policy.json`; `explain policy.json --server fs --tool write_file --args '{"path":"/etc/x"}' [--alert]`;
`test policy.json --traces ../eval/final_v3/traces.json` replays recorded proposals and prints verdict counts, which rules fired, **violating proposals the policy would allow (aim for 0)** and **benign proposals it would ask (the human burden)**.

## In the UI
Inbox cards show "held by rule X"; auto-resolved rows show "auto-allowed by rule X" or "denied by rule X". `/health` reports `policy: {digest, rules, usable}` (path only with the token).

## Limits
Hub only (the built-in agent loop does not use it yet); the policy is read at each proxy session start and pinned for that session; no regex; no drift-state inputs. A policy is a burden reducer,
not a detector: the example policy on the v3 traces still allows violating proposals that only semantics can catch, so keep a monitor running. See DECISIONS D18.
