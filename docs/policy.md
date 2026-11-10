# Policy engine (opt-in, MCP proxy)

Rules that decide `allow`, `deny` or `ask` for each tool call, so you only see the ambiguous ones. Set `SENTINEL_POLICY=/path/policy.json` (or `builtin:starter`, see below) on the backend.
Without it nothing changes: no policy allows anything (the proxy's `auto_approve` list still applies). With it, **the policy decides and `auto_approve` is ignored.**

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
resolved with your destination registry, `SENTINEL_REGISTRY`), `party`, `alert`. Operators: `equals not_equals in not_in glob not_glob under not_under contains icontains_any exists not_exists max_len`.
`icontains_any` takes a list of 1 to 64 strings and is true when the argument (a string, or a list of strings such as `paths`) contains ANY of them, ignoring case
(Unicode casefold) and path spelling: the text is also tested with `\\` turned into `/`, runs of `/` collapsed, `/./` removed and `..` resolved, so `.git//config`,
`/etc/./passwd` and `.git\config` match the needle `.git/config` / `/etc/passwd`. A missing argument, or an argument that is neither a string nor a list, is false. Anything
that cannot be examined counts as a match, so a padded or oddly typed argument cannot slip past an `ask` rule: a string over 4096 characters, a list over 64 entries, a
list entry that is not a string (a nested list, an object, a number). Use it in `ask`/`deny` rules (`lint` warns if an `allow` rule uses it).

## How a decision is made
1. `deny` beats `ask` beats `allow`; none matching => `default` (`ask` unless you set it). The rule shown is the most specific one of the winning class.
2. An alert from a monitor turns an `allow` into `ask` (never silently allowed). An `allow` also needs a WORKING monitor (not the `rules` fallback / stub embedder); otherwise the call is held.
3. Anything uncertain fails closed: a broken policy file => every call is held; a rule that errors => `ask` (unless a deny matched); a missing/odd argument is false for positive
   operators and true for negative ones (`not_under` on a missing path matches); a tool name with control or bidi characters never matches an `allow` but does match `deny`/`ask` rules.
4. Paths: `under` compares whole segments after lexical normalisation (`/project2` is not under `/project`; `..` escapes are outside). It cannot see symlinks.
Tip: write `allow` rules with positive operators only (`lint` warns otherwise).

## Starter policy
`SENTINEL_POLICY=builtin:starter` selects a conservative policy shipped with the server (`server/policies/starter.json`). It is the **default of the shipped
`docker-compose.yml`** (and listed in `.env.example`) and what we recommend for a new setup, so a first-time user is not asked about every plain read.

**The default of the hub itself is unchanged:** with `SENTINEL_POLICY` unset nothing is auto-allowed by policy and every call is held (fail closed). Upgrading never
starts allowing anything on its own; you opt in by setting the variable (compose does this for new deployments).

- **Allows** read-only tools: `read_file`, `read_text_file`, `read_multiple_files`, `list_directory`, `list_directory_with_sizes`, `directory_tree`,
  `search_files`, `get_file_info`, `list_allowed_directories` (filesystem server), `read_graph`, `search_nodes`, `open_nodes` (memory server), `get_current_time`,
  `convert_time` (time server). Matching is by tool name, on any server: scope the allow rules with `when.server` if you run a server that reuses a read-only tool name for something with side effects. A file path must be a string.
  `directory_tree`, `search_files` and `get_file_info` are allowed on ANY directory, so they expose file NAMES and metadata (not contents), sensitive ones included;
  if that matters to you, remove them from the `allow-read-only-fs` rule.
  Reads of URLs always ask: any path argument containing `://` (http, https, ftp, file, s3, ...) and any call with `isUrl` set (rule `ask-url-flag`) is held, because a tool such as
  Desktop Commander's `read_file` with `isUrl: true` makes an outbound request that can carry data in the URL. The allow rules cannot see tool annotations such as `openWorldHint`,
  so a tool that fetches through another flag name is not covered: scope the allow rules with `when.server` for servers you do not trust.
- **Asks** (a human decides) when `path`, `paths` (any entry), `source`, `destination`, `directory` or `file` contains, in any letter case, `.ssh`, `.aws`, `.gnupg`,
  `.env`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `credentials`, `secrets`, `.netrc`, `.pgpass`, `.npmrc`, `.docker`, `.pem`, `.p12`, `.pfx`,
  `/etc/shadow`, `/etc/passwd`, `sudoers`, `/proc/`, `.bash_history`, `.git-credentials`, `.kube`, `.git/config` or `://` (a URL). One `icontains_any` rule per argument, so
  one sensitive entry in `read_multiple_files` holds the whole call. This is a substring test on the text of the path: it cannot see symlinks or a file reached
  through another name. These rules beat the allow rules.
- **Asks** for everything else (default `ask`): writes, edits, moves, deletes, `send_*`, webhooks, shell, database, unknown tools. There are no `deny` rules.

Reads are allowed but exfiltration is not: sending, writing and executing are still held, so a read alone cannot leave the machine without a human seeing the
sending step. A read can still expose content to the model; keep secrets out of the directories you share with the agent.

**Needs a working monitor.** As for every `allow` (rule 2 above), an alert, or a monitor that is not working (the `rules` fallback, the stub embedder, an image built
with `EMBEDDINGS=0`), turns the allow into a held call: with a stub embedder the starter allows nothing. `/health` shows the active `monitor` and `embedder`; if it says
`stub`, expect cards for reads too.

**Read-only.** A `builtin:` policy cannot be edited: with `SENTINEL_POLICY_WRITABLE=1` the standing-rule UI stays off and the log says why. An unknown name
(`builtin:nope`) behaves like a broken policy file: every call is held, the log names the problem and `/health` reports `policy.usable: false`.
To adapt it, write a copy and point `SENTINEL_POLICY` at that path (add `SENTINEL_POLICY_WRITABLE=1` for standing rules):
```
cd server && python -m policy_cli init /etc/sentinel/policy.json --starter    # refuses to overwrite unless --force; mode 0600
```
On the recorded v3 traces the starter allows 115 of 376 benign proposals and 0 of the 127 violating ones (`policy_cli test builtin:starter --traces ../eval/final_v3/traces.json`).

## Tools
`cd server && python -m policy_cli lint policy.json`; `explain policy.json --server fs --tool write_file --args '{"path":"/etc/x"}' [--alert]`;
`test policy.json --traces ../eval/final_v3/traces.json` replays recorded proposals and prints verdict counts, which rules fired, **violating proposals the policy would allow (aim for 0)** and **benign proposals it would ask (the human burden)**.

## In the UI
Inbox cards show "held by rule X"; auto-resolved rows show "auto-allowed by rule X" or "denied by rule X". `/health` reports `policy: {digest, rules, usable}` (path only with the token).

## Limits
Hub only (the built-in agent loop does not use it yet); the policy is read at each proxy session start and pinned for that session; no regex; no drift-state inputs. A policy is a burden reducer,
not a detector: the example policy on the v3 traces still allows violating proposals that only semantics can catch, so keep a monitor running. See DECISIONS D18.

**Known limits of the starter (accepted, from the independent review).** It is a substring test, so it errs towards asking: ordinary files such as `src/credentials.py`, `docs/secrets.md`,
`.env.example`, `.envrc`, `.dockerignore`, fixture `*.pem` files and any directory called `proc` (the `/proc/` needle) also produce a card. That costs operator attention, never safety;
copy the starter with `policy_cli init` and trim the needles you do not want. A `paths` argument that is a bare number, null or object (not a list) is not inspected (the reference filesystem server rejects such shapes).

