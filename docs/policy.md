# Policy engine (opt-in, MCP proxy)

Rules that decide `allow`, `deny` or `ask` for each tool call, so you only see the ambiguous ones. Set `SENTINEL_POLICY=/path/policy.json` (or `builtin:starter`, see below) on the backend.
Without it nothing changes: no policy allows anything (the proxy's `auto_approve` list still applies). With it, **the policy decides and `auto_approve` is ignored.**

## Example
See `docs/examples/policy.example.json`; a small one:
```json
{"version": 1, "default": "ask",
 "rules": [
  {"id": "read-project", "verdict": "allow", "when": {"tool": "read_file", "arg_keys": ["path"], "args": [{"path": "path", "op": "under", "value": "/project"}]},
   "confine": {"path": "read"}},
  {"id": "no-writes-outside", "verdict": "deny", "when": {"tool": "write_file", "args": [{"path": "path", "op": "not_under", "value": "/project"}]}},
  {"id": "external-needs-human", "verdict": "ask", "when": {"destination": "external"}}
 ]}
```
Conditions in `when` are ANDed: `server`, `tool` (glob), `args` (`path` = dotted keys, `op`, `value`), `destination` (`internal|external|relay|none|any`,
resolved with your destination registry, `SENTINEL_REGISTRY`), `party`, `alert`, `arg_keys`. Operators: `equals not_equals in not_in glob not_glob under not_under contains icontains_any exists not_exists max_len`.
`icontains_any` takes a list of 1 to 64 strings and is true when the argument (a string, or a list of strings such as `paths`) contains ANY of them, ignoring case
(Unicode casefold) and path spelling: the text is also tested with `\\` turned into `/`, runs of `/` collapsed, `/./` removed and `..` resolved, so `.git//config`,
`/etc/./passwd` and `.git\config` match the needle `.git/config` / `/etc/passwd`. A missing argument is false. Anything
that cannot be examined counts as a match, so a padded or oddly typed argument cannot slip past an `ask` rule: a string over 4096 characters, a list over 64 entries, a
list entry that is not a string (a nested list, an object, a number), and an argument that is neither a string nor a list (an object, a number, `null`, a boolean).
Use it in `ask`/`deny` rules (`lint` warns if an `allow` rule uses it).

`arg_keys` is a list of at most 100 argument names (an empty list = no arguments at all). The rule matches only if EVERY top-level argument name of the call is in the
list (exact, case-sensitive); arguments that are not an object never match an `allow` rule with `arg_keys` (they do match `ask`/`deny` rules). Use it on `allow`
rules, with the argument names from the real tool's input schema, so a tool that shares a read-only NAME but takes an extra flag that does something else (Desktop
Commander's `read_file {isUrl: true}` fetches a URL) is not auto-allowed: an unknown argument falls through to the default. `lint` warns when an `args` condition
names a key that is not in `arg_keys` (the rule could never match).

`confine` (allow rules only, DECISIONS D31) says which arguments are paths and what the call may do with them: `{"path": "read"}` = read exactly the
named file (not a directory, nothing beneath it), `{"path": "list"}` = list the names beneath the named directory (never contents); `{}` = "no argument
of this tool is a path" (an operator assertion). At most 20 keys, each listed in `when.arg_keys` (so `confine` needs `arg_keys`). A `paths` list gets
one grant per entry (at most 64). When such a rule auto-allows a call, the MCP proxy runs it in a fresh worker that the kernel (Landlock) lets touch
ONLY the named objects (rule 5). Floors (stricter only): an allow rule without `confine` asks (reason `unconfined`; `lint` warns and prints the map
to add); a call with a path-slot argument (`path`, `paths`, `source`, `destination`, `directory`, `file`) that is not in the deciding rule's
`confine` asks; a non-empty `confine` on a server the proxy cannot confine asks (reason `unconfinable`); a `default: allow` asks for a call with a
path-slot argument. A custom argument name (`file_path`) is a path only if the rule lists it in `confine`; `lint` WARNS (it does not reject: only the operator
knows the tool) when `confine: {}` is paired with an `arg_keys` entry that looks like a path (`file_path`, `filepath`, `filename`, `dir`, `src`, `dest`, `uri`, `url`,
`name`, or anything ending in `path`, `paths`, `file`, `dir`): such a call would otherwise run unconfined in the session process. A write cannot be confined (only `read` and
`list` exist): auto-allow writes with `confine` and they fail with EACCES; keep writes on `ask`. Standing rules made from a card ("Always allow")
get `arg_keys` = the call's argument names and `confine` = `read` on its path arguments. An "Always allow" for a call with a path-like argument
that is not a confine slot (Desktop Commander's `edit_block` `file_path`) is refused (`cannot_build`; the card stays a normal card): `confine: {}` would run it unconfined.

## How a decision is made
1. `deny` beats `ask` beats `allow`; none matching => `default` (`ask` unless you set it). The rule shown is the most specific one of the winning class.
2. An alert from a monitor turns an `allow` into `ask` (never silently allowed). An `allow` also needs a WORKING monitor (not the `rules` fallback / stub embedder); otherwise the call is held.
3. Anything uncertain fails closed: a broken policy file => every call is held; a rule that errors => `ask` (unless a deny matched); a missing/odd argument is false for positive
   operators and true for negative ones (`not_under` on a missing path matches); a tool name with control or bidi characters never matches an `allow` but does match `deny`/`ask` rules.
4. Paths: `under` compares whole segments after lexical normalisation (`/project2` is not under `/project`; `..` escapes are outside). The rules judge
   the TEXT the agent wrote; they never see symlinks, and nothing predicts what the server will open (rule 5).
5. Kernel confinement (MCP proxy, DECISIONS D31). A path allow is enforced, not predicted: the hub allows a call with a non-empty `confine` only when the
   proxy says the call is `confinable`, and the proxy then runs it in a one-shot worker (also for a `session` server, whose own process keeps serving
   human-approved calls) whose Landlock rules grant only the system set, the server's `sandbox.runtime`, its private HOME and, per confined value, the
   object the kernel finds by walking the written string with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`: an absolute value from `/`, a relative one
   from each directory the server maps names in (its absolute directory arguments, else its working directory; at most 4). A value with a symlink
   anywhere, one that escapes its base, or one that is missing gets NO grant, never a wider one. So whatever the server does with the text (`..` after a
   link, a Unicode respelling of a missing name, another base, a link swapped in after the check) it meets EACCES on anything that was not named: a wrong
   guess costs an error result, not a leak. The worker's status must report the confinement before the call is sent (else `confine_failed`).
   `confinable` is false (a human is asked) when the server has no `sandbox` or no `sandbox.runtime`, the host has no Landlock or `openat2` (old kernel, a
   seccomp profile), or the proxy's precheck (the same walk, in the proxy) finds a symlink, an escape, `~`, more than 64 values or more than 4 bases: a
   legitimate read through a link would only fail in the worker, so a human decides it. A missing name is not a reason to ask. An older proxy that sends
   no `confinable` gets the same: its path allows ask. **An unsandboxed server therefore gets a card for every path read the starter would allow.**
   Where a symlinked value leads (`os.path.realpath`, at most 64) is shown on the card: "notes.txt -> /w/.env (as the proxy resolves it; the server may
   differ)". It is a hint for the human and never changes a verdict.
Tip: write `allow` rules with positive operators only (`lint` warns otherwise).

## Starter policy
`SENTINEL_POLICY=builtin:starter` selects a conservative policy shipped with the server (`server/policies/starter.json`). It is the **default of the shipped
`docker-compose.yml`** (and listed in `.env.example`) and what we recommend for a new setup, so a first-time user is not asked about every plain read.

**The default of the hub itself is unchanged:** with `SENTINEL_POLICY` unset nothing is auto-allowed by policy and every call is held (fail closed). Upgrading never
starts allowing anything on its own; you opt in by setting the variable (compose does this for new deployments).

- **Allows** read-only tools: `read_file`, `read_text_file`, `read_multiple_files`, `list_directory`, `list_directory_with_sizes`, `directory_tree`,
  `search_files`, `get_file_info`, `list_allowed_directories` (filesystem server), `read_graph`, `search_nodes`, `open_nodes` (memory server), `get_current_time`,
  `convert_time` (time server), each ONLY with the argument names of the real tool (`arg_keys`, taken from the pinned servers' schemas: filesystem 1.0.0,
  memory 1.0.0, time; plus `offset`/`length` of Desktop Commander's `read_file`). Any other argument (`isUrl`, even `isUrl: false`, `options`, `origin`, `depth`, ...) is held.
  Matching is by tool name on any server: scope the allow rules with `when.server` if you run a server that reuses a read-only tool name and its argument names for
  something with side effects. A file path must be a string; `read_multiple_files` needs a non-empty list.
  `directory_tree`, `search_files` and `get_file_info` are allowed on ANY directory, so they expose file NAMES and metadata (not contents), sensitive ones included;
  if that matters to you, delete the rules `allow-tree` and `allow-search` and `get_file_info` from `allow-read-only-fs`.
  Reads of URLs always ask: any path argument containing `://` (http, https, ftp, file, s3, ...) is held, and so is any call with `isUrl` (no allow rule lists it), because
  a tool such as Desktop Commander's `read_file` with `isUrl: true` makes an outbound request that can carry data in the URL. The rule `ask-url-flag` is redundant in the
  starter as shipped (default `ask`, no allow rule lists `isUrl`) and is kept as defence in depth for copies that widen `arg_keys` or the default. The allow rules cannot
  see tool annotations such as `openWorldHint`.
- **Asks** (a human decides) when `path`, `paths` (any entry), `source`, `destination`, `directory` or `file` contains, in any letter case, `.ssh`, `.aws`, `.gnupg`,
  `.env`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `credentials`, `secrets`, `.netrc`, `.pgpass`, `.npmrc`, `.docker`, `.pem`, `.p12`, `.pfx`,
  `/etc/shadow`, `/etc/passwd`, `sudoers`, `/proc/`, `.bash_history`, `.git-credentials`, `.kube`, `.git/config` or `://` (a URL). One `icontains_any` rule per argument, so
  one sensitive entry in `read_multiple_files` holds the whole call. This is a substring test on the WRITTEN path only. A link `notes.txt -> .env` is not
  matched by it; it is either asked (the proxy's precheck sees the link) or, if auto-allowed, runs in a worker that cannot open `.env` (rule 5). A hard link or a
  bind mount under a harmless name IS readable: the kernel grants what was named, these rules judge whether the name is sensitive. These rules beat the allow rules.
- **Path reads need a confinable server.** The allow rules carry `confine` (`read` for `read_file`, `read_text_file`, `read_multiple_files`; `list` for
  `list_directory`, `list_directory_with_sizes`, `directory_tree`, `search_files`, `get_file_info`; `{}` for the tools without paths). They auto-allow only
  through a proxy whose server has a `sandbox` with `runtime` (docs/boundary.md has a filesystem-server example); otherwise every such read gets a card.
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
On the recorded v3 traces the starter allows 115 of 376 benign proposals and 0 of the 127 violating ones on a confinable server (`policy_cli test builtin:starter
--traces ../eval/final_v3/traces.json`); with `--unconfinable` (an unsandboxed server) it allows none of them.

## Tools
`cd server && python -m policy_cli lint policy.json`; `explain policy.json --server fs --tool write_file --args '{"path":"/etc/x"}' [--alert]`;
`test policy.json --traces ../eval/final_v3/traces.json [--unconfinable]` replays recorded proposals (as the hub decides them on a confinable server, or with
`--unconfinable` on one without sandbox/runtime) and prints verdict counts, which rules fired, **violating proposals the policy would allow (aim for 0)** and **benign proposals it would ask (the human burden)**.

## In the UI
Inbox cards show "held by rule X" and, for a symlinked path value, where it leads (a hint); auto-resolved rows show "auto-allowed by rule X" or "denied by rule X". `/health` reports `policy: {digest, rules, usable}` (path only with the token).

## Limits
Hub only (the built-in agent loop does not use it yet); the policy is read at each proxy session start and pinned for that session; no regex; no drift-state inputs. A policy is a burden reducer,
not a detector: the example policy on the v3 traces still allows violating proposals that only semantics can catch, so keep a monitor running. See DECISIONS D18.

**Known limits of the starter (accepted, from the independent review).** It is a substring test, so it errs towards asking: ordinary files such as `src/credentials.py`, `docs/secrets.md`,
`.env.example`, `.envrc`, `.dockerignore`, fixture `*.pem` files and any directory called `proc` (the `/proc/` needle) also produce a card. A listing of bare `/proc`, `/sys` or `/dev` is auto-allowed (names only; a read of a file beneath
`/proc/` is asked): the needle `/proc` without the slash would ask for it but turns one benign v3 proposal into an ask (115 to 114 of 376), so it was not adopted (a test pins this). That costs operator attention, never safety;
copy the starter with `policy_cli init` and trim the needles you do not want. A path slot holding an object, number, `null` or boolean is asked (it cannot be inspected).

**Confinement limits (DECISIONS D31).** What the kernel cannot close: (1) the grant is what was NAMED, not whether it is sensitive: a hard link or bind mount
under a harmless name is readable, and `list` exposes every name beneath; the text ask rules still decide sensitivity. (2) Metadata is not mediated by
Landlock: `stat`, `lstat`, `readlink`, `realpath` reveal existence, sizes and link targets of any path (`get_file_info` anywhere). (3) The worker always reads
the system set (`/usr`, `/lib`, `/etc/ssl`, ...), its `runtime` and its HOME: a named file there is readable without a grant. (4) Only the confined worker is
narrowed: the hub, the proxy and a session server's own process (human-approved calls) keep their access. (5) Network is the server's setting; Landlock does not
cover UDP or pathname unix sockets. (6) The threat model is a trusted server driven by hostile arguments; a malicious server is the sandbox's business (D21).
(7) Human-approved calls and the legacy `auto_approve` list (no policy) are not confined; the card's link target is a hint and can differ from what the server
opens: for `lnk/../b` it shows both resolutions (`..` after the link, and `..` resolved first as Node does) and says a human-approved call is not confined. (8) A one-shot worker does not see a session server's in-memory state (use it for stateless path tools) and costs a server start per auto-allowed read
(about 0.2 s for the filesystem server, 0.8 s for Desktop Commander, measured).
