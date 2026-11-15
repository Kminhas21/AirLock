# Enforcement boundary: sandboxed downstream servers and just-in-time secrets (opt-in, Linux)

Approving a call used to mean "the proxy forwards it to a server that can do anything". Now each downstream server can run in a **least-privilege sandbox**, and credentials can exist **only inside a short-lived worker for one approved call**.

## Config (per server in `proxy.json`; everything optional, default = unchanged behaviour)
```json
{"servers": {"github": {
   "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
   "lifecycle": "per_call", "call_timeout_s": 30,
   "sandbox": {"read": ["/opt/mcp"], "write": ["/work/out"], "network": "none", "env_allow": [], "require": true,
               "rlimits": {"cpu_s": 60, "mem_mb": 1024, "nofile": 256, "nproc": 64, "fsize_mb": 100}},
   "secrets": {"GITHUB_TOKEN": {"from_env": "HOST_GITHUB_TOKEN", "tools": ["create_issue"]}}}}}
```
- `sandbox`: Landlock filesystem rules (only the built-in system read set plus your `read`/`write` paths), network `none | loopback | host` (a network namespace; Landlock TCP deny as fallback), environment filtered to `env_allow`, resource limits, no_new_privs, all capabilities dropped, a private empty HOME. `require: true` (default) means: if any requested layer cannot be applied the server is NOT started (proxy exit code 4). Nothing is ever silently run unsandboxed.
- `command` inside a sandbox: a BARE name (`python`, `npx`) is looked up only in `/usr/local/bin:/usr/bin:/bin`, never in the proxy's `PATH` (fail closed). An interpreter elsewhere (a venv, pyenv, nvm, a CI toolcache such as `/opt/hostedtoolcache`) needs an absolute path, under a readable directory; otherwise the server does not start (`sentinel-sandbox: command not found`). Found on a GitHub runner, whose `/usr/bin` has `python3` but no `python` (D30).
- `lifecycle: per_call`: a keyless worker lists the tools at startup; every APPROVED call runs in a fresh sandboxed worker that is killed afterwards (hard kill at `call_timeout_s`). `session` (default) keeps one sandboxed process alive.
- `runtime` (inside `sandbox`): absolute directories with the server's CODE (interpreter, packages), readable and executable, like the system set. With
  it, the server is **confinable**: a policy rule with `confine` can auto-allow its path calls, each in a one-shot worker whose Landlock rules grant only the
  system set, `runtime`, a private HOME and the exact objects the agent named (docs/policy.md rule 5, DECISIONS D31). Without `sandbox` + `runtime` every
  path allow is asked (chip "path allows asked: ..."). Its `read`/`write` apply to the server's own process (human-approved calls), never to a confined worker.
- `secrets` need `per_call` and a sandbox. The value is read from the PROXY's environment at call time and handed to the worker only for the listed tools, only for that call. Secrets never appear in argv, logs, frames to the hub or the event log (names only).

### A filesystem server with confined auto-allowed reads
```json
{"servers": {"fs": {
   "command": "/usr/local/bin/node", "args": ["/opt/mcp/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js", "/work"],
   "sandbox": {"read": ["/work"], "write": ["/work/out"], "runtime": ["/opt/node22", "/opt/mcp/node_modules"], "network": "none"}}}}
```
`runtime` is checked at config load, because it is read + execute for every confined worker: `/`, `/etc`, `/proc`, `/root`, `/home`, `/var`, `/sys`, `/dev`, `/tmp`,
an ancestor of the temp directory (the private HOME lives there), and any entry equal to or containing a `read`/`write` entry are refused (a `runtime` of `/`
would hand the secret to every confined read), and the proxy treats such a server as not confinable even if a config skipped validation. Name the server's own
code directories. `runtime` is where Node and the server's packages live (`readlink -f $(which node)` names the Node install; Node 22 and filesystem 1.0.0 need nothing else,
measured). With `SENTINEL_POLICY=builtin:starter` a `read_text_file` of `/work/a.txt` is auto-allowed and can read exactly `/work/a.txt`; `/work/notes.txt ->
.env` is asked (the proxy's precheck sees the link); a write is asked and, once approved, runs in the server's own process with `write: ["/work/out"]`.
The shipped `docker-compose.yml` demo server (`docker/demo/proxy.json`) is sandboxed the same way (`runtime: ["/app/tests/proxy"]`): in a container with
Docker's default seccomp profile, `openat2` and Landlock work (measured) but namespaces do not, so `network: none` uses the Landlock TCP deny (kernel >= 6.7).

## What the operator sees
Per session, boundary chips (`net none`, `fs sandboxed`, `fresh worker per call`, red `unsandboxed`, amber `weaker than requested`, amber `path allows asked: <why>`). On a call that will receive credentials: "This call will receive credentials: NAME (exist only during this call)". Such a call is never auto-approved by the proxy's `auto_approve`, and a policy `allow` stands only if the rule says `"secrets": true`.

## What this does NOT protect against (read this)
- The agent's own tools outside MCP (shell, filesystem, network of the agent host). Close that gap by running the AGENT in its own sandbox/container with only stdio to the proxy and the model API.
- A same-user process reading the proxy's memory or `/proc/<pid>/environ` (secrets come from the proxy's environment). Run the proxy as a different user or in its own container.
- Syscalls Landlock/namespaces do not cover (no seccomp filter yet), UDP/raw sockets under `network: host`, kernel exploits, side channels, a proxy killed with SIGKILL (workers' temp dirs are not cleaned up then).
- Kernel confinement of auto-allowed path calls grants what was NAMED: a hard link or bind mount under a harmless name is readable, `stat`/`readlink` of any path
  are not mediated, the system set / `runtime` / HOME are always readable, and human-approved calls run in the server's own process (docs/policy.md, "Confinement limits").
  Hard links are a documented gap, pinned by a live test (K6) so it stays visible.
- A RELATIVE value is walked from every base directory the server may map it to (its absolute directory arguments, at most 4; more asks a human), and each base that
  has the name gets a grant: with up to 4 bases the call can read the same relative name in any of them, so a name that exists in two allowed directories is
  over-granted by up to 4 files. Keep allowed directories few or use absolute paths.
- Linux only (x86_64 / aarch64). Needs Landlock (kernel >= 5.13) and, for `network: none`, user/network namespaces or Landlock network rules (kernel >= 6.7). Without them a sandboxed config fails closed.
See DECISIONS D21.
