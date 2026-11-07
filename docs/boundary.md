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
- `lifecycle: per_call`: a keyless worker lists the tools at startup; every APPROVED call runs in a fresh sandboxed worker that is killed afterwards (hard kill at `call_timeout_s`). `session` (default) keeps one sandboxed process alive.
- `secrets` need `per_call` and a sandbox. The value is read from the PROXY's environment at call time and handed to the worker only for the listed tools, only for that call. Secrets never appear in argv, logs, frames to the hub or the event log (names only).

## What the operator sees
Per session, boundary chips (`net none`, `fs sandboxed`, `fresh worker per call`, red `unsandboxed`, amber `weaker than requested`). On a call that will receive credentials: "This call will receive credentials: NAME (exist only during this call)". Such a call is never auto-approved by the proxy's `auto_approve`, and a policy `allow` stands only if the rule says `"secrets": true`.

## What this does NOT protect against (read this)
- The agent's own tools outside MCP (shell, filesystem, network of the agent host). Close that gap by running the AGENT in its own sandbox/container with only stdio to the proxy and the model API.
- A same-user process reading the proxy's memory or `/proc/<pid>/environ` (secrets come from the proxy's environment). Run the proxy as a different user or in its own container.
- Syscalls Landlock/namespaces do not cover (no seccomp filter yet), UDP/raw sockets under `network: host`, kernel exploits, side channels, a proxy killed with SIGKILL (workers' temp dirs are not cleaned up then).
- Linux only (x86_64 / aarch64). Needs Landlock (kernel >= 5.13) and, for `network: none`, user/network namespaces or Landlock network rules (kernel >= 6.7). Without them a sandboxed config fails closed.
See DECISIONS D21.
