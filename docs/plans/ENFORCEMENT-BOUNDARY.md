# Plan: enforcement boundary (GitHub issue #5, docs/PROPOSALS.md #5), first iteration

## The honest problem
"Denied" today means the proxy did not forward the call. Two gaps remain: (1) an APPROVED call runs with whatever authority the downstream server process has (full filesystem, full network, long-lived secrets in its environment, forever);
(2) the agent can bypass the proxy with tools it has outside MCP. SENTINEL cannot close (2) from the proxy: that is the agent host's sandbox. This iteration closes (1) and makes the boundary VISIBLE:
**least-privilege sandboxes for the downstream servers, and just-in-time secrets that exist only inside a short-lived worker for the duration of one approved call.**

## What this machine can enforce (probed)
Linux 6.18: Landlock ABI 7 (filesystem + TCP connect/bind rules), user + network + mount + pid namespaces via `os.unshare`, `prctl(PR_SET_NO_NEW_PRIVS)`, `setrlimit`. No bwrap/firejail, no seccomp library: everything is done with the Python stdlib + ctypes syscalls (no new dependency).
Unsupported kernels/OSes FAIL CLOSED: a server configured with a sandbox whose requested layer is unavailable is NOT started (`require` defaults to true).

## Components
### 1. Sandbox trampoline: `sentinel_proxy/sandbox.py` + `python -m sentinel_proxy.sandbox_exec --spec <base64-json> -- <command> <args...>`
Spec (JSON object, strict, unknown keys rejected):
`{"read": [abs paths], "write": [abs paths], "network": "none"|"loopback"|"host", "env_allow": [names], "rlimits": {"cpu_s": int, "mem_mb": int, "nofile": int, "nproc": int, "fsize_mb": int}, "require": true|false}`.
The trampoline, in this order, in the child BEFORE exec: (a) filter its own environment down to `env_allow` (+ `PATH`, `LANG`, `HOME` set to a fresh empty temp dir) so only listed names survive; (b) `setrlimit`s; (c) `PR_SET_NO_NEW_PRIVS`; (d) network: `none` => `os.unshare(CLONE_NEWUSER|CLONE_NEWNET)` when not already root-capable, or `CLONE_NEWNET` as root, else Landlock TCP deny-all (ABI >= 4); `loopback` => new netns + bring `lo` up (or Landlock allowing only 127.0.0.1 is NOT possible, so require the netns); `host` => no network restriction; (e) Landlock filesystem: handle all FS access rights; allow read on `read` + a built-in system read set (`/usr /lib /lib32 /lib64 /bin /sbin` , the Python prefixes `sys.prefix sys.base_prefix`, `/dev/null /dev/zero /dev/urandom` (read), `/proc/self` NOT allowed, `/etc/ssl /etc/ld.so.cache /etc/localtime` read) and read+write on `write` + the private temp HOME; everything else denied (including `/etc/passwd`, `/home`, `/root`, the repo, `/proc`, `/sys`); (f) `exec` the command (resolved with the SAFE path set).
Failure policy: if `require` is true and ANY requested layer cannot be applied, the trampoline prints a one-line reason to stderr and exits 126 WITHOUT exec'ing; with `require` false it applies what it can and records what it could not.
Status: before exec the trampoline writes one line `SENTINEL_SANDBOX_STATUS {json}` to stderr: `{"layers": ["env","rlimit","no_new_privs","netns"|"landlock_net","landlock_fs"], "missing": [...], "network": "...", "landlock_abi": n}`.
API for the proxy: `probe() -> {"landlock_abi": int, "unshare_net": bool}`, `sandbox_params(spec, command, args, env) -> (command, args, env)` (wraps the downstream's command in the trampoline; `env` passed through as the PROCESS environment, never argv, so secrets are not visible in `ps`), `validate_spec(obj) -> spec` (raises `SandboxSpecError`).
### 2. Proxy integration (`sentinel_proxy/config.py`, `proxy.py`, `backend.py`)
Per server (all optional, default = today's behaviour):
`"sandbox": <spec>`, `"lifecycle": "session"|"per_call"` (default session), `"secrets": {"ENV_NAME": {"from_env": "HOST_VAR", "tools": ["tool", ...]}}`, `"call_timeout_s": 60`.
- `session` lifecycle: the server is spawned once inside its sandbox. `secrets` are NOT allowed here (config error): a long-lived process would keep them.
- `per_call` lifecycle (required for secrets): at startup a KEYLESS sandboxed worker is started only to read `tools/list`, then closed. Each APPROVED call starts a fresh sandboxed worker, injects only the secrets whose `tools` list contains this tool (values read from the proxy's own environment at that moment; a missing host variable => the call is refused with `secret_unavailable`, nothing started), performs initialize + the one `tools/call`, returns the result, and kills the worker (hard kill after `call_timeout_s`; the secret never outlives the call). Workers never receive the proxy's other environment.
- `proxy_hello` gains `boundary`: `{server: {"lifecycle", "layers": [...], "missing": [...], "network", "secrets": ["ENV_NAME", ...]}}` (names only, never values).
- `proxy_call` gains `secrets_used`: the ENV_NAMEs this call will receive (empty list normally), so the human sees credentials being granted BEFORE approving.
- The proxy refuses to start a sandboxed server when the trampoline reports `missing` layers and `require` is true; it logs the boundary at startup on stderr.
### 3. Hub (`server/inbox_hub.py`): validates and carries `boundary` and `secrets_used`
Closed shapes/limits (<= 50 servers, <= 20 names each, names `^[A-Z_][A-Z0-9_]{0,63}$`, layers from the closed set `env rlimit no_new_privs netns landlock_net landlock_fs`); invalid => treated as absent (never fatal). Stored in the `proxy_hello` and `call_proposed` log payloads (names only), included in `inbox_snapshot.sessions[].boundary`, `inbox_pending.secrets_used`. A call with `secrets_used` NON-EMPTY is never auto-approved by the legacy `auto` flag and never by a policy `allow` unless the policy rule says so explicitly with `secrets: true` in `when` (new boolean condition, policy engine + writer: a policy that does not mention it holds such calls for the human).
### 4. UI
Per session a "Boundary" chip row (per server: network none/loopback/host, fs sandboxed yes/no, lifecycle); a prominent "This call will receive credentials: NAME1, NAME2" warning on the card; the Approve button text stays "Approve". 
### 5. Tests and gate
Real-process tests that PROVE enforcement (write outside allowed path fails, read of a canary file fails, outbound connection to a local listener fails under network none, env canary is scrubbed, rlimit enforced, secret absent in a session-lifecycle server and in later calls, present only during the approved call, worker dead after the call), fail-closed tests (`require` with an unavailable layer, monkeypatched `probe`), mutants in the gate, Playwright (boundary chip + credential warning), docs/boundary.md, DECISIONS D21.

## Threat model (put in docs/boundary.md)
Protects against: a compromised or buggy downstream server or tool call reading/writing files it should not, calling out to the network, or holding long-lived secrets; an approved call having more authority than its operator thought; secrets leaking via the downstream's environment at startup.
Does NOT protect against: the agent's own tools outside MCP (needs the agent host sandboxed: run the agent in its own container, give it only stdio to the proxy and the model API); a process that can read the proxy's memory/environment (same-user agents can read `/proc/<pid>/environ`: run the proxy as a different user or inside its own container); kernel exploits; side channels; syscalls not covered by Landlock/namespaces (no seccomp filter in v1); UDP/raw network when `network: host`; TOCTOU of path allowlists on shared mounts. Linux only.

## Tickets
| Id | Area | Files |
|---|---|---|
| EB1 | sandbox trampoline + probe + spec validation | `sentinel_proxy/sandbox.py`, `sentinel_proxy/sandbox_exec.py`, `tests/proxy/test_sandbox*.py` |
| EB2 | proxy integration (config, per_call workers, JIT secrets, boundary, secrets_used) | `sentinel_proxy/*`, `tests/proxy/*` |
| EB3 | hub + policy `secrets` condition | `server/inbox_hub.py`, `server/policy.py`, `server/policy_writer.py`, tests |
| EB4 | UI chip + credential warning | `frontend/src/**` |
| EB5 | e2e, gate stage, mutants, docs/boundary.md, D21, issue #5 comment | tests/e2e, frontend/e2e, scripts, docs |
Non-goals: seccomp filters, PID namespace per worker, cgroups, container images, macOS/Windows, HTTP/SSE downstream, a credential-injecting egress proxy, sandboxing the agent host.
