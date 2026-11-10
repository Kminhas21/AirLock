# Monitoring an agent you didn't write: the MCP proxy and the approval inbox

SENTINEL sits between an MCP agent (Claude Code, Claude Desktop, Cursor, ...) and its stdio MCP servers. Every tool call is held until you approve
it in the web UI (Inbox tab), except tools you explicitly allow-listed. Monitors (action similarity, registry modes, union) look at each call and an
alert always holds the call, even an allow-listed one.

## Run it
1. Backend with a token (the inbox sockets refuse to work without one):
   `cd server && SENTINEL_WS_TOKEN=<secret> SENTINEL_MONITOR=action_sim uvicorn main:app --port 8080`
2. UI: `cd frontend && VITE_SENTINEL_WS_TOKEN=<secret> npm run dev`, open the **Inbox** tab.
3. Proxy config `proxy.json`:
   ```json
   {"session_id": "my-agent",
    "servers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/work"]}},
    "auto_approve": ["fs:read_text_file", "fs:list_directory"]}
   ```
   (optional per server: `prefix`, `env`, `cwd`, `trust_read_only_hint`; optional `backend`, default `ws://127.0.0.1:8080/proxy/ws`)
4. Point your agent at the proxy instead of the server, passing the token through the MCP client's env:
   `{"command": "python", "args": ["-m", "sentinel_proxy", "--config", "/path/proxy.json"], "env": {"SENTINEL_WS_TOKEN": "<secret>"}}`
   (run from the repo root, or install the repo on PYTHONPATH). Install the dependency: `pip install -r requirements-proxy.txt`.

## What you will see
- A card per held call: server, tool, the exact arguments (numbered lines; huge arguments disable Approve), any monitor alert, a countdown.
- **Approve** forwards the call; **Deny** (or the 300 s timeout, a dropped proxy, a dead backend) returns "Denied by SENTINEL: <reason>" to the agent.
- Auto-approved calls need no click, but are shown as resolved ("auto").

## Rules to remember
- Only the exact string `approve` approves. Every failure is a deny.
- Use a call-based monitor. With `SENTINEL_MONITOR=rules` or the stub embedder no alerts can be raised, so auto-approve is DISABLED (those calls are held).
- Monitor history is per proxy session: a restarted proxy starts with an empty denied history. Keep `session_id` stable, and note a second live proxy with
  the same id is rejected.
- Token limit: it keeps out processes that cannot read your environment. Anything with full access to your account can read it.
- Not covered yet: HTTP/SSE downstream servers, tools/list_changed, multi-user, hosted deployment. See DECISIONS D16.

## Compatibility with real MCP servers (measured, DECISIONS D26)
Each server below was run DIRECTLY and THROUGH the proxy and hub with the same MCP client, and everything the client can observe was diffed
(`docs/TESTING_REALITY.md`, rung 2): filesystem 1.0.0, memory 1.0.0, sequential-thinking 1.0.0, the protocol-coverage `everything` 1.0.0 (all npm), Microsoft
Playwright MCP 0.0.85 (real Chromium), git, fetch, time (PyPI, current SDK), and sqlite 2025.4.25 (built on the OLD 1.x Python SDK; it works through the 2.x proxy).

**Passes through unchanged:** the tool list (names, descriptions, input and output schemas, annotations such as `readOnlyHint`), and every call result: text,
image, embedded resource, `resource_link`, `structuredContent`, `isError`. Every call was held by the gate. A downstream gets a CLEAN environment (not your shell's).

**Does NOT pass through (the proxy is a tool gate, not a transparent MCP proxy):**
- `resources`, `prompts`, `completions`, `logging` and `tasks`: the client sees only the `tools` capability and gets "Method not found" for the rest. A server whose value is
  mostly resources or prompts (the git and sqlite servers' prompts, fetch's resources) loses that part. Nothing is gated or leaked; it is simply not offered.
- Server `instructions` (the usage hints a client normally adds to the model's context) and logging notifications.
- `progress` notifications: a long tool call shows no progress, and a client that extends its timeout on progress will not get that extension.
- Server-to-client requests (`sampling`, `roots`, `elicitation`): the proxy does not declare those client capabilities, so a server that needs them does not OFFER
  the tools that depend on them (4 of the 17 `everything` tools were absent through the proxy).
- The server's identity: the client sees `sentinel-proxy`. Starting a proxied server takes about 3 s longer (hub connection and monitor build).
- HTTP/SSE (remote) servers: stdio only.

### Third-party servers (chosen by research, not written by us)
Chosen from public MCP-server rankings (2026) on four criteria: widely used, NOT an Anthropic reference server, runs over stdio without credentials, and exercises the risky classes the gate exists for.
**Desktop Commander 0.3.1** (`@wonderwhy-er/desktop-commander`, MIT; terminal execution, file read/write/edit, process control: 25 tools) and **Context7 4.6.0** (`@upstash/context7-mcp`, MIT; library documentation
from a hosted API: 2 tools). Both were run directly and through the proxy and hub, and with a real Claude Code client behind `builtin:starter`.
- Desktop Commander: all 25 tools, schemas and annotations identical through the proxy; 10 of 10 calls gated; a real `start_process` ran only after approval; a denied `rm -rf` left the project directory intact.
  Dropped as documented above: its `instructions`, its `resources` (`ui://` pages) and its logging notifications (49 in one session).
- Context7: works end to end through the proxy (real library results after approval; the anonymous tier answers a monthly-quota error when shared egress is exhausted: the real server's own message is passed back unchanged).
- **A proxied server gets a CLEAN environment on purpose.** A server that needs the network from behind an HTTPS proxy, or needs credentials, must be given them in its own `env` block
  (here: `HTTPS_PROXY`, `NODE_USE_ENV_PROXY=1`, `NODE_EXTRA_CA_CERTS` for Node's built-in `fetch`); without them Context7 answered "fetch failed" even when run directly in the same minimal environment.
- The starter policy auto-allowed Desktop Commander's `read_file {isUrl: true}` (an outbound HTTP request) because the allow rules match tool NAMES on any server: fixed by asking for any URL-like value and for `isUrl: true` (D27).

