# Running SENTINEL: workflows, local setup, and deploying to AWS

Everything below was checked against the code in this repository. Where something is a recommendation I have **not** run (notably anything on AWS), it says so.

## 0. What the pieces are

| Piece | What it is | Where it runs |
|---|---|---|
| **Backend** (`server/`) | FastAPI app. Holds the approval hub (`/proxy/ws`, `/inbox/ws`), the built-in demo agent (`/ws`), monitors, policy, event log, identity. **One process, in-memory state.** | A server (your laptop, an EC2 box, a container) |
| **Inbox UI** (`frontend/`) | React app. The human's approval screen (Inbox tab) and the demo agent view (Session tab). Static files after `npm run build`. | Any static host or `npm run dev` |
| **Proxy** (`sentinel_proxy/`) | A stdio MCP server you put between an agent and its real MCP servers. Every tool call is held until a human approves. | **On the agent's machine** (laptop, CI runner), not on the backend |

Flow: `agent --stdio--> sentinel_proxy --stdio--> real MCP servers`, and `sentinel_proxy --websocket--> backend <--websocket-- Inbox UI`.

## 1. Prerequisites

- Linux or macOS (the sandbox features are **Linux only**; everything else works on macOS). Windows is untested.
- Python 3.13 (what this was built and tested on), Node 22 (tested on v22), git.
- For real embeddings (alerts that look at meaning): network access to huggingface.co **once** to download `all-MiniLM-L6-v2` (~90 MB, cached in `~/.cache/huggingface`). Without it the monitors fall back to a stub and `/health` says so.
- Optional: an `OPENROUTER_API_KEY` for the built-in demo agent only. The MCP proxy path needs **no LLM key**.

```bash
git clone https://github.com/Kminhas21/AirLock.git && cd AirLock
git checkout fix/verified-gate-and-bug-fixes          # the branch of PR #1, which holds all of this work (check whether it has been merged yet)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt                    # backend + seismograph (torch via sentence-transformers) + proxy + test deps
cd frontend && npm ci && cd ..
```
`pip install` pulls PyTorch (large, a few GB). For a backend-only install: `pip install -r server/requirements.txt -r requirements-proxy.txt` (add `-r seismograph/requirements.txt` for real embeddings).

## 2. See it work locally in ~5 minutes (no API key, no LLM)

Terminal 1, the backend (single shared token, the simplest mode):
```bash
cd server
SENTINEL_WS_TOKEN=devtoken SENTINEL_MONITOR=action_sim uvicorn main:app --port 8080
# first start downloads MiniLM; to skip real embeddings for a first look add SENTINEL_EMBEDDER=stub
curl localhost:8080/health          # {"status":"ok","monitor":"action_sim",...}   (monitor:"rules" => the stub/fallback is active; it says so)
```
Terminal 2, the Inbox UI:
```bash
cd frontend
VITE_SENTINEL_WS_TOKEN=devtoken npm run dev     # open http://localhost:5173 and click the "Inbox" tab (must be exactly this origin)
```
Terminal 3, a pretend agent calling a real (fake) MCP server through the proxy:
```bash
cat > /tmp/proxy.json <<EOF
{"session_id": "demo", "backend": "ws://127.0.0.1:8080/proxy/ws",
 "servers": {"fs": {"command": "python", "args": ["$PWD/tests/proxy/fake_downstream.py"]}}}
EOF
export SENTINEL_WS_TOKEN=devtoken PYTHONPATH=$PWD
python tests/proxy/agent_cli.py /tmp/proxy.json write_file '{"path": "/tmp/x", "content": "hello"}'
```
The Inbox shows a card: server, tool, the exact arguments. Click **Approve** and the terminal prints the result; click **Deny** (optionally with a reason) and it prints `Denied by SENTINEL: human (operator note: ...)`. Repeat the same call after denying it and the card carries a critical alert (with real embeddings and `action_sim`).

## 3. Use it with a real MCP agent (Claude Desktop, Claude Code, Cursor, ...)

Replace each MCP server entry in the agent's config with the proxy, and move the real server into the proxy's `proxy.json`:
```json
// proxy.json
{"session_id": "my-laptop",
 "backend": "ws://127.0.0.1:8080/proxy/ws",
 "servers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/work"]}},
 "auto_approve": ["fs:read_text_file", "fs:list_directory"]}
```
```json
// the agent's MCP config
{"mcpServers": {"sentinel": {"command": "/path/to/AirLock/.venv/bin/python",
   "args": ["-m", "sentinel_proxy", "--config", "/path/to/proxy.json"],
   "env": {"PYTHONPATH": "/path/to/AirLock", "SENTINEL_WS_TOKEN": "devtoken"}}}}
```
Tool names are unchanged; a name clash between two servers needs a per-server `"prefix"`. Anything not in `auto_approve` waits in your Inbox (default timeout 300 s, then it is denied).

## 4. The built-in demo agent (Session tab)

Needs `OPENROUTER_API_KEY` (or `OLLAMA_BASE_URL=http://localhost:11434/v1` for a local model) in `server/.env` or the environment. Open the Session tab, type a task, pick Aligned or Adversarial, **Run**. You see the kill-chain graph, the drift chart (Mahalanobis distance against the 3.368 threshold), alerts, and Approve/Deny on every tool call. The cached replay (`demo/cached_runs`) works with no key but is reachable only through a raw WebSocket client sending `{"event":"start_task","mode":"replay","scenario":"aligned"}`; the UI does not offer it.

## 5. All user workflows

**W1 Developer, first look.** Section 2.
**W2 Operator on one machine (solo).** Section 3. Day to day: leave the Inbox tab open; approve/deny; type a reason in the box next to Deny and the agent receives it (`operator note`); use the card's panels: *Why flagged* (alert score against its threshold, earlier denials) and *Session so far* (counters, last 10 calls, secrets redacted).
**W3 Tuning what you are asked about.** (a) `auto_approve` in `proxy.json` for tools you always allow; (b) a **policy** (below); (c) a **monitor** (`SENTINEL_MONITOR`): `action_sim` (default; meaning-based, needs MiniLM), `rules`, `learned`, the registry modes (need `SENTINEL_REGISTRY`, see `docs/registry.md`) or `registry_learned_dropout_or_action`. A monitor alert always holds a call, even an allow-listed one. With the `rules` monitor or the stub embedder no alerts are raised and auto-approvals are disabled (those calls are held).
**W4 Policy author.** `SENTINEL_POLICY=policy.json` (see `docs/policy.md`, example `docs/examples/policy.example.json`): `cd server && python -m policy_cli lint policy.json`, `explain ... --tool write_file --args '{...}'`, `test policy.json --traces ../eval/final_v3/traces.json` (counts what it would allow/ask; aim for 0 violating proposals allowed). With a policy, `auto_approve` is ignored. Optional: `SENTINEL_POLICY_WRITABLE=1` lets an operator create standing rules from a card ("Always allow/deny/ask like this"), applied to NEW sessions.
**W5 Running risky servers safely (Linux).** Per server in `proxy.json`: `"sandbox": {...}`, `"lifecycle": "per_call"`, `"secrets": {"GITHUB_TOKEN": {"from_env": "HOST_GITHUB_TOKEN", "tools": ["create_issue"]}}`: a least-privilege sandbox (filesystem, network, env, limits) and credentials that exist only inside one approved call. The card warns "This call will receive credentials: GITHUB_TOKEN". Read `docs/boundary.md` for what it does **not** cover (the agent's own non-MCP tools).
**W6 Audit and incident review.** `SENTINEL_EVENT_LOG=/var/lib/sentinel/events.db SENTINEL_LOG_KEY=<16+ chars>`; then `cd server && python -m eventlog_cli verify events.db` (exit 1 = tampering), `show events.db --session S`, `export events.db --jsonl`, `policy-test events.db policy.json` (what would a policy have done to real calls). After a restart, calls that were pending are logged as denied (`restart`) and shown as history. `docs/eventlog.md`.
**W7 Team / multi-tenant admin.** `SENTINEL_IDENTITY_FILE=identity.json` created with `python -m identity_cli add-operator|add-agent <id> --tenant T --role R --file identity.json` (`--file` goes AFTER the subcommand; each prints a token once); roles viewer/approver/admin; tenants; optional JWT for SSO tokens; escalation levels with webhook notifications (Slack/JSON). Operators click **Sign in** and paste their token; agents get `SENTINEL_AGENT_TOKEN`. `docs/identity.md`.
**W8 Researcher / maintainer.** `scripts/verify.sh` (the gate; ~45 min; exit 0 = green), `python -m eval.run_eval_v3*` (detector evaluations, one-shot), `DECISIONS.md` for why things are the way they are.

## 6. Configuration cheat-sheet (the ones you will actually set)

`SENTINEL_WS_TOKEN` (legacy shared token; **required** for the inbox sockets when no identity file) · `SENTINEL_IDENTITY_FILE` · `SENTINEL_ALLOWED_ORIGINS` (browser Origins allowed to connect; default `http://localhost:5173`) · `SENTINEL_GATE_TIMEOUT_S` (300) · `SENTINEL_MONITOR` · `SENTINEL_EMBEDDER=minilm|stub` · `SENTINEL_REGISTRY` · `SENTINEL_POLICY` · `SENTINEL_POLICY_WRITABLE` · `SENTINEL_EVENT_LOG`/`SENTINEL_LOG_KEY` · `SENTINEL_PUBLIC_URL` (link in notifications) · `SENTINEL_HEALTH_DETAIL=1` (show paths in `/health` without a token) · `HF_HUB_OFFLINE=1` (never touch huggingface at runtime) · frontend build-time: `VITE_SENTINEL_WS_URL`, `VITE_SENTINEL_INBOX_WS_URL`, `VITE_SENTINEL_WS_TOKEN` (legacy only) · proxy: `SENTINEL_AGENT_TOKEN` (or `SENTINEL_WS_TOKEN`), `SENTINEL_PROXY_CONNECT_WAIT_S`.

## 7. Deploying to AWS (a reference recipe, NOT run or tested here)

**Honest status:** the repo has no Dockerfile, no Terraform/CDK, no systemd unit and no CI deploy. Nothing in this section has been executed on AWS. Proposal #7 (operating the monitor as a service) is not built.

**Constraints that shape any deployment**
1. **Exactly one backend process.** All state (pending calls, sessions, tenant filters, escalation timers) is in memory. Do not run `--workers N`, do not scale beyond one task. A restart denies the in-flight calls (logged as `restart`), by design.
2. WebSockets are required end to end (ALB/nginx must allow upgrades and long idle times, at least longer than the gate timeout: set 3600 s).
3. Use **identity mode** on the internet (no tokens in URLs; the legacy mode puts `?token=` in the URL, which ends up in proxy/access logs).
4. TLS in front (ACM certificate on an ALB, or Caddy/nginx with Let's Encrypt). Browsers need `wss://`.
5. `SENTINEL_ALLOWED_ORIGINS` must list the exact HTTPS origin of the UI (`https://sentinel.example.com`).
6. The proxies run **on the agent hosts** and connect out to `wss://sentinel.example.com/proxy/ws` with `SENTINEL_AGENT_TOKEN`.
7. Bake the MiniLM model into the image/AMI and set `HF_HUB_OFFLINE=1` (otherwise the first start needs huggingface.co).
8. The SQLite event log wants a local disk (an EBS volume). SQLite on EFS/NFS is discouraged (locking). Back the volume up.
9. Behind a load balancer start uvicorn with `--proxy-headers --forwarded-allow-ips='*'` (trusting only your ALB's subnet if you can) so the sign-in throttle sees the real client address, not the ALB's. I have not tested this combination; check it with a deliberately failing login.
10. Keep the identity file, `SENTINEL_LOG_KEY` and webhook secrets in Secrets Manager/SSM and write them to a 0600 file or environment at start. The identity file holds only token digests, but treat it as sensitive.

**Recipe A, one EC2 instance (simplest; recommended first)**
1. t3.large (MiniLM runs on CPU; 8 GB RAM is comfortable), Ubuntu 24.04, 30 GB gp3 root + a separate 10 GB gp3 volume mounted at `/var/lib/sentinel`. Security group: 443 from where you need it, 22 from your IP only.
2. Install Python 3.13 (deadsnakes/pyenv/uv; 3.12 is untested), clone the repo at a **tag or commit you tested**, `pip install -r server/requirements.txt -r seismograph/requirements.txt` into a venv, run once with network to cache MiniLM, then set `HF_HUB_OFFLINE=1`.
3. Create the identity file with `identity_cli` (first admin, an agent per CI runner/laptop); put it in `/var/lib/sentinel/identity.json` (0600, owned by a dedicated `sentinel` user).
4. systemd unit (reference): `ExecStart=/opt/sentinel/.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8080 --proxy-headers --forwarded-allow-ips=127.0.0.1`, `WorkingDirectory=/opt/sentinel/server`, `User=sentinel`, `EnvironmentFile=/etc/sentinel/env` containing `SENTINEL_IDENTITY_FILE`, `SENTINEL_ALLOWED_ORIGINS`, `SENTINEL_MONITOR=action_sim`, `SENTINEL_EVENT_LOG=/var/lib/sentinel/events.db`, `SENTINEL_LOG_KEY`, `HF_HUB_OFFLINE=1`, `SENTINEL_PUBLIC_URL`, optionally `SENTINEL_POLICY`; `Restart=on-failure`.
5. nginx (or Caddy) terminating TLS and proxying `/` to `127.0.0.1:8080` with `proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header X-Forwarded-For $remote_addr; proxy_read_timeout 3600s;`.
6. UI: on your machine `cd frontend && VITE_SENTINEL_INBOX_WS_URL=wss://sentinel.example.com/inbox/ws VITE_SENTINEL_WS_URL=wss://sentinel.example.com/ws npm run build`, then upload `frontend/dist` to S3 behind CloudFront, or serve it from the same nginx. Do **not** set `VITE_SENTINEL_WS_TOKEN` (identity mode).
7. Point DNS at it. Test: `curl https://sentinel.example.com/health`, sign in at the UI, run section 3 on a laptop with `"backend": "wss://sentinel.example.com/proxy/ws"` and `SENTINEL_AGENT_TOKEN`.

**Recipe B, ECS Fargate + ALB (more AWS-native, more work).** Needs a Dockerfile you would have to write (python:3.13-slim, install the requirements, copy `server/ seismograph/ eval/`, bake MiniLM, run uvicorn as above). Desired count **1**, ALB idle timeout 3600 s, health check `GET /health`, secrets from Secrets Manager into env, ephemeral storage only (so the event log is lost on a task replacement unless you use EBS via ECS-on-EC2). The UI goes to S3+CloudFront as above.

**What I would not do yet:** put it on the public internet without identity mode and TLS; run more than one backend process; rely on the sandbox features on Fargate (Landlock/user namespaces may be unavailable there: the sandbox then **fails closed**, i.e. sandboxed servers refuse to start).

## 8. Troubleshooting

- *Inbox says Disconnected / Sign in loops*: the browser Origin is not in `SENTINEL_ALLOWED_ORIGINS`, the token is wrong (legacy mode: `VITE_SENTINEL_WS_TOKEN` must equal `SENTINEL_WS_TOKEN` at **build/dev start** time), or the backend has no token/identity file (the inbox sockets refuse to run unauthenticated).
- *`/health` shows `"monitor":"rules"` although you asked for `action_sim`*: MiniLM could not load (stub embedder). It falls back loudly and auto-approve is disabled. Check network once, or the HF cache, or `HF_HUB_OFFLINE`.
- *Proxy exits 3*: backend rejected it (`unauthorized`, `forbidden_server`, duplicate session id, `log_unavailable`); read its stderr line. *Exit 4*: a requested sandbox layer is unavailable on this machine.
- *Every call is held and nothing auto-approves*: working as designed when no working monitor is active, when a call receives credentials, or when a policy is broken.
- *Run the checks*: `scripts/verify.sh`; for one area, `pytest tests/server`, `pytest tests/proxy`, `cd frontend && npx vitest run`.
