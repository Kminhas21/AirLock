# Running SENTINEL in Docker

One image serves the hub **and** the built operator UI (`http://localhost:8080`). It is built in stages and **the image
does not exist unless its tests passed**.

```
cp .env.example .env        # fill SENTINEL_BOOTSTRAP_ADMIN_TOKEN / _AGENT_TOKEN (>= 24 chars each, different) and SENTINEL_LOG_KEY
docker compose up -d --build
open http://localhost:8080  # sign in with the admin token
docker compose --profile demo run --rm demo-agent    # a fake agent asks to write a file; decide it in the Inbox
```

## Build stages (`Dockerfile`)

| stage | what it does |
|---|---|
| `py-deps` | installs the Python requirements (CPU PyTorch when `EMBEDDINGS=1`) |
| `model` | bakes the MiniLM weights into the image (no network needed at runtime) |
| `backend-test` | runs the backend tests (`TEST_LEVEL=fast` ~2000 tests, `full`, or `none`); writes a marker on success |
| `ui-deps` / `ui-test` / `ui-build` | `npm ci`, vitest, production build |
| `gate` | collects the two success markers |
| `runtime` | the deployable image; its first `RUN` bind-mounts `gate` and fails if either marker is missing, so **a failing test stops the build** |
| `demo` | runtime + a fake agent and downstream for the demo profile |
| `final` | alias of runtime (default target) |

Build args: `TEST_LEVEL` (fast|full|none), `EMBEDDINGS` (1 default; 0 = no PyTorch/model, monitors fall back to the
rules monitor and `/health` says `embedder: stub`), `TORCH_INDEX_URL` (empty = PyPI CUDA wheels, ~5 GB).

Hardening: non-root uid 10001, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, `HEALTHCHECK /health`,
loopback-only port publish (`SENTINEL_BIND`), no secrets in layers (`.dockerignore` excludes `**/.env`, keys, `identity.json`,
databases). Exactly ONE container: the hub keeps its state in memory.

Entrypoint modes: `serve` (default), `check` (validate config, exit 2 with a message on bad config), `proxy <args>`,
or any command. Event-log tools: `docker run --rm -w /app/server -v VOL:/var/lib/sentinel -e SENTINEL_LOG_KEY=... IMAGE python -m eventlog_cli verify /var/lib/sentinel/events.db`.

## Tests of the Docker setup (`tests/docker`)

* Always run (no Docker needed): Dockerfile/compose/dockerignore static checks, entrypoint and bootstrap script tests,
  and a reconstruction of the `backend-test` stage's file tree from the `COPY` lines + `.dockerignore`, running the fast tests in it.
* Opt in (`scripts/docker_test.sh`, ~6 min): builds both images (tests run inside the build), then starts real containers:
  healthy/non-root/read-only, model baked in, UI + security headers, sign-in, fail-fast config errors, no credentials in the
  image, a proxy in a SECOND container deciding a call through the Inbox with the event log verifying and surviving a restart,
  and `docker compose up` plus the demo profile.

Sandbox environment variables for `scripts/docker_test.sh`: `SENTINEL_DOCKER_TEST_LEVEL`, `_EMBEDDINGS`, `_TORCH_INDEX`,
`_NETWORK_HOST`, `_FORWARD_PROXY`, `_BUILD_CA`, `_HF_SEED`.

## Not verified

* The default `EMBEDDINGS=1` + CPU-torch path was not run end to end in the development sandbox (the CPU wheel index was
  unreachable and the CUDA stack did not fit the disk); the `EMBEDDINGS=0` build is what the container tests ran against.
* The Landlock/netns sandbox (`docs/boundary.md`) has not been exercised inside a container (it needs the right seccomp/caps).
* No TLS in the image (put an ALB/Caddy in front), no Terraform/CDK yet; see `docs/RUNNING.md` for the AWS recipes.
