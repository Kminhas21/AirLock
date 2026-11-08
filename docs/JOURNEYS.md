# User-journey tests (`frontend/journeys`)

One spec per user workflow in `docs/RUNNING.md` (W1, W2, W4, W5, W6, W7) plus W9 (Docker). Each journey starts its OWN real stack:
the real backend serving the BUILT UI from one origin, a real stdio proxy and a scripted agent, an identity file with per-person tokens
(W1 uses no identity and a scripted LLM), and for W9 the real hardened Docker image plus a demo-agent container.

    cd frontend && npm run journeys                 # builds the UI, runs all journeys (W9 skips if sentinel:local / sentinel:demo are not built)
    npx playwright test -c playwright.journeys.config.ts j2   # one journey

Every journey writes numbered, named screenshots to `frontend/journeys/.shots/<journey>/` (git-ignored; never committed). W6 also writes
`cli-evidence.txt` (verify OK, and a tampered copy failing at the first bad event). Gate: `RUN_JOURNEY_TESTS=1 scripts/verify.sh`.

Honest limits: agents are scripted MCP clients behind the real proxy (not Claude Desktop); W5 needs Landlock/user namespaces (Linux);
W9 uses the `EMBEDDINGS=0` image unless `JOURNEY_DOCKER_IMAGE` is set.
