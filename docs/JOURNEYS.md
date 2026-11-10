# User-journey tests (`frontend/journeys`)

One spec per user workflow in `docs/RUNNING.md` (W1, W2, W4, W5, W6, W7) plus W9 (Docker). Each journey starts its OWN real stack:
the real backend serving the BUILT UI from one origin, a real stdio proxy and a scripted agent, an identity file with per-person tokens
(W1 uses no identity and a scripted LLM), and for W9 the real hardened Docker image plus a demo-agent container.

    cd frontend && npm run journeys                 # builds the UI, runs all journeys (W9 skips if sentinel:local / sentinel:demo are not built)
    npx playwright test -c playwright.journeys.config.ts j2   # one journey

Every journey writes numbered, named screenshots to `frontend/journeys/.shots/<journey>/` (git-ignored; never committed). W6 also writes
`cli-evidence.txt` (verify OK, and a tampered copy failing at the first bad event). Gate: `RUN_JOURNEY_TESTS=1 scripts/verify.sh`.

**W10 live drift** (`j10-live-drift.spec.ts`) answers "is the monitor live, real and novel?": the stack runs the REAL MiniLM (a journey fails if `/health`
says anything else), `tests/browser/novel_llm.py` invents fresh text every run (no trace, replay file or cache can contain it), the UI sends `mode: "live"`,
the Plotly chart equals the `drift_update` frames of THIS run, an INDEPENDENT fresh MiniLM recomputation (`journeys/tools/recompute_drift.py`) reproduces the
numbers, and a second run on the same page replaces the first. A second test repeats the checks with a REAL model through OpenRouter and is skipped unless
`OPENROUTER_API_KEY` is set (it uses `gpt-4o-mini`; the key is read from the environment only, never stored). Every journey now defaults to MiniLM.
Negative check done by hand: with `SENTINEL_EMBEDDER=stub` the recomputation disagrees (e.g. distance -0.26 vs -11.6) and the test fails.

Honest limits: agents are scripted MCP clients behind the real proxy (not Claude Desktop); W5 needs Landlock/user namespaces (Linux);
The novel LLM is synthetic (it is not a model); the real-model test is the only one with unscripted model text and its alerts depend on the model. W9 uses the `EMBEDDINGS=0` image (stub embedder inside the container) unless `JOURNEY_DOCKER_IMAGE` is set.
