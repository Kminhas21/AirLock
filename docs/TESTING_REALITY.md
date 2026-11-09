# Testing against reality: what is mocked, what is not, what broke

Most bugs in this project were found by running something REAL, not by unit tests (DECISIONS.md D16 to D24). The pattern: two components
disagree, a real model sends something nobody scripted, or the thing is packaged and run for real. This page says what each test layer really
proves, where we still fake things, and which gate stage guards each rung. Read it before trusting a green gate.

## The realism ladder

| Rung | What is real | What is still faked | Where | Gate stage |
|---|---|---|---|---|
| 0 Unit / in-process | the code under test | the model (scripted objects), the clock, the network | `tests/server`, `tests/e2e`, `tests/proxy` | `backend pytest` |
| 1 Contract and full-stack | hub + proxy + real MCP SDK over real websockets | the downstream (a 50-line fake), the model, the agent | `tests/e2e`, `frontend/e2e` | `browser ...` stages |
| 2 **Real dependencies** | filesystem, memory and time MCP servers (npm/PyPI, pinned), the real proxy, hub and operator socket | the agent and the human | `tests/realdeps` | `reality: real MCP servers` |
| 3 **Hostile model** | the backend process over real HTTP with the real OpenAI client, 24 malformed/oversized/odd provider responses | the model is a script (it is adversarial, not intelligent) | `tests/hostile`, `tests/browser/hostile_llm.py` | `reality: hostile model` |
| 4 Real model smoke | a real LLM through OpenRouter, the real MiniLM, an independent recomputation of the drift numbers | one cheap model, nothing asserted about alerts | `frontend/journeys/j10-live-drift.spec.ts` (needs `OPENROUTER_API_KEY`, skipped without) | opt-in `RUN_JOURNEY_TESTS=1` |
| 5 **Load** | real backend, MiniLM + action_sim, event log; 40 concurrent proxy-protocol sessions, 3 racing operators, abrupt disconnects | the agents are protocol clients, not real MCP agents | `tests/load` | `reality: hub under concurrent load` |
| 6 Containers and browsers | the real image, real Chromium | one browser engine, the `EMBEDDINGS=0` image | `tests/docker`, `frontend/journeys` | opt-in `RUN_DOCKER_TESTS=1`, `RUN_JOURNEY_TESTS=1` |

Rungs 2, 3 and 5 are new in this round, each marked with `reality` (`pytest -m reality ...`) so the slow process-based suites do not run inside
the mutation check; every bug they found also has a fast in-process regression test and a mutant (H1 to H6) that the default suite must catch.

## What running real things found (this round)

| Found by | Defect | Impact | Fix |
|---|---|---|---|
| hostile model, `giant_arguments` | the effect-gist file-name regex was quadratic (`eval/effects.py`): 200 KB of `A` took about 4 minutes in a C regex holding the GIL | **one tool call froze the entire hub** (every session, every operator, `/health`) | bounded pattern and scan window; `tests/eval/test_effects_bounded.py`; mutants H1, H2 |
| hostile model, `empty_choices` | `response.choices[0]` on a 200 response with no choices raised IndexError | session died with "Internal server error" and a logged traceback | clean `llm_error` ending; mutant H3 |
| hostile model, `list_content_parts` | assistant content as a list of parts reached the embedder and raised | session died | `_content_text` normaliser; mutant H4 |
| real servers, 2 MB argument | the hub drops the proxy's whole link on a frame over 1 MB | the agent saw "backend connection lost", and **every other pending call of that session was denied** | the proxy denies only that call, locally, with a clear reason; mutants H5, H6 |
| real servers, `search_files` | (my test assumed substring matching; the real server uses globs) | none, a test bug | test fixed; recorded because it shows how a fake downstream hides real semantics |
| load, vanished agent | a call whose proxy dies in the same instant it sends the proposal is **never logged** | no side effect (nothing was approved), but the attempt is missing from the audit trail | NOT fixed, see "Known gaps" |

Measured on this machine (real MiniLM, 100 sessions x 20 calls, 3 operators): about 38 decided calls/s, p50 decision latency about 2.4 s (queueing:
one call at a time through the monitor, so latency is about concurrency / throughput), `/health` worst 24 ms, memory flat (+10 MB), event log
verified with 5,879 events. The hub is single-process by design, so this is its ceiling.

## What each reality stage asserts (so a green stage means something)

* **Hostile model.** For every mode: exactly one terminal event, never a hang; nothing after it; only known event names; no NaN/Infinity to the UI;
  no traceback, path, class name or key fragment in what the client sees; no unhandled exception in the server log (handled, deliberately logged
  conditions such as `LLM call failed` are allowed); the server stays healthy and the NEXT normal session still completes (no poisoned state).
* **Real MCP servers.** Writes land on disk only after a human decision; denied writes never reach the server; the server's own refusals
  (outside the allowed directory, `..`, symlink escape) come back as errors, not hangs; a 0.9 MB argument works through the whole path and a 2 MB one
  is denied alone with the link intact; a stateful server (memory) and a Python stdio server work; killing the server mid-session yields an error
  and the hub survives; the real Node server also runs inside the Landlock sandbox and a symlink out of the write directory is blocked by the kernel.
* **Load.** No session errors; `/health` under 2 s while loaded; throughput above a floor; memory growth under 300 MB; the log verifies; every decision
  a client saw is in the log exactly once with the same verdict even though three operators race to decide each call; every proposed call ends in
  a decision (nothing left pending); calls held when their agent vanished are logged as denied by the system.

## Known gaps (not fixed, not hidden)

1. A proposal whose connection closes in the same instant is not logged (see above). Consider logging `call_proposed` before anything else on receipt.
2. The ceiling is about 38 calls/s and one process. There is no soak test longer than a few minutes; run `python -m tests.load.loadlib --sessions 200 --calls 50 --seconds 3600` for one.
3. Only one real model (gpt-4o-mini) has been run, once; real clients (Claude Desktop, Cursor) never.
4. Detector thresholds were tuned on synthetic, one-model-family traces (D12 to D14). Nothing here tests detection quality on real traffic.
5. No TLS (`wss`), no load balancer, no Fargate, no Firefox/Safari; the default CPU-PyTorch image was never built end to end here.
6. Provider error bodies are written to the server log (a provider that echoes a key fragment would put it there); the client never sees them.
7. The reference servers are well behaved. Slow, huge-reply, hanging and progress-notification servers are still untested.

## How to use this

* Before shipping a feature: add (or extend) a test on every rung that applies, and say in the DECISIONS entry which rungs ran.
* A new component that parses outside data (provider reply, MCP result, webhook, identity file) needs a hostile case in `tests/browser/hostile_llm.py` or its own fuzz.
* When a real run finds a bug, add a FAST in-process regression test and a mutant so the default gate catches it without the slow stage.
* Run the reality stages alone: `python -m pytest -m reality tests/hostile`, `REALDEPS_REQUIRED=1 python -m pytest -m reality tests/realdeps`, `python -m pytest -m reality tests/load`
  (scale the last with `LOAD_SESSIONS`, `LOAD_CALLS`, `LOAD_SECONDS`). `scripts/realdeps_setup.sh` installs the pinned servers into `.realdeps/`.
