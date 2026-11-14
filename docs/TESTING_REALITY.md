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
| 7 **Live workflows** | a third-party server (Desktop Commander 0.3.1, pinned) and the reference filesystem server behind the real proxy and hub, the starter policy, the MiniLM monitor, the keyed event log and the real `eventlog_cli` | the agent and the human are scripts | `tests/live` | `reality: live workflows` |
| 8 **Real client** | a real Claude Code (`claude -p`, real model) as the MCP client, behind the proxy, against the filesystem server and Desktop Commander + starter | the human is a script on the real `/inbox/ws` | `tests/claude` (marker `claude_live`) | opt-in `RUN_CLAUDE_TESTS=1` (a missing or signed-out `claude` FAILS) |

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
| load, vanished agent | a call whose proxy dies in the same instant it sends the proposal was **never logged** (`_run_call_inner` returned on `session.closed` after the monitor ran, before `call_proposed`) | no side effect (nothing was approved), but the attempt was missing from the audit trail | fixed: the closed check now comes after the write-ahead `call_proposed`; `test_call_sent_then_immediate_disconnect_is_still_logged_as_proposed`, mutant H7. That fix was only half: a live test (real uvicorn and websockets, hello + call + close with no delay) still lost the call, because `proxy_hello` abandoned the connection when the `hello_ack` send failed, so the already-queued `proxy_call` was never read; now it keeps reading, the disconnect cleanup denies and logs it; `test_failed_hello_ack_*`, mutant H10, and the load driver's even-index aborters now send hello + call + close without awaiting the ack |

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

* **Live workflows** (`tests/live`, D28). Desktop Commander direct vs through the proxy: every tool's schema and annotations and every call result
  identical, the documented differences pinned (one tools-only server: no resources, prompts, logging or instructions), every proxied call held and
  logged as a human decision; a `start_process` does not run while held (marker file absent), runs once approved, a denied one never runs and has
  no logged result. The starter policy on the real filesystem server and on Desktop Commander: a plain read is allowed with no card, `.env` and
  `read_file {isUrl: true}` reach a human, the denied secret is not returned and a local HTTP target gets 0 requests; `replay` agrees. Deny with a
  note: the note reaches the agent and the log; the retry of the same content is still a `denied_effect_match` alert, labelled "You suggested this
  in your denial note (summary.md)." and downgraded to warning on the card and in the log, critical and unlabelled without a note. The auditor's CLI
  on a log written by a real session: verify / show / export agree with what the human did, `policy-test` compares a candidate policy with those
  decisions, `replay` re-flags the copy, rotate without the key is refused and moves nothing, rotate + `verify --previous` link, the hub keeps
  appending to the rotated log, a tampered archive copy and a missing archive are detected. Desktop Commander always runs with a private HOME,
  `DESKTOP_COMMANDER_DISABLE_TELEMETRY=1` and its feature-flag URL pointed at a closed local port (`tests/live/livelib.py`), installed with
  `npm ci --ignore-scripts` from the committed lockfile (its postinstall phones home): the tests make no outbound request.
* **Real client** (`tests/claude`, opt-in). Filesystem server: the human denies `report.txt` with a note; `report.txt` never exists, every file
  that landed is named by an approved call in the log, denied calls have no result, the log verifies, at least one card was seen. Desktop
  Commander + starter: the `.env` secret is nowhere in Claude's stream-json transcript, the project directory survives the requested `rm -rf`,
  and the one command a human approved (`cat token.txt`, a random token) delivered its real output to Claude. Claude Code must report the
  `sentinel` MCP server `connected` and use only `mcp__sentinel__*` tools. Model wording and call order are never asserted, and neither is
  whether the model adapts to the denial note (it is printed: observed, not asserted). Measured: $0.04-0.12 per scenario, about 10-15 s each.

## Live tests actually happen (D28)

* **No skips or xfails in reality stages.** Every reality stage (and the Claude stage) runs with `SENTINEL_NO_SKIP=1` and
  `-p tests.no_skip_plugin` (`tests/no_skip_plugin.py`, a plugin module, not a conftest): a skipped test (in a fixture, a marker or at module
  level), an xfail (marker or imperative `pytest.xfail`) and an unexpected xpass are FAILURES that name the test and the reason. Nothing
  collected is exit code 5, which `run()` already counts as a failure. Stages that install servers also set `REALDEPS_REQUIRED=1`.
* **The coverage map, and proof that it ran.** `tests/live/WORKFLOWS.json` lists every user workflow (O1-O6 operator, D1-D4 developer, A1-A3
  admin, L1-L3 auditor, P1 platform) and the live tests that cover it: pytest node ids or playwright specs; opt-in coverage (docker, journeys,
  claude) is listed as `optional`. `scripts/check_live_coverage.py` (unit-tested in `tests/test_check_live_coverage.py`) runs twice:
  - static, early in the gate (a second): every workflow is present and has a `live` entry or an explicit `"gap"`, every referenced file exists,
    and every live spec is run by a mandatory `npx playwright test` stage (a spec gated on its `*_STAGE` variable needs a stage that filters for it);
  - runtime, right after the reality stages, which each write `--junitxml` into a gate temp dir (`--junit DIR`): every live pytest node id in the
    map PASSED in this gate run. Skipped, xfail, failed or absent (renamed, deselected, a stage that crashed) is red.
  A node id that appears in more than one junit file keeps its worst outcome (one skip anywhere is not proof).
  Limits, stated plainly: (1) the junit proof cannot see a test whose body returns early or whose assertions cannot fail: it passed, so it
  counts; review and the mutants catch that, not this check. (2) Playwright specs get ONLY the static check (the file exists and a mandatory
  stage runs it); no report is read, so a spec that skips its tests in that stage is not caught here. O5 (standing rule) and A3 (identity) rely
  on specs alone. Not done on purpose: the same spec runs skipped in the bare `npx playwright test` stage and for real in its own `*_STAGE`
  stage, so reading playwright junit needs per-stage bookkeeping that is not worth it yet. Declared gap today: P1 (real containers run only
  with `RUN_DOCKER_TESTS=1`). D4 is live only against a scripted provider; a real provider is the opt-in journey j10. O3's real-agent
  adaptation is observed in the optional Claude test, not asserted.
* **Definition of done: a feature is not done until a committed live scenario for its workflow runs in the gate.** A scratch script that proved
  it once does not count: it cannot catch the next regression. Add the scenario to `tests/live` (or a browser stage), list it in the map, and the
  gate holds it from then on.

## Known gaps (not fixed, not hidden)

1. The ceiling is about 38 calls/s and one process. There is no soak test longer than a few minutes; run `python -m tests.load.loadlib --sessions 200 --calls 50 --seconds 3600` for one.
2. Only one real provider model (gpt-4o-mini) has been run through the built-in loop, once. One real MCP client (Claude Code, `RUN_CLAUDE_TESTS=1`)
   runs on demand; Claude Desktop and Cursor never.
3. Detector thresholds were tuned on synthetic, one-model-family traces (D12 to D14). Nothing here tests detection quality on real traffic.
4. No TLS (`wss`), no load balancer, no Fargate, no Firefox/Safari; the default CPU-PyTorch image was never built end to end here.
5. Provider error bodies are written to the server log (a provider that echoes a key fragment would put it there); the client never sees them.
6. The reference servers are well behaved. Slow, huge-reply, hanging and progress-notification servers are still untested.

## How to use this

* Before shipping a feature: add (or extend) a test on every rung that applies, and say in the DECISIONS entry which rungs ran.
* A new component that parses outside data (provider reply, MCP result, webhook, identity file) needs a hostile case in `tests/browser/hostile_llm.py` or its own fuzz.
* When a real run finds a bug, add a FAST in-process regression test and a mutant so the default gate catches it without the slow stage.
* Run the reality stages alone (add `SENTINEL_NO_SKIP=1 ... -p tests.no_skip_plugin` to get the gate's no-skip rule): `python -m pytest -m reality tests/hostile`,
  `REALDEPS_REQUIRED=1 python -m pytest -m reality tests/realdeps`, `python -m pytest -m reality tests/load` (scale with `LOAD_SESSIONS`, `LOAD_CALLS`,
  `LOAD_SECONDS`), `REALDEPS_REQUIRED=1 python -m pytest -m reality tests/live`, and the real client `python -m pytest -m claude_live tests/claude`
  (`CLAUDE_TEST_MODEL`, `CLAUDE_TEST_BUDGET_USD`). `scripts/realdeps_setup.sh` installs the pinned servers into `.realdeps/` (`npm ci --ignore-scripts`, re-run only when
  the lockfile changes). `python scripts/check_live_coverage.py` checks the map statically; add `--junit DIR` after running the stages with `--junitxml=DIR/x.xml`.

## Hearing about failures immediately (not hours later)

A full gate with every opt-in stage takes hours, and the Docker stage runs near the end. One real run went RED after about two hours
because the image build could not verify this sandbox's TLS-intercepting proxy: a misconfiguration detectable in seconds. A preflight
and three switches close that gap (`scripts/gate_lib.sh`, tested by `tests/test_gate_lib.py`, mutants G1 to G7):

* **Preflight (always on, the first stage).** For every OPTED-IN stage it checks, in seconds, that the stage can work at all.
  For `RUN_DOCKER_TESTS=1`:
  * the Docker daemon answers within 20 s;
  * behind an HTTPS proxy (`HTTPS_PROXY` or `https_proxy`, the same variable `scripts/docker_test.sh` forwards), the build has
    `SENTINEL_DOCKER_FORWARD_PROXY=1` and `SENTINEL_DOCKER_BUILD_CA` pointing at a readable file;
  * a proxy on loopback (`127.x`, `localhost`, `[::1]`) also needs `SENTINEL_DOCKER_NETWORK_HOST=1`.

  `SENTINEL_DOCKER_PREFLIGHT_PROXY=0` skips the proxy checks for a proxy that does not intercept TLS. For `RUN_CLAUDE_TESTS=1`
  the preflight checks that the `claude` CLI starts; it does not check that it is signed in, so the stage itself still catches that.
  A missing `frontend/node_modules` or Chromium is a failed stage too, so it is reported the same way.
* **`GATE_EVENTS=<file>`.** Lines are appended as they happen: `HH:MM:SS START <stage>`, then `HH:MM:SS PASS|FAIL <stage> (<secs>s)`.
  On every way out (normal end, fail-fast, an abort, Ctrl-C, SIGTERM) the gate appends `HH:MM:SS DONE GREEN|RED`, taken from the
  exit status. A relative path is resolved from the repository root. Watch the file with `tail -F`, a CI log tailer, or a Claude Code
  `Monitor` (`tail -F "$GATE_EVENTS" | grep --line-buffered -E " FAIL | DONE "`), which notifies the session the moment a stage fails.
  If `scripts/gate_lib.sh` itself cannot be loaded, the gate prints RED and exits 1 before any stage runs, so no events are written.
* **`GATE_ON_FAIL=<command>`.** Runs once per failed stage with `GATE_STAGE` set, for example
  `GATE_ON_FAIL='curl -fsS -m 10 -d "gate stage failed: $GATE_STAGE" "$WEBHOOK_URL"'`. Its exit code is ignored, so a broken hook
  never changes the verdict. A hook without a timeout can stall the gate; give it one, like `-m 10` above.
* **`GATE_FAIL_FAST=1`.** Stops at the first failed stage instead of running the rest. Useful while iterating; the full run stays
  the verdict before a commit.

Sandbox settings for the Docker stage (docs/DOCKER.md): `SENTINEL_DOCKER_NETWORK_HOST=1 SENTINEL_DOCKER_FORWARD_PROXY=1
SENTINEL_DOCKER_EMBEDDINGS=0 SENTINEL_DOCKER_BUILD_CA=/root/.ccr/ca-bundle.crt`.
