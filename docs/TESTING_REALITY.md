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
  no logged result. Kernel confinement (D31, `test_kernel_confine_live.py`): both servers sandboxed with `runtime`; every past path-prediction bypass
  (K0-K5: a link, `..` after a linked dir, a Unicode respelling, a kernel-order decoy, a 4th/5th allowed dir, a decoy in another base) is run as is
  (held, or auto-allowed and denied by the kernel) AND with `SENTINEL_CONFINE_PRECHECK=force_true` (auto-allowed, no card, the server gets it, EACCES);
  `SECRET-<uuid>` is in neither the result nor the event log (results logged); plain reads, lists, trees, `read_multiple_files` and Desktop Commander reads
  are auto-allowed with the right content; a human-approved write still lands through the session process. The narrow write right (D32, `test_write_confine_live.py`): an overwrite of an existing
  `.md`/`.txt` file is auto-allowed with no card, in place (same inode), with a before-image whose sha256 equals the old bytes and a `writes` record in the event log; create, move, mkdir,
  source code, sensitive names (`.github/`, `CLAUDE.md`, a git hook, `.env`), a second name, a symlink, a file outside the write directory and every Desktop Commander write are held
  (default) or refused by the proxy / worker / kernel (`force_true`), and the victims (`.env`, a bashrc-like file, a git hook) are compared byte for byte after every case;
  K1-K5 run again with a write payload. The starter policy on the real (sandboxed)
  filesystem server and on Desktop Commander: a plain read is allowed with no card, `.env` and
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
* **The coverage map, and proof that it ran.** `tests/live/WORKFLOWS.json` lists every user workflow (O1-O6 operator, D1-D4 developer, A1-A4
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
* **`GATE_FAIL_FAST=1`.** Stops at the first failed stage instead of running the rest. Useful while iterating; the `GATE_TIER=pr`
  run (below) stays the verdict before a commit.

Sandbox settings for the Docker stage (docs/DOCKER.md): `SENTINEL_DOCKER_NETWORK_HOST=1 SENTINEL_DOCKER_FORWARD_PROXY=1
SENTINEL_DOCKER_EMBEDDINGS=0 SENTINEL_DOCKER_BUILD_CA=/root/.ccr/ca-bundle.crt`.

## CI tiers (D30): what runs where

The full gate took about 69 minutes serially on 4 cores (mutation check 25 min, backend pytest 16 min, browser stages about 25 min). That is
too long for every commit, and it grows with every test. `GATE_TIER` (read by `scripts/verify.sh`, logic in `scripts/gate_lib.sh`) runs a
subset; the tiers nest, each runs everything the one before it runs. `.github/workflows/ci.yml` picks the tier from the trigger.

| Tier | Trigger | Adds | Measured here (4 cores) |
|---|---|---|---|
| `push` | every push | preflight, mutation targets current, static live-coverage map, **backend pytest, fast** (every test without a `slow`/`research`/`reality`/`claude_live` marker, pytest-xdist), seismograph script, frontend typecheck/lint/unit/build | 66 s wall |
| `pr` | pull request; **the local pre-commit gate** | **backend pytest, slow** (`slow` marker: the process-based files and the action_sim parity), the four reality stages + live coverage proven, browser e2e, action_sim replay parity, browser inbox/policy/operator/boundary/identity, **changed-files mutants** (`mutation_check.py --changed-since $GATE_BASE`) | 777 s (13 min) to the mutation stage; mutants: 182 s for a change to gate files only (22 mutants), 1538 s when tests/ changed (all 149: the review-round run took 2328 s, about 39 min) |
| `full` | nightly | the whole mutation check (replaces the changed-files one); Docker (`RUN_DOCKER_TESTS=1`), journeys (`RUN_JOURNEY_TESTS=1`) and the real Claude Code client (`RUN_CLAUDE_TESTS=1`) when opted in, as before | about 45 min (estimate, not run: pr without its mutants ~12.5 min + mutation check ~25 min + Docker, journeys, Claude ~5 min) |
| `weekly` | weekly | **research** (below): `backend pytest, research`, the five non-default replay-parity stages (learned D7, registry D8, registry_learned D9, registry_learned_e D9b, union D9c), the three registry-UI stages and the two "replay registry is current" checks | about 58 min (estimate, not run: full + research pytest ~1 min + research browser stages ~12 min) |

* **Default is `full`.** A bare `bash scripts/verify.sh` runs what it ran before, minus the research stages (now `weekly`). An unknown tier
  is RED before any stage runs. `GATE_LIST=1 GATE_TIER=pr bash scripts/verify.sh` prints the stages a tier would run with their commands
  and exits 2 (never 0, so a listing cannot pass for a green gate).
* **Run a tier locally:** `GATE_TIER=push bash scripts/verify.sh`, `GATE_TIER=pr bash scripts/verify.sh` (add `GATE_EVENTS=/tmp/ev.log` for
  per-stage times).
* **Changed-files mutants (`pr`).** `GATE_BASE` is the ref to diff against; the default `@origin` means origin's default branch
  (`refs/remotes/origin/HEAD`, else `origin/main`; run `git fetch origin` once). CI sets `origin/<PR base>` on pull requests and
  `origin/<default branch>` otherwise. What counts as changed: commits since the merge base, plus staged, unstaged and untracked files
  (deletions included; a rename counts as a deletion of the old path plus the new one: `git diff --no-renames`). Selection uses the
  **killer map** `scripts/mutant_killers.json` (below), and every rule fails SAFE (more mutants, never fewer): a changed mutant target
  selects its mutants; a changed, deleted or renamed test file selects the mutants it is a witness for; a mutant with no current map
  entry always runs. A changed file that is not a test is matched against the witnesses that READ it (the test files whose text names its path,
  its base name or its directory, `_readers`): **a doc, CI file, script or data file selects only those witnesses' mutants**, so a one-line edit
  to `DECISIONS.md`, `README.md`, `docs/TESTING_REALITY.md`, `ci.yml` or `scripts/verify.sh` selects a handful, not all. A support file under
  `tests/<dir>/` (conftest, helper, fixture, data) selects the witnesses under `tests/<dir>/` plus the tests that import or name it, so
  `tests/proxy/conftest.py` selects only the proxy-witness mutants. **Only a change that can alter EVERY test run selects every pytest mutant**:
  `pytest.ini`, `pyproject.toml`, `setup.cfg`, `tox.ini`, `requirements*.txt`, a root `conftest.py`, and the support files directly under
  `tests/` (`conftest.py`, `no_skip_plugin.py`, `harness.py`, `reality_fixtures.py`, `__init__.py`). Frontend: vite/vitest/eslint/tsconfig/package
  config and every non-test file under `frontend/src` select every vitest mutant. A changed test module also selects the mutants of every test that imports or names it, transitively to depth 4 (`from test_inbox_hub import Rig`:
  editing that helper module selects the 58 mutants its importers witness, not 6). A non-target `.py` source file selects nothing (see the limits
  below). A mutant killed by `"*"` (combination or unknown) is selected by any changed test file and by any support or doc change that reaches a
  reader. A changed top-level gate test (`tests/test_*.py`) also still selects every gate-script mutant (`scripts/*`, `tests/*.py`).
  `--max-selected N` (env `GATE_MUTATION_MAX`, CI pr: 150) turns a selection above N into a loud RED, "too many mutants selected for the PR tier
  (N > limit): run the nightly mutation workflow", instead of a silent timeout; the pr job runs the selection 4 at a time (`GATE_MUTATION_JOBS`).
  No usable map (missing, unreadable, other schema) falls back to the old rule: any change under `tests/` selects every mutant. Nothing
  selected = a quick pass that says so. A missing or unknown base ref is RED, never "nothing changed".
* **The killer map (`scripts/mutant_killers.json`, `mutation_check.py --build-killer-map`).** Per mutant: its definition hash, the WITNESS test
  files, the runner (pytest / vitest), the tier of the failing test and a `kind`. Attribution reuses the check's own machinery: each mutant is
  applied to a throwaway copy, the suite runs serially with `-x`, and the failing file is the witness, which is then re-run ALONE on the mutant
  to prove it kills by itself (`kind: single`). Order matters for what the witness is: the tests that name the mutated module run first
  (`candidate_tests`, one pytest run per directory because `tests/e2e/conftest.py` and `tests/proxy/conftest.py` are both imported as `conftest`),
  then the whole suite, and `tests/docker/test_image_context.py::test_the_fast_backend_tests_pass_in_a_tree_made_only_of_what_the_test_stage_copies`
  (it re-runs a quarter of the suite in a nested tree and sorts first) runs LAST, alone. The witness set is SUFFICIENT, not exhaustive: as long
  as no witness file is touched the mutant is still killed by it, so other tests that also kill it need not be listed. Granularity: one test
  FILE. A mutant whose witness file passes alone, or whose failure names no test file, is a **combination** kill: killer `"*"`, selected by ANY
  changed test file of its runner (the union of everything that could be a killer). A mutant that survives attribution is a hole in the suite:
  the build exits RED and prints it. Frontend mutants are attributed to their vitest file (`frontend/src/**/*.test.ts(x)`); that closes an old
  gap, where editing a vitest file selected nothing, while a pytest edit re-ran the vitest mutants. The build saves the map as results arrive
  (a restart resumes; `--rebuild-all` first empties it) and takes about 4 hours on 4 cores because the check is real now (below).
* **The unmutated tree must be green (`require_clean_backend_tree`).** The throwaway copy used to omit `frontend/`, so
  `tests/contract/test_ui_threshold.py` failed in EVERY tree, mutated or not, and with `-x` about 220 backend mutants read as "killed" by a
  test that failed for the wrong reason: the mutation stage proved nothing for them. Now the copy keeps `frontend/` (without `node_modules` and
  `dist`), and before any backend mutant runs (the full check, `--changed-since` with a selection, `--build-killer-map`, attribution) the whole
  suite runs once on the UNMUTATED copy (`-n 4`, about 7 min); red = the run REFUSES with the failing tests named. Tests that read the committed
  map skip inside a mutation run (`MUTATION_CHECK_RUN=1`) so a stale map can never make a survivor look killed.
  `--jobs N` (env `GATE_MUTATION_JOBS`) runs N mutants at a time, each serial in its own copy; `--log FILE` (env `GATE_MUTATION_LOG`) appends each
  verdict and a rerun skips what is recorded.
* **Keeping the map current.** `python scripts/mutation_check.py --check-killer-map` is a push-tier stage (and `tests/test_mutation_check.py`
  runs the same check): it is RED when a mutant has no entry, its definition hash differs, an entry names a mutant that is gone, a killer file
  no longer exists, or the map's `mutants_hash` does not match. The fix is `python scripts/mutation_check.py --build-killer-map`, which
  re-attributes ONLY the missing/stale entries (`--rebuild-all` redoes all). Adding a mutant therefore means committing its map entry too.
* **The full check in CI (`full` and `weekly`) is its own job.** It is hours of serial pytest runs, so `.github/workflows/ci.yml` runs it as the
  job `mutation`: 4 shards (`--shard i/4`: sha256 of the mutant name mod 4, every mutant in exactly one shard), each 3 mutants at a time, timeout 350
  min, with every verdict appended to a cached log (`--log`, `actions/cache`) so a rerun of the same workflow run resumes. The `gate` job in those tiers
  runs with `GATE_MUTATION_FULL=external`: its mutation stage only re-proves the targets and names the job. Locally `GATE_TIER=full bash
  scripts/verify.sh` still runs the whole check unsharded (`GATE_MUTATION_JOBS=N` for N at a time; `GATE_MUTATION_SHARD=i/N` for one shard).
  Estimate, not measured on GitHub: the whole check is about 4 h of 4-core work, so roughly 2-3 h per shard. The workflow has been parsed and its
  wiring tested, not run.
* **What counts as a kill.** pytest exit 5 ("no tests collected": a group made only of tests deselected by the default `-m`, e.g. `tests/live`)
  is NOT a kill and the next group runs; a mutant reads KILLED only with a named failing test or a timeout (a hung mutant is killed), and a non-zero
  exit that names no test is RED ("inconclusive"), never a silent kill.
* **Selection versus the old rule.** For SOURCE-file changes (no test file touched) the selection is a superset of the old one (a target change
  selects its mutants as before; shared-support files only add). For TEST-only changes it is a strict subset (the old rule selected everything);
  that is the point, and the safety is the witness argument above.
* **Safety net.** `full` (nightly) and `weekly` run the whole mutation check without the map, so a weakened test that the map's shortcut
  missed is found the next night. Known limits of the shortcut: like the old rule it only looks at the changed files, so a change to a
  NON-target source file that stops a witness test from killing a mutant is not seen until the nightly run; and a data file outside `tests/`
  that a test reads is not "shared support" (only `contracts.ts` is listed).
* **Non-root pass (opt-in, in no tier): `GATE_AS_USER=1`.** CI's runner is unprivileged; a dev box or a container is usually root, and root hides bugs
  (a test once depended on network-namespace support only root has, and passed locally). `GATE_AS_USER=1 bash scripts/verify.sh` adds ONE stage,
  `non-root pass`, to whatever tier you run (`GATE_LIST=1` shows it; without the variable no tier lists it, so CI time does not grow);
  `sudo bash scripts/run_nonroot.sh [pytest args]` runs just that stage. It runs `python -m pytest tests/proxy tests/server tests/live -m 'not research' -n 4`
  as the user `sentinel-nonroot` (`NONROOT_USER`; an existing account is reused only if this script made it: GECOS marker, uid >= 1000), in a private copy of
  the repository under `NONROOT_DIR` (default `/var/tmp/sentinel-nonroot-<user>/repo`; the directory must be absent, empty or carry the marker file the script
  wrote, never a symlink or a system directory, and it is the ONLY place the root-run script writes) and with an EMPTY environment (PATH, HOME, TMPDIR, LANG,
  `HF_*`, `OMP_NUM_THREADS=1`, and `SENTINEL_SANDBOX_REQUIRED=1` only when you set it to 1: a missing sandbox is then a failure, not a skip; your tokens never
  reach it). The copy leaves out `.git`, `frontend/node_modules`, caches and credential-looking files (`.env`, `*.pem`, `*.key`, `id_*`, `.netrc`,
  `credentials*`); the absolute path inside `.realdeps/tv` is rewritten; the user gets its own copy of the MiniLM cache once (`NONROOT_HF=0` skips it).
  Needs root once for `useradd`/`runuser`; `NONROOT_WORKERS` sets `-n`; `NONROOT_DRY_RUN=1` prints the plan and changes nothing; already non-root, it just runs
  pytest in the checkout. **Cleanup: `sudo NONROOT_CLEAN=1 bash scripts/run_nonroot.sh`** removes the script-made user (`userdel -r`, its home and model copy
  included) and the work directory, each only if it carries the script's marker. Pinned by tests/test_gate_tiers.py (listed only with `GATE_AS_USER=1`, never in
  a default tier) and tests/test_run_nonroot.py.
* **Pre-commit gate: `GATE_TIER=pr` locally.** `full` and `weekly` run in CI (nightly and weekly), not before every commit. That is a real
  trade: a change that breaks only a research detector, a mutant of a file the change did not touch, Docker or a journey is found the next
  night or week, not before the commit.
* **Every push runs `push`** (about a minute), including pushes to a branch with an open PR, which also runs `pr`. Left as is on purpose:
  it is cheap, and it is the only CI signal for a branch without a PR.
* **One place for pytest selection.** Markers `slow` and `research` (`pytestmark` in each file, or per test / per parameter; no new
  conftest; `--strict-markers` makes a misspelt marker an error) and three `-m` expressions `GATE_PYTEST_PUSH|PR|WEEKLY` in
  `scripts/gate_lib.sh`. `tests/test_gate_tiers.py` collects every test (`-m ""`) and proves each is selected by some stage of some tier
  (the backend stages by marker, reality and claude stages by marker and directory) and that no test runs in two backend stages; it also
  pins each tier's stage list. A new test file is `push` by default; mark it `slow` if it starts real processes for many seconds.
* **What is `research`** (tests of ONLY the opt-in detectors D7-D9c, their registry and their tooling): tests/e2e/test_registry_parity.py,
  test_registry_parity_union.py, test_registry_parity_v3.py, test_ws_registry_decisions.py; the `learned` parameters of
  tests/e2e/test_monitor_parity.py; tests/server/test_registry.py, test_proposal_monitor_registry.py, test_proposal_monitor_registry_v3.py;
  tests/eval/test_eval_registry_detectors.py, test_eval_registry_run.py, test_eval_registry_v3_detectors.py, test_eval_registry_v3_fit.py,
  test_eval_registry_v3_guards.py, test_make_replay_registry.py; and in tests/eval/test_dump_expectations.py the D7, D8/D9, registry-CLI
  and D9b/D9c tests. Left in `push` because they also cover the default path or shared code: tests/eval/test_eval_v2_*.py (D3 is a v2
  detector), test_eval_detectors.py, test_eval_d5_control.py, test_eval_run_v3.py, test_check_v3_integrity.py, test_trace_schema_v3.py,
  tests/server/test_alert_message_safety.py (mixed parameters), and `test_frozen_option_supports_d6_and_d7` (D4-D7).
* **Live coverage.** The reality stages and `live coverage proven` start at `pr` and always run together (`--junit` only where the
  reality stages ran; tested). Every live spec still runs in `pr` (replay-traces is the action_sim stage).
* **Parallel backend tests.** `pytest-xdist` (`requirements-dev.txt`), `GATE_PYTEST_WORKERS` (local default 4, CI `auto`),
  `OMP_NUM_THREADS=1` per worker (4 workers x 4 torch threads made MiniLM setup take 61 s instead of 5 s; the fast set went from 281 s to
  48 s). Proven by two clean runs of each set at `-n 4`. Fixed for it: random parametrize ids (test_identity.py generated RSA keys at import:
  xdist workers must collect the same ids) and five sandbox leak checks (tests/proxy/test_boundary.py x4, tests/e2e/test_boundary_end_to_end.py)
  that diffed the GLOBAL `/tmp/sentinel-sbx-*` set, which another worker's sandbox polluted. Each test now gives its proxy and its server's
  trampoline a private `TMPDIR`, asserts that the sandbox HOME it saw (the probe server reports `HOME`) was created under that root, and
  then that none is left there. Tried: with sandbox-HOME removal disabled, and with a trampoline that ignores `TMPDIR` (mutant T19), all
  five fail. The mutation check stays serial: under xdist `-x` does not stop early.
* **Sandbox tests never skip silently in CI.** `SENTINEL_SANDBOX_REQUIRED=1` (set by the workflow) turns the Landlock / network-namespace
  skips (`needs_sandbox`, `needs_landlock`, `needs_landlock_net`, `needs_netns`, via `sandbox_skipif` in tests/no_skip_plugin.py) into
  runs that FAIL where the sandbox is missing. Root-only tests (`needs_root`) still skip on a non-root runner.
* **Mutation speed.** EVERY mutant whose target is under `scripts/` or `tests/` first meets the top-level `tests/test_*.py` (the gate's own
  tests, seconds), because those mutants' killers sit at the end of the collection order; a mutant that survives that quick pass still has
  to survive the whole suite to count as a survivor. Other mutants run the whole suite directly, as before.
* **CI** (`.github/workflows/ci.yml`, not run here: validated with actionlint 1.7.7 and a YAML load; tracked although `.gitignore` ignores
  dotfiles, via `!.github/`, tested): one job, tier from the trigger, concurrency group per trigger and ref (a newer run cancels the
  superseded one), timeouts 25 / 120 (pr) / 150 (nightly gate job) / 350 (each mutation shard) min (the pr tier outgrew 50 when a PR that edited a test ran every mutant; the killer map now selects only the mutants that test witnesses), pip / npm / MiniLM / Playwright / `.realdeps` caches (the `.realdeps` key includes the exact
  Python version and `scripts/realdeps_setup.sh`; the script pins `mcp-server-time` and rebuilds its venv when the interpreter does not run
  or the version is not the pin; that server's own dependencies are not pinned), `HF_HUB_OFFLINE=1` after the one model fetch, CPU torch,
  Chromium via `npx playwright install` with `CHROMIUM_PATH` from Playwright, the events file and junit (`GATE_JUNIT_DIR`: backend stages
  write there; the reality junit is copied there after the proof, which always reads a fresh temp dir) uploaded as an artifact. Nightly and
  weekly set `RUN_DOCKER_TESTS=1` and `RUN_JOURNEY_TESTS=1` on the runner's own Docker (no proxy variables). Weekly sets
  `RUN_CLAUDE_TESTS=1` only when the `ANTHROPIC_API_KEY` secret exists and passes it as `SENTINEL_CLAUDE_API_KEY`: verify.sh moves it out
  of the environment before the first stage and hands it, as `ANTHROPIC_API_KEY`, to the Claude stage alone (never in argv; tested).
  On failure CI also uploads `frontend/e2e/.results` (one directory per stage: `run()` sets `GATE_STAGE`, `playwright.config.ts` derives
  the outputDir from it), and the e2e specs forward the agents' and proxies' stderr to the test output.
  Unverified until it runs on GitHub: the Landlock + network-namespace tests on `ubuntu-24.04` (the workflow lifts the AppArmor
  restriction on unprivileged user namespaces; a failure there now fails the job), the Docker stage's build time without cached layers,
  and the Claude stage's sign-in by key.
