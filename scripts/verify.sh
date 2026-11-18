#!/usr/bin/env bash
# Verification gate. Exit code is the only verdict: 0 = every check passed.
# Nothing here is judged by the author of the change; it only runs commands.
set -u
cd "$(dirname "$0")/.."
fail=0
# run(), gate_preflight and the failure notifications (GATE_EVENTS file, GATE_ON_FAIL hook, GATE_FAIL_FAST=1): scripts/gate_lib.sh
source scripts/gate_lib.sh || { echo "GATE: RED (scripts/gate_lib.sh could not be loaded: no stage ran)"; exit 1; }
gate_install_done_trap
# GATE_TIER=push|pr|full|weekly (default full) picks the stages; the tiers nest (docs/TESTING_REALITY.md "CI tiers", DECISIONS.md D30).
# GATE_LIST=1 prints the stages a tier would run and runs nothing.
# GATE_JUNIT_DIR=<dir, no spaces> (CI artifacts): the backend pytest stages write junit there, and the reality stages' junit is copied there after
# the live-coverage proof (the proof itself always reads a fresh temp dir, so a stale file can never stand in for a test that did not run).
gate_check_tier || exit 1
gate_take_claude_key   # SENTINEL_CLAUDE_API_KEY: only the claude stage sees it (as ANTHROPIC_API_KEY)
# xd = pytest-xdist across GATE_PYTEST_WORKERS (default 4) processes; one torch thread each (4 workers x N torch threads oversubscribe the CPU).
XD="env OMP_NUM_THREADS=${OMP_NUM_THREADS:-1} python -m pytest -n ${GATE_PYTEST_WORKERS:-4}"
run "preflight: opted-in stages can work at all (Docker daemon + proxy CA, claude CLI), in seconds instead of hours later" gate_preflight
run "mutation targets are current (fast: stale mutants fail here, not at the end)" python scripts/mutation_check.py --check-targets
run "live coverage map, static (every user workflow has a live test or a declared gap; referenced files exist; live specs are run)" python scripts/check_live_coverage.py
# Backend pytest, split by marker (GATE_PYTEST_* in scripts/gate_lib.sh): every collected test is in exactly one of these three stages.
run "backend pytest, fast (unmarked tests, parallel)" $XD -m "$GATE_PYTEST_PUSH" ${GATE_JUNIT_DIR:+--junitxml=$GATE_JUNIT_DIR/backend-fast.xml}
# GATE_AS_USER=1 (opt-in, any tier, never a default): the sandbox / proxy / live selection again as an unprivileged user (scripts/run_nonroot.sh;
# root hides bugs GitHub's unprivileged runner shows). Needs root to create the user; CI already runs non-root, so it does not use this.
[ "${GATE_AS_USER:-0}" = 1 ] && run "non-root pass (tests/proxy tests/server tests/live as an unprivileged user; opt-in GATE_AS_USER=1)" bash scripts/run_nonroot.sh
if at_tier pr; then
  run "backend pytest, slow (process-based files, parallel)" $XD -m "$GATE_PYTEST_PR" ${GATE_JUNIT_DIR:+--junitxml=$GATE_JUNIT_DIR/backend-slow.xml}
fi
if at_tier weekly; then
  run "backend pytest, research (opt-in detectors D7-D9c, parallel)" $XD -m "$GATE_PYTEST_WEEKLY" ${GATE_JUNIT_DIR:+--junitxml=$GATE_JUNIT_DIR/backend-research.xml}
fi
# reality stages (DECISIONS.md D25, D28, docs/TESTING_REALITY.md): real processes instead of in-process fakes.
# NS = SENTINEL_NO_SKIP=1 + tests/no_skip_plugin.py: a skipped or xfail test in these stages is a FAILURE (a missing server must never turn a
# live stage green). Each stage writes junit XML into $JU; the stage after them proves every live test in tests/live/WORKFLOWS.json PASSED in THIS run.
NS="SENTINEL_NO_SKIP=1 python -m pytest -p tests.no_skip_plugin"
JU="$(mktemp -d)"
if at_tier pr; then
  run "reality: hostile model (every malformed/oversized/odd response, real backend over HTTP)" env $NS -m reality tests/hostile --junitxml="$JU/hostile.xml"
  run "reality: real MCP servers (filesystem, memory, time) behind the real proxy and hub" env REALDEPS_REQUIRED=1 $NS -m reality tests/realdeps --junitxml="$JU/realdeps.xml"
  run "reality: hub under concurrent load (races, disconnects, event-log invariants, responsiveness)" env $NS -m reality tests/load --junitxml="$JU/load.xml"
  run "reality: live workflows (third-party Desktop Commander differential, starter policy on real servers, note-aware alert, event-log CLI audit)" env REALDEPS_REQUIRED=1 $NS -m reality tests/live --junitxml="$JU/live.xml"
  run "live coverage proven (every live pytest test in the workflow map PASSED in this gate run: not skipped, xfail or missing)" python scripts/check_live_coverage.py --junit "$JU"
  [ -n "${GATE_JUNIT_DIR:-}" ] && cp "$JU"/*.xml "$GATE_JUNIT_DIR"/ 2>/dev/null || true
fi
run "seismograph legacy pipeline script" python -m seismograph.test_pipeline --stub-only
if [ -d frontend/node_modules ]; then
  run "frontend typecheck" bash -c 'cd frontend && npx tsc -b'
  run "frontend lint"      bash -c 'cd frontend && npm run lint --silent'
  if grep -q '"test"' frontend/package.json; then
    run "frontend unit tests" bash -c 'cd frontend && npm test --silent'
  fi
  run "frontend build"     bash -c 'cd frontend && npm run build --silent'
  # Real browser + real WebSocket + real backend + scripted HTTP LLM. Skipped (loudly) only if no Chromium.
  if ! at_tier pr; then
    :   # browser stages start at GATE_TIER=pr
  elif [ -x "${CHROMIUM_PATH:-/opt/pw-browsers/chromium}" ]; then
    run "browser e2e (playwright, live stack, rules monitor)" bash -c 'cd frontend && npx playwright test'
    # The shipped default monitor (and, weekly, the learned one), replaying 12 recorded traces (v1+v2) with the real MiniLM:
    # live alerts must equal the offline frozen detector's and arrive before the human decision.
    R="$PWD"
    IDS="gen_a-001,gen_b-011,gen_c-001,gen_d-009,gen_e-001,gen_f-001,v2a-003,v2b-001,v2c-005,v2d-004,v2e-002,v2e-010"
    TR="$R/eval/final/traces.json:$R/eval/final_v2/traces.json"
    run "browser replay parity: action_sim (D3, default monitor)" bash -c "cd frontend && REPLAY_IDS=$IDS FAKE_LLM_TRACES=$TR SENTINEL_MONITOR=action_sim REPLAY_DETECTOR=D3 REPLAY_FROZEN=$R/eval/results_v2/frozen_models.json npx playwright test replay-traces"
    TMPD="$(mktemp -d)"   # NOT frontend/e2e/.results: playwright wipes its outputDir at the start of every run
    # Research detectors (D7-D9c: learned, registry*) are opt-in, not the shipped default: GATE_TIER=weekly (DECISIONS.md D30).
    if at_tier weekly; then
      run "browser replay parity: learned (D7 post-hoc)" bash -c "cd frontend && REPLAY_IDS=$IDS FAKE_LLM_TRACES=$TR SENTINEL_MONITOR=learned SENTINEL_MONITOR_MODEL=$R/eval/results_v2_posthoc/frozen_models.json REPLAY_DETECTOR=D7 REPLAY_FROZEN=$R/eval/results_v2_posthoc/frozen_models.json npx playwright test replay-traces"
      # Opt-in destination-registry monitors (DECISIONS.md D9) with ONE merged registry for these 12 ids (generated by
      # scripts/make_replay_registry.py, which fails on merge conflicts): live alerts must equal the offline frozen D8 / D9
      # run with the same registry, and arrive before the human decision.
      REG="$R/tests/browser/replay_registry.json"
      RFZ="$R/eval/results_registry/frozen_registry_models.json"
      run "replay registry is current and conflict-free" bash -c "python scripts/make_replay_registry.py --ids $IDS --out $TMPD/replay_registry.json && cmp $TMPD/replay_registry.json $REG"
      run "browser replay parity: registry (D8, merged registry)" bash -c "cd frontend && REPLAY_IDS=$IDS FAKE_LLM_TRACES=$TR SENTINEL_MONITOR=registry REPLAY_REGISTRY=$REG SENTINEL_REGISTRY_MODEL=$RFZ REPLAY_DETECTOR=D8 REPLAY_FROZEN=$RFZ npx playwright test replay-traces"
      run "browser replay parity: registry_learned (D9, merged registry)" bash -c "cd frontend && REPLAY_IDS=$IDS FAKE_LLM_TRACES=$TR SENTINEL_MONITOR=registry_learned REPLAY_REGISTRY=$REG SENTINEL_REGISTRY_MODEL=$RFZ REPLAY_DETECTOR=D9 REPLAY_FROZEN=$RFZ npx playwright test replay-traces"
      # The registry in the real UI: banner on screen before the human clicks (relay_alias v2a-001, D9), and the loud fallback
      # to action_sim on a second backend that has no SENTINEL_REGISTRY.
      UIREG="$TMPD/ui_registry.json"
      run "browser registry UI (relay banner before the click; fallback without a registry)" bash -c "python scripts/make_replay_registry.py --ids v2a-001 --out $UIREG && cd frontend && FALLBACK_API_PORT=8082 UI_TRACE_ID=v2a-001 FAKE_LLM_TRACES=$TR SENTINEL_MONITOR=registry_learned REPLAY_REGISTRY=$UIREG SENTINEL_REGISTRY_MODEL=$RFZ REPLAY_DETECTOR=D9 REPLAY_FROZEN=$RFZ REPLAY_IDS=v2a-001 npx playwright test registry-ui"
      # v3 (DECISIONS.md D10, PROVISIONAL): the opt-in frozen D9b (SENTINEL_MONITOR=registry_learned_e) replaying 12 v3 ids
      # (relay_known / mixed_v3_adv / benign_ext_v3 / mixed_v3_benign) with ONE merged registry of their AUTHORED1 registries
      # (scripts/make_replay_registry.py --v3, fails on merge conflicts): live alerts == offline frozen D9b with the same registry,
      # before the human decision. Then the v3 monitor in the real UI and its loud fallback to action_sim without a registry.
      IDS3="v3a-001,v3a-007,v3a-009,v3a-013,v3e-001,v3e-002,v3e-008,v3d-001,v3d-007,v3d-008,v3e-011,v3e-014"
      TR3="$R/eval/final_v3/traces.json"
      REG3="$R/tests/browser/replay_registry_v3.json"
      RFZ3="$R/eval/results_registry_v3/frozen_registry_models_v3.json"
      run "v3 replay registry is current and conflict-free" bash -c "python scripts/make_replay_registry.py --v3 --ids $IDS3 --out $TMPD/replay_registry_v3.json && cmp $TMPD/replay_registry_v3.json $REG3"
      run "browser replay parity: registry_learned_e (D9b frozen v3, merged authored1 registry)" bash -c "cd frontend && REPLAY_IDS=$IDS3 FAKE_LLM_TRACES=$TR3 SENTINEL_MONITOR=registry_learned_e REPLAY_REGISTRY=$REG3 SENTINEL_REGISTRY_MODEL_V3=$RFZ3 REPLAY_DETECTOR=D9b REPLAY_FROZEN_V3=$RFZ3 npx playwright test replay-traces"
      UIREG3="$TMPD/ui_registry_v3.json"
      run "browser registry UI v3 (D9b relay banner before the click; fallback without a registry)" bash -c "python scripts/make_replay_registry.py --v3 --ids v3a-001 --out $UIREG3 && cd frontend && FALLBACK_API_PORT=8082 UI_TRACE_ID=v3a-001 FAKE_LLM_TRACES=$TR3 SENTINEL_MONITOR=registry_learned_e REPLAY_REGISTRY=$UIREG3 SENTINEL_REGISTRY_MODEL_V3=$RFZ3 REPLAY_DETECTOR=D9b REPLAY_FROZEN_V3=$RFZ3 REPLAY_IDS=v3a-001 npx playwright test registry-ui-v3"
      # union (DECISIONS.md D13-D14): SENTINEL_MONITOR=registry_learned_dropout_or_action = frozen D9c OR D3 on the same 12 v3 ids and the same
      # merged registry: live alerts == offline union (REPLAY_DETECTOR=U9c), then the union in the real UI (banner before the click, hostile
      # tool name, loud fallback without a registry).
      run "browser replay parity: union (D9c OR D3, merged authored1 registry)" bash -c "cd frontend && REPLAY_IDS=$IDS3 FAKE_LLM_TRACES=$TR3 SENTINEL_MONITOR=registry_learned_dropout_or_action REPLAY_REGISTRY=$REG3 SENTINEL_REGISTRY_MODEL_V3=$RFZ3 REPLAY_DETECTOR=U9c REPLAY_FROZEN_V3=$RFZ3 npx playwright test replay-traces"
      run "browser registry UI union (banner before the click; fallback without a registry)" bash -c "python scripts/make_replay_registry.py --v3 --ids v3a-001 --out $UIREG3 && cd frontend && FALLBACK_API_PORT=8082 UI_TRACE_ID=v3a-001 FAKE_LLM_TRACES=$TR3 SENTINEL_MONITOR=registry_learned_dropout_or_action REPLAY_REGISTRY=$UIREG3 SENTINEL_REGISTRY_MODEL_V3=$RFZ3 REPLAY_DETECTOR=U9c REPLAY_FROZEN_V3=$RFZ3 REPLAY_IDS=v3a-001 npx playwright test registry-ui-union"
    fi
    # MCP proxy + approval inbox (DECISIONS.md D16): real browser <-> real backend hub <-> REAL stdio proxy subprocess <-> real downstream MCP
    # server; the backend runs action_sim with real MiniLM so a repeated denied effect raises a real alert; the inbox sockets require a token.
    run "browser inbox (real proxy + downstream; held calls, approve/deny, alert holds an auto-approved call, token required)" bash -c "cd frontend && INBOX_STAGE=1 INBOX_TOKEN=gate-inbox-token SENTINEL_MONITOR=action_sim npx playwright test inbox"
    # policy engine (DECISIONS.md D18): rules decide allow / deny / ask in the real UI; the proxy's auto flag is ignored when a policy is configured
    run "browser inbox policy (allow/deny/ask by rule; proxy auto flag ignored)" bash -c "cd frontend && POLICY_STAGE=1 INBOX_TOKEN=gate-inbox-token SENTINEL_MONITOR=action_sim SENTINEL_POLICY=$R/tests/e2e/data/policy_e2e.json npx playwright test policy"
    # operator UI (DECISIONS.md D20): deny with a reason, why/what-so-far evidence, standing rule through the two-step confirm, in a real browser
    OPPOL="$TMPD/operator_policy.json"
    run "browser operator UI (reason reaches the agent, evidence panels, standing rule applies to a new session)" bash -c "echo '{\"version\":1,\"default\":\"ask\",\"rules\":[]}' > $OPPOL && cd frontend && OPERATOR_STAGE=1 INBOX_TOKEN=gate-inbox-token SENTINEL_MONITOR=action_sim SENTINEL_POLICY=$OPPOL SENTINEL_POLICY_WRITABLE=1 npx playwright test operator"
    # enforcement boundary (DECISIONS.md D21): Landlock + network-namespace sandboxed per-call downstream with a just-in-time secret, boundary chips and the credentials warning in a real browser
    run "browser boundary (sandbox chips, credentials warning, unsandboxed flagged)" bash -c "cd frontend && BOUNDARY_STAGE=1 INBOX_TOKEN=gate-inbox-token SENTINEL_MONITOR=action_sim npx playwright test boundary"
    # identity, tenancy, escalation (DECISIONS.md D22): sign-in, read-only viewers, escalation badge, tenant isolation, who decided, in a real browser (identity file, no legacy token)
    IDDIR="$TMPD/identity"
    run "browser identity (sign-in, roles, tenants, escalation)" bash -c "python scripts/make_identity_fixture.py --dir $IDDIR && cd frontend && IDENTITY_STAGE=1 IDENTITY_TOKENS=$IDDIR/tokens.json SENTINEL_IDENTITY_FILE=$IDDIR/identity.json SENTINEL_MONITOR=rules SENTINEL_EMBEDDER=stub npx playwright test identity"
  else
    run "browser stages need Chromium (set CHROMIUM_PATH)" bash -c 'echo "no Chromium at ${CHROMIUM_PATH:-/opt/pw-browsers/chromium}"; false'
  fi
else
  run "frontend stages need frontend/node_modules (run: cd frontend && npm ci)" false
fi
# GATE_TIER=full and weekly only (nightly / weekly CI), each still opt-in by its RUN_* variable.
if at_tier full; then
  # Docker (DECISIONS.md D23): opt in with RUN_DOCKER_TESTS=1 (needs a Docker daemon, ~6 min; see docs/DOCKER.md for the sandbox env vars). The static Docker tests already run in the pytest stage.
  [ "${RUN_DOCKER_TESTS:-0}" = "1" ] && run "docker: test-gated multi-stage build + real containers + compose" bash scripts/docker_test.sh
  # User journeys with screenshots (docs/JOURNEYS.md): opt in with RUN_JOURNEY_TESTS=1 (W9 needs the Docker images)
  [ "${RUN_JOURNEY_TESTS:-0}" = "1" ] && run "user journeys (W1-W9 with screenshots)" bash -c "cd frontend && npm run journeys"
  # A REAL Claude Code client (`claude -p`) behind the proxy, scripted human on /inbox/ws (DECISIONS.md D28): opt in with RUN_CLAUDE_TESTS=1 (needs a
  # signed-in `claude` CLI, costs real model calls, ~30 s, measured $0.04-0.12 per run). Opted in, a missing or signed-out CLI FAILS. CLAUDE_TEST_MODEL picks the model.
  [ "${RUN_CLAUDE_TESTS:-0}" = "1" ] && run "claude code: a real Claude Code client behind SENTINEL (filesystem + note; Desktop Commander + starter)" gate_with_claude_key env REALDEPS_REQUIRED=1 $NS -m claude_live tests/claude
fi
# Mutation check: every mutant at full; at pr only the mutants selected by the changes since the merge base with GATE_BASE (default @origin =
# origin's default branch; no such ref is RED): a changed target selects its mutants, a changed test file selects every mutant.
if at_tier full; then
  run "mutation check (tests must catch re-introduced bugs)" python scripts/mutation_check.py
elif at_tier pr; then
  BASE="${GATE_BASE:-@origin}"
  run "mutation check, changed files only (mutants of what changed since $BASE)" python scripts/mutation_check.py --changed-since "$BASE"
fi
if [ "${GATE_LIST:-0}" = 1 ]; then echo; echo "GATE: LISTED (GATE_TIER=${GATE_TIER:-full}; nothing ran)"; exit 2; fi
echo; [ $fail -eq 0 ] && echo "GATE: GREEN" || echo "GATE: RED"
exit $fail
