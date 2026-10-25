#!/usr/bin/env bash
# Verification gate. Exit code is the only verdict: 0 = every check passed.
# Nothing here is judged by the author of the change; it only runs commands.
set -u
cd "$(dirname "$0")/.."
fail=0
run() { # name, command...
  local name="$1"; shift
  echo "=== GATE: $name"
  if "$@"; then echo "--- PASS: $name"; else echo "--- FAIL: $name"; fail=1; fi
}
run "backend pytest (server + seismograph + contract + e2e)" python -m pytest
run "seismograph legacy pipeline script" python -m seismograph.test_pipeline --stub-only
if [ -d frontend/node_modules ]; then
  run "frontend typecheck" bash -c 'cd frontend && npx tsc -b'
  run "frontend lint"      bash -c 'cd frontend && npm run lint --silent'
  if grep -q '"test"' frontend/package.json; then
    run "frontend unit tests" bash -c 'cd frontend && npm test --silent'
  fi
  run "frontend build"     bash -c 'cd frontend && npm run build --silent'
  # Real browser + real WebSocket + real backend + scripted HTTP LLM. Skipped (loudly) only if no Chromium.
  if [ -x "${CHROMIUM_PATH:-/opt/pw-browsers/chromium}" ]; then
    run "browser e2e (playwright, live stack, rules monitor)" bash -c 'cd frontend && npx playwright test'
    # The shipped default monitor and the learned one, replaying 12 recorded traces (v1+v2) with the real MiniLM:
    # live alerts must equal the offline frozen detector's and arrive before the human decision.
    R="$PWD"
    IDS="gen_a-001,gen_b-011,gen_c-001,gen_d-009,gen_e-001,gen_f-001,v2a-003,v2b-001,v2c-005,v2d-004,v2e-002,v2e-010"
    TR="$R/eval/final/traces.json:$R/eval/final_v2/traces.json"
    run "browser replay parity: action_sim (D3, default monitor)" bash -c "cd frontend && REPLAY_IDS=$IDS FAKE_LLM_TRACES=$TR SENTINEL_MONITOR=action_sim REPLAY_DETECTOR=D3 REPLAY_FROZEN=$R/eval/results_v2/frozen_models.json npx playwright test replay-traces"
    run "browser replay parity: learned (D7 post-hoc)" bash -c "cd frontend && REPLAY_IDS=$IDS FAKE_LLM_TRACES=$TR SENTINEL_MONITOR=learned SENTINEL_MONITOR_MODEL=$R/eval/results_v2_posthoc/frozen_models.json REPLAY_DETECTOR=D7 REPLAY_FROZEN=$R/eval/results_v2_posthoc/frozen_models.json npx playwright test replay-traces"
  else
    echo "--- FAIL: no Chromium at \${CHROMIUM_PATH:-/opt/pw-browsers/chromium}; set CHROMIUM_PATH"; fail=1
  fi
else
  echo "--- FAIL: frontend/node_modules missing (run: cd frontend && npm ci)"; fail=1
fi
[ -f scripts/mutation_check.py ] && run "mutation check (tests must catch re-introduced bugs)" python scripts/mutation_check.py
echo; [ $fail -eq 0 ] && echo "GATE: GREEN" || echo "GATE: RED"
exit $fail
