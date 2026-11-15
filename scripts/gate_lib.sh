# Sourced by scripts/verify.sh. The gate's stage runner, plus three opt-in ways to hear about a failure the moment it happens
# instead of when the whole gate ends (docs/TESTING_REALITY.md, "Hearing about failures immediately"):
#   GATE_EVENTS=<file>      appended as it happens: "HH:MM:SS START <name>", "HH:MM:SS PASS|FAIL <name> (<secs>s)", and on EVERY way out
#                           of the gate (normal end, fail-fast, an abort, SIGINT/SIGTERM) "HH:MM:SS DONE GREEN|RED". A relative path is taken
#                           from the repository root (verify.sh cds there). Watch it with `tail -F`, a CI log tailer, or a Claude Code Monitor.
#   GATE_ON_FAIL=<command>  run (bash -c) once per failed stage with GATE_STAGE=<name>; e.g. a webhook:
#                           GATE_ON_FAIL='curl -fsS -m 10 -d "gate stage failed: $GATE_STAGE" "$MY_WEBHOOK_URL"'
#                           Its own exit code is ignored: a broken hook never changes the verdict.
#   GATE_FAIL_FAST=1        stop at the first failed stage (exit 1) instead of running the rest.
#   GATE_TIER=push|pr|full|weekly   which stages run (default full; docs/TESTING_REALITY.md "CI tiers", DECISIONS.md D30). The tiers nest:
#                           each runs everything the one before it runs (except pr's changed-files mutation stage, which full replaces).
#   GATE_LIST=1             run nothing: print "STAGE <name> :: <command>" for every stage the tier would run, then "GATE: LISTED", exit 2
#                           (never 0, so a listing can never pass for a green gate).
# Expects the caller to define `fail=0`.

# The ONE place that maps pytest markers to tiers (tests/test_gate_tiers.py proves every collected test is selected by one of them, once):
# unmarked -> push, `slow` (process-based files) -> pr, `research` (opt-in detectors D7-D9c) -> weekly; `reality` and `claude_live` have
# their own stages in verify.sh.
GATE_PYTEST_PUSH='not reality and not claude_live and not slow and not research'
GATE_PYTEST_PR='slow and not research and not reality and not claude_live'
GATE_PYTEST_WEEKLY='research and not reality and not claude_live'

gate_tier_rank() { # tier -> 1..4, 0 if unknown
  case "$1" in push) echo 1 ;; pr) echo 2 ;; full) echo 3 ;; weekly) echo 4 ;; *) echo 0 ;; esac
}

# true when the gate's tier (GATE_TIER, default full) includes the stages of tier $1
at_tier() {
  [ "$(gate_tier_rank "${GATE_TIER:-full}")" -ge "$(gate_tier_rank "$1")" ]
}

gate_check_tier() {
  if [ "$(gate_tier_rank "${GATE_TIER:-full}")" = 0 ]; then
    echo "GATE_TIER=${GATE_TIER:-} is not one of push, pr, full, weekly"; return 1
  fi
}

gate_event() { # kind name [seconds]
  [ -n "${GATE_EVENTS:-}" ] || return 0
  printf '%s %s %s%s\n' "$(date -u +%H:%M:%S)" "$1" "$2" "${3:+ (${3}s)}" >> "$GATE_EVENTS"
}

run() { # name, command...
  local name="$1"; shift
  if [ "${GATE_LIST:-0}" = 1 ]; then printf 'STAGE %s :: ' "$name"; printf '%q ' "$@"; echo; return 0; fi
  local t0=$SECONDS
  echo "=== GATE: $name"
  gate_event START "$name"
  if "$@"; then
    echo "--- PASS: $name"
    gate_event PASS "$name" $((SECONDS - t0))
  else
    echo "--- FAIL: $name"
    fail=1
    gate_event FAIL "$name" $((SECONDS - t0))
    if [ -n "${GATE_ON_FAIL:-}" ]; then GATE_STAGE="$name" bash -c "$GATE_ON_FAIL" || true; fi
    if [ "${GATE_FAIL_FAST:-0}" = 1 ]; then echo; echo "GATE: RED (fail-fast at: $name)"; exit 1; fi
  fi
}

# DONE GREEN|RED from the exit status, on every way out (the verdict is the exit code; a signal or an abort is RED).
gate_install_done_trap() {
  trap 'rc=$?; gate_event DONE "$([ $rc -eq 0 ] && echo GREEN || echo RED)"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
}

# Checks, in seconds, that every OPTED-IN stage can work at all, so a misconfiguration is not found hours later at the end of the gate.
gate_preflight() {
  local ok=0
  if [ "${RUN_DOCKER_TESTS:-0}" = 1 ]; then
    if ! timeout 20 docker info >/dev/null 2>&1; then
      echo "preflight: RUN_DOCKER_TESTS=1 but the Docker daemon is not reachable (start dockerd)"; ok=1
    fi
    # Behind an HTTPS proxy the image build reaches PyPI/npm only with the proxy forwarded and its CA trusted (docs/DOCKER.md).
    # SENTINEL_DOCKER_PREFLIGHT_PROXY=0 skips this for a proxy that does not intercept TLS.
    local proxy="${HTTPS_PROXY:-${https_proxy:-}}"      # the same variable scripts/docker_test.sh forwards
    if [ -n "$proxy" ] && [ "${SENTINEL_DOCKER_PREFLIGHT_PROXY:-1}" = 1 ]; then
      local ca="${SENTINEL_DOCKER_BUILD_CA:-}"
      if [ -z "$ca" ] || [ ! -f "$ca" ] || [ ! -r "$ca" ] || [ "${SENTINEL_DOCKER_FORWARD_PROXY:-}" != 1 ]; then
        echo "preflight: an HTTPS proxy is set; the Docker build needs SENTINEL_DOCKER_FORWARD_PROXY=1 and SENTINEL_DOCKER_BUILD_CA (a readable"
        echo "           CA file), or SENTINEL_DOCKER_PREFLIGHT_PROXY=0 for a proxy that does not intercept TLS"; ok=1
      fi
      case "$proxy" in
        *://127.*|*://localhost*|*://\[::1\]*|127.*|localhost*)
          if [ "${SENTINEL_DOCKER_NETWORK_HOST:-}" != 1 ]; then
            echo "preflight: the proxy ($proxy) is on loopback; the build container reaches it only with SENTINEL_DOCKER_NETWORK_HOST=1"; ok=1
          fi ;;
      esac
    fi
  fi
  if [ "${RUN_CLAUDE_TESTS:-0}" = 1 ] && ! claude --version >/dev/null 2>&1; then
    echo "preflight: RUN_CLAUDE_TESTS=1 but the claude CLI is missing or broken"; ok=1
  fi
  return $ok
}

# The Claude stage's API key (CI: SENTINEL_CLAUDE_API_KEY) reaches that stage only: gate_take_claude_key moves it into a shell variable that
# no child process inherits, gate_with_claude_key runs one command with it as ANTHROPIC_API_KEY. Never in argv (GATE_LIST prints argv).
gate_take_claude_key() {
  GATE_CLAUDE_KEY="${SENTINEL_CLAUDE_API_KEY:-}"
  unset SENTINEL_CLAUDE_API_KEY
}

gate_with_claude_key() {
  if [ -n "${GATE_CLAUDE_KEY:-}" ]; then ANTHROPIC_API_KEY="$GATE_CLAUDE_KEY" "$@"; else "$@"; fi
}
