#!/bin/sh
# Backend tests that run INSIDE the image build (Dockerfile stage `backend-test`).
#   fast (default) ~2000 tests, ~25 s: the security-relevant, hermetic suites (identity, policy, event log, notifier, UI serving, health, contract).
#   full           the whole tests/server + tests/contract suites (minutes).
#   none           skip (for quick local builds; the image is then NOT test-gated).
# Sandbox/Landlock tests are never run here: a build container is not the place to probe kernel features.
set -eu
level="${1:-fast}"
cd /app
export HF_HUB_OFFLINE=1 OMP_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1
case "$level" in
  none) echo "backend tests: SKIPPED (TEST_LEVEL=none)"; exit 0 ;;
  fast)
    exec python -m pytest -q -p no:cacheprovider \
      tests/contract \
      tests/server/test_ui_static.py tests/server/test_health_view.py tests/server/test_safe_text.py \
      tests/server/test_auth.py tests/server/test_gate.py \
      tests/server/test_identity.py tests/server/test_identity_cli.py \
      tests/server/test_policy.py tests/server/test_policy_cli.py tests/server/test_policy_writer.py \
      tests/server/test_notify.py tests/server/test_escalation.py \
      tests/server/test_eventlog.py tests/server/test_eventlog_cli.py tests/server/test_eventlog_scrub.py \
      tests/server/test_registry.py ;;
  full) exec python -m pytest -q -p no:cacheprovider tests/server tests/contract ;;
  *) echo "unknown TEST_LEVEL '$level' (use fast | full | none)" >&2; exit 2 ;;
esac
