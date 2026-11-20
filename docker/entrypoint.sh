#!/bin/sh
# Container entrypoint.   sentinel-entrypoint [serve | check | proxy <args> | <any command>]
#   serve  (default)  pre-flight checks, then ONE uvicorn process (the hub keeps its state in memory: never run more than one worker or one replica)
#   check             the same pre-flight checks, then exit 0 (use it in CI / before a deploy)
#   proxy <args>      run the MCP proxy: sentinel-entrypoint proxy --config /etc/sentinel/proxy.json
# The pre-flight fails FAST (exit 2) with a message instead of starting something that would refuse every connection.
set -eu

die() { echo "sentinel: $*" >&2; exit 2; }

preflight() {
  data_dir="${SENTINEL_DATA_DIR:-/var/lib/sentinel}"
  # identity mode from two bootstrap tokens (digests only are stored); an existing file is never overwritten
  if [ -z "${SENTINEL_IDENTITY_FILE:-}" ] && [ -n "${SENTINEL_BOOTSTRAP_ADMIN_TOKEN:-}${SENTINEL_BOOTSTRAP_AGENT_TOKEN:-}" ]; then
    [ -w "$data_dir" ] || die "$data_dir is not writable (mount a volume there)"
    python /opt/sentinel/bootstrap_identity.py "$data_dir/identity.json" || exit 2
    export SENTINEL_IDENTITY_FILE="$data_dir/identity.json"
  fi
  if [ -z "${SENTINEL_IDENTITY_FILE:-}" ] && [ -z "${SENTINEL_WS_TOKEN:-}" ]; then
    die "no credentials configured: set SENTINEL_BOOTSTRAP_ADMIN_TOKEN and SENTINEL_BOOTSTRAP_AGENT_TOKEN (>= 16 chars each, e.g. openssl rand -hex 24), or mount an identity file and set SENTINEL_IDENTITY_FILE. Without them the inbox would refuse every connection."
  fi
  if [ -n "${SENTINEL_IDENTITY_FILE:-}" ]; then
    [ -r "$SENTINEL_IDENTITY_FILE" ] || die "SENTINEL_IDENTITY_FILE=$SENTINEL_IDENTITY_FILE is not readable"
    (cd /app/server && python -m identity_cli lint --file "$SENTINEL_IDENTITY_FILE" >/dev/null) || die "the identity file is invalid: run  python -m identity_cli lint --file $SENTINEL_IDENTITY_FILE"
  elif [ "${#SENTINEL_WS_TOKEN}" -lt 16 ]; then
    die "SENTINEL_WS_TOKEN must be at least 16 characters (openssl rand -hex 24)"
  else
    echo "sentinel: legacy shared-token mode: the bundled UI has no token baked in, so use identity mode (SENTINEL_BOOTSTRAP_*) to sign in from the browser" >&2
  fi
  if [ -n "${SENTINEL_EVENT_LOG:-}" ]; then
    log_dir="$(dirname "$SENTINEL_EVENT_LOG")"
    [ -w "$log_dir" ] || die "the event log directory $log_dir is not writable"
    [ -n "${SENTINEL_LOG_KEY:-}" ] || echo "sentinel: warning: SENTINEL_EVENT_LOG is set without SENTINEL_LOG_KEY: tampering by truncation would not be detectable" >&2
  fi
}

cmd="${1:-serve}"
[ "$#" -gt 0 ] && shift
case "$cmd" in
  serve)
    preflight
    cd /app/server
    # --proxy-headers: behind a load balancer the real client address (needed by the sign-in throttle) comes from X-Forwarded-For, but ONLY from the
    # addresses in FORWARDED_ALLOW_IPS (set it to your load balancer's address range, never '*' on an open network)
    exec uvicorn main:app --host 0.0.0.0 --port "${SENTINEL_PORT:-8080}" \
      --proxy-headers --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" --log-level "${SENTINEL_LOG_LEVEL:-info}"
    ;;
  check)
    preflight
    echo "sentinel: pre-flight checks passed"
    ;;
  proxy)
    cd /app
    exec python -m sentinel_proxy "$@"
    ;;
  *)
    exec "$cmd" "$@"
    ;;
esac
