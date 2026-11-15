#!/usr/bin/env bash
# Installs the REAL MCP servers used by tests/realdeps, tests/live and tests/claude into ./.realdeps (git-ignored). Idempotent.
#   filesystem + memory + Desktop Commander (npm, pinned EXACTLY by tests/realdeps/package-lock.json via `npm ci`) and time (PyPI, in its own venv
#   so its mcp pin cannot clash with ours).
#   npm runs with --ignore-scripts: no third-party install script runs (Desktop Commander's postinstall phones home and downloads ripgrep;
#   none of the three servers needs a script to start). The tests give Desktop Commander a private HOME and switch its telemetry off.
#   Re-installs only when a server is missing or the committed lockfile changed since the last install (.realdeps/.installed.lock).
set -euo pipefail
cd "$(dirname "$0")/.."
D=.realdeps
LOCK=tests/realdeps/package-lock.json
[ -f "$LOCK" ] || { echo "missing $LOCK (the pin): refusing to install unpinned servers" >&2; exit 1; }
mkdir -p "$D"
if [ ! -x "$D/node_modules/.bin/mcp-server-filesystem" ] || [ ! -x "$D/node_modules/.bin/mcp-server-memory" ] \
   || [ ! -x "$D/node_modules/.bin/desktop-commander" ] || ! cmp -s "$LOCK" "$D/.installed.lock"; then
  cp tests/realdeps/package.json "$D/package.json"
  cp "$LOCK" "$D/package-lock.json"
  (cd "$D" && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error)
  cp "$LOCK" "$D/.installed.lock"
fi
# PyPI time server, pinned (its own dependencies are not: there is no lockfile for them). Rebuilt when the venv's interpreter no longer runs
# (a restored cache from another Python) or the installed version is not the pin.
TIME_PIN=2026.11.4
if ! "$D/tv/bin/python" -c "import importlib.metadata as m, sys; sys.exit(m.version('mcp-server-time') != '$TIME_PIN')" 2>/dev/null \
   || [ ! -x "$D/tv/bin/mcp-server-time" ]; then
  rm -rf "$D/tv"
  python -m venv "$D/tv"
  "$D/tv/bin/pip" install -q "mcp-server-time==$TIME_PIN"
fi
echo "realdeps ready: $D"
