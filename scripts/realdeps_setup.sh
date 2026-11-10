#!/usr/bin/env bash
# Installs the REAL MCP servers used by tests/realdeps into ./.realdeps (git-ignored). Idempotent.
#   filesystem + memory (npm, pinned in tests/realdeps/package.json) and time (PyPI, in its own venv so its mcp pin cannot clash with ours)
set -euo pipefail
cd "$(dirname "$0")/.."
D=.realdeps
mkdir -p "$D"
cp tests/realdeps/package.json "$D/package.json"
[ -f tests/realdeps/package-lock.json ] && cp tests/realdeps/package-lock.json "$D/package-lock.json"
if [ ! -x "$D/node_modules/.bin/mcp-server-filesystem" ] || [ ! -x "$D/node_modules/.bin/mcp-server-memory" ]; then
  (cd "$D" && npm install --no-audit --no-fund --loglevel=error)
fi
if [ ! -x "$D/tv/bin/mcp-server-time" ]; then
  python -m venv "$D/tv"
  "$D/tv/bin/pip" install -q mcp-server-time
fi
[ -f "$D/package-lock.json" ] && cp "$D/package-lock.json" tests/realdeps/package-lock.json
echo "realdeps ready: $D"
