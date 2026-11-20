#!/usr/bin/env bash
# Local flake hunter (NOT part of any CI tier or verify.sh). Runs a pytest selection ROUNDS times under xdist
# oversubscription while CPU burners run, and records every failing test id per round.
#   scripts/flake_hunt.sh [-r ROUNDS] [-n WORKERS] [-b BURNERS] [-o OUTDIR] [-t MAX_SECONDS] -- <pytest args...>
# Example (the `backend pytest, fast` selection of verify.sh):
#   scripts/flake_hunt.sh -r 8 -- -m 'not reality and not claude_live and not slow and not research'
# Exit: 0 = no test failed; 1 = at least one test failed in some rounds but not all (flaky);
#       2 = at least one test failed in every round (broken; also 1's cases are reported); 3 = bad usage, no rounds ran, or pytest itself errored (exit other than 0/1).
# Output: OUTDIR/round-N.log, OUTDIR/round-N.junit.xml, OUTDIR/summary.txt (counts per test id + first failure text).
set -u
cd "$(dirname "$0")/.."
ROUNDS=8; WORKERS=8; BURNERS=4; MAXSEC=0
OUT="${TMPDIR:-/tmp}/flake_hunt.$(date +%s)"
while getopts "r:n:b:o:t:" o; do
  case $o in r) ROUNDS=$OPTARG;; n) WORKERS=$OPTARG;; b) BURNERS=$OPTARG;; o) OUT=$OPTARG;; t) MAXSEC=$OPTARG;; *) sed -n 2,9p "$0"; exit 3;; esac
done
shift $((OPTIND-1)); [ "${1:-}" = "--" ] && shift
mkdir -p "$OUT"
pids=()
cleanup() { for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
trap "cleanup; trap - EXIT; exit 130" INT TERM
for ((i=0;i<BURNERS;i++)); do python -c 'while 1: pass' & pids+=($!); done
start=$(date +%s); done_rounds=0
for ((r=1;r<=ROUNDS;r++)); do
  if [ "$MAXSEC" -gt 0 ] && [ $(( $(date +%s)-start )) -ge "$MAXSEC" ]; then echo "time box reached: no new round after $done_rounds"; break; fi
  echo "== round $r/$ROUNDS (-n $WORKERS, $BURNERS burners)"
  OMP_NUM_THREADS=1 python -m pytest -n "$WORKERS" -p no:cacheprovider --junitxml="$OUT/round-$r.junit.xml" "$@" >"$OUT/round-$r.log" 2>&1
  rc=$?
  echo "   pytest exit $rc ; log $OUT/round-$r.log"
  # 0 = all passed, 1 = some tests failed; anything else (usage/collection error, empty selection, crash) is a broken command, not a clean run
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then cleanup; trap - EXIT; echo "pytest exited $rc (not a test result): fix the selection; see $OUT/round-$r.log"; exit 3; fi
  done_rounds=$r
done
cleanup; trap - EXIT
[ "$done_rounds" -gt 0 ] || { echo "no round ran"; exit 3; }
python - "$OUT" "$done_rounds" <<'PY'
import sys, glob, collections, xml.etree.ElementTree as ET
out, n = sys.argv[1], int(sys.argv[2])
fails = collections.defaultdict(list)   # test id -> [(round, text)]
errors = []
for r in range(1, n + 1):
    try:
        root = ET.parse(f"{out}/round-{r}.junit.xml").getroot()
    except Exception as e:
        errors.append(f"round {r}: no readable junit ({e}); see round-{r}.log"); continue
    for tc in root.iter("testcase"):
        bad = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
        if bad is not None:
            tid = f"{tc.get('classname')}::{tc.get('name')}"
            txt = (bad.get("message") or "") + "\n" + (bad.text or "")
            fails[tid].append((r, txt.strip()[-1500:]))
lines = [f"rounds run: {n}"] + errors
flaky = broken = 0
for tid, fl in sorted(fails.items(), key=lambda kv: -len(kv[1])):
    k = len(fl); kind = "BROKEN" if k == n else "FLAKY"
    broken += k == n; flaky += k != n
    lines.append(f"\n{kind} {k}/{n}  {tid}  rounds={[r for r, _ in fl]}\n  first failure (round {fl[0][0]}):\n" + "\n".join("    " + l for l in fl[0][1].splitlines()[-25:]))
if not fails and not errors: lines.append("no failures")
lines.append(f"\nSUMMARY flaky={flaky} broken={broken}")
open(f"{out}/summary.txt", "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
sys.exit(2 if broken else 1 if flaky or errors else 0)
PY
