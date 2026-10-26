#!/usr/bin/env python
"""Build ONE merged destination registry for the browser replay-parity stages of scripts/verify.sh.

    python scripts/make_replay_registry.py --ids gen_a-001,...,v2e-010 --out tests/browser/replay_registry.json

The per-trace registries (eval/registries_v2/ex1.json, extractor 1) of the chosen trace ids are combined with
``server.registry.merge``. Ids without an entry (all v1 traces, v2 external_benign / same_party_unrelated ...) contribute
nothing: they run against the registry's defaults. The script REPORTS every merge conflict (two traces saying different
things about the same destination) and the merged registry's lint result, and exits 1 on either: if two traces conflict,
swap one of them for another v2 trace that has an entry. Exit 2 on bad arguments. Prints what it did on stdout.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from server.registry import merge  # noqa: E402

DEFAULT_IDS = "gen_a-001,gen_b-011,gen_c-001,gen_d-009,gen_e-001,gen_f-001,v2a-003,v2b-001,v2c-005,v2d-004,v2e-002,v2e-010"
DEFAULT_SOURCE = REPO / "eval" / "registries_v2" / "ex1.json"
DEFAULT_OUT = REPO / "tests" / "browser" / "replay_registry.json"


def build(ids: list[str], per_trace: dict):
    """-> (merged Registry, conflicts, ids with an entry, ids without one, lint errors of the merged registry)."""
    have = [i for i in ids if i in per_trace]
    reg, conflicts = merge([per_trace[i] for i in have])
    return reg, conflicts, have, [i for i in ids if i not in per_trace], reg.validate()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ids", default=DEFAULT_IDS, help="comma-separated trace ids")
    ap.add_argument("--source", default=str(DEFAULT_SOURCE), help="JSON {trace id: registry}")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    a = ap.parse_args(argv)
    ids = [i for i in a.ids.split(",") if i]
    if not ids:
        ap.error("--ids is empty")
    try:
        per_trace = json.loads(Path(a.source).read_text())
    except (OSError, ValueError) as exc:
        ap.error(f"cannot read {a.source}: {exc}")
    reg, conflicts, have, without, errors = build(ids, per_trace)
    print(f"{len(ids)} ids: {len(have)} with a registry entry ({', '.join(have) or '-'}); "
          f"{len(without)} use the defaults ({', '.join(without) or '-'})")
    print(f"merged registry: {len(reg.entries)} entries, digest {reg.digest()}")
    for c in conflicts:
        print(f"CONFLICT: {c}")
    for e in errors:
        print(f"LINT ERROR: {e}")
    if conflicts or errors:
        print(f"NOT written: {len(conflicts)} conflict(s), {len(errors)} lint error(s). Swap a conflicting trace for "
              f"another v2 trace that has an entry in {a.source}.")
        return 1
    Path(a.out).write_text(json.dumps(reg.to_dict(), indent=1) + "\n")
    print(f"wrote {a.out}: conflict-free, lint clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
