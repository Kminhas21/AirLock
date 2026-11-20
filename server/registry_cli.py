"""Operator CLI for destination registries.

    python -m registry_cli lint <registry.json>
    python -m registry_cli resolve <registry.json> --tool send_email --args '{"to":"x@y"}' [--json] [--scan-text]

Run from the server/ directory (or with server/ on PYTHONPATH).  Exit status: 0 ok, 1 lint errors,
2 unreadable registry / bad arguments.
"""
from __future__ import annotations

import argparse
import json
import sys

from registry import Registry


def _load(path: str):
    try:
        return Registry.load(path), None
    except FileNotFoundError:
        return None, f"cannot read {path}: no such file"
    except (OSError, ValueError) as e:      # json.JSONDecodeError is a ValueError
        return None, f"cannot read {path}: {e}"


def cmd_lint(ns) -> int:
    reg, err = _load(ns.registry)
    if err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 2
    errors, warnings = reg.validate(), reg.warnings()
    for w in warnings:
        print(f"WARN:  {w}")
    for e in errors:
        print(f"ERROR: {e}")
    if errors:
        print(f"FAILED: {len(errors)} error(s), {len(warnings)} warning(s) in {ns.registry}")
        return 1
    print(f"OK: {len(reg.entries)} entries, {len(warnings)} warning(s), digest {reg.digest()}")
    return 0


def cmd_resolve(ns) -> int:
    reg, err = _load(ns.registry)
    if err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 2
    try:
        args = json.loads(ns.args)
    except ValueError as e:
        print(f"ERROR: --args is not valid JSON: {e}", file=sys.stderr)
        return 2
    res = reg.resolve(ns.tool, args, scan_text=ns.scan_text)
    if ns.json:
        print(json.dumps({
            "tool": ns.tool,
            "reaches": sorted(res.reaches),
            "registered": res.registered,
            "tokens": [{"kind": rt.token.kind, "value": rt.token.value, "resolution": rt.resolution.kind,
                        "party": rt.resolution.party, "entry_id": rt.resolution.entry_id} for rt in res.tokens],
        }, indent=2))
        return 0
    print(f"tool: {ns.tool}")
    if not res.tokens:
        print("no destinations (nothing leaves)")
    for rt in res.tokens:
        r = rt.resolution
        party = f" party={r.party}" if r.party else ""
        print(f"  {rt.token.kind:8} {rt.token.value}  ->  {r.kind}{party}  [{r.entry_id}]")
    print(f"reaches: {', '.join(sorted(res.reaches)) or '(nobody)'}")
    print(f"registered: {'yes' if res.registered else 'no'}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="registry_cli", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("lint", help="validate a registry file")
    p.add_argument("registry")
    p.set_defaults(fn=cmd_lint)
    p = sub.add_parser("resolve", help="show how a tool call resolves")
    p.add_argument("registry")
    p.add_argument("--tool", required=True)
    p.add_argument("--args", default="{}", help="tool arguments as a JSON object")
    p.add_argument("--json", action="store_true")
    p.add_argument("--scan-text", action="store_true", help="also scan free-text parameters (body, message, ...)")
    p.set_defaults(fn=cmd_resolve)
    ns = ap.parse_args(argv)
    return ns.fn(ns)


if __name__ == "__main__":
    sys.exit(main())
