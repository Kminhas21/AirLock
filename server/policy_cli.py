"""Operator CLI for the policy engine.

    python -m policy_cli lint <policy.json>
    python -m policy_cli explain <policy.json> --server S --tool T --args '{...}' [--registry reg.json] [--alert]
    python -m policy_cli test <policy.json> --traces <traces.json> [--registry reg.json] [--server NAME] [--json]
    python -m policy_cli init OUT.json [--starter] [--force]       (an editable copy of the built-in starter policy)

A policy argument may also be ``builtin:starter`` (the shipped starter policy).

Run from the server/ directory (or with server/ on PYTHONPATH).  Exit status: 0 ok, 1 policy errors,
2 unreadable file / bad arguments.  Never a traceback for bad input.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import policy as P

VIOLATING_LABELS = ("violation", "denied_seed")     # eval traces: a labelled violation and the seeded denied action
BENIGN_LABELS = ("ok",)


class _Args(argparse.ArgumentParser):
    def error(self, message):                        # argparse exits 2 by itself; keep it explicit
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(2)


def _err(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 2


def _load_policy(path: str):
    """-> (Policy, None, 0) | (None, errors, exit code)."""
    try:
        return P.load_policy(path), None, 0
    except P.PolicyUnreadable as e:
        return None, e.messages, 2
    except P.PolicyError as e:
        return None, e.messages, 1


def _load_registry(path):
    if not path:
        return None, None
    try:
        from registry import Registry
        return Registry.load(path), None
    except FileNotFoundError:
        return None, f"cannot read {path}: no such file"
    except (OSError, ValueError) as e:
        return None, f"cannot read {path}: {e}"


def _policy_or_exit(path: str):
    pol, errs, code = _load_policy(path)
    if pol is None:
        stream = sys.stdout if code == 1 else sys.stderr
        for m in errs:
            print(f"ERROR: {m}", file=stream)
        if code == 1:
            print(f"FAILED: {len(errs)} error(s) in {path}")
    return pol, code


def cmd_lint(ns) -> int:
    pol, code = _policy_or_exit(ns.policy)
    if pol is None:
        return code
    warnings = pol.lint()
    for w in warnings:
        print(f"WARN:  {w}")
    print(f"OK: {len(pol.rules)} rules, default {pol.default}, {len(warnings)} warning(s), digest {pol.digest()}")
    return 0


def cmd_explain(ns) -> int:
    pol, code = _policy_or_exit(ns.policy)
    if pol is None:
        return code
    try:
        args = json.loads(ns.args)
    except ValueError as e:
        return _err(f"--args is not valid JSON: {e}")
    reg, err = _load_registry(ns.registry)
    if err:
        return _err(err)
    d = pol.evaluate(ns.server, ns.tool, args, registry=reg, alerts_present=ns.alert)
    print(f"verdict: {d.verdict}")
    print(f"rule:    {d.rule_id or '(none)'}")
    print(f"reason:  {d.reason}")
    print(f"escalated: {'yes (alert)' if d.escalated else 'no'}")
    by_id = {r.id: r for r in pol.rules}
    if not d.matched:
        print("matched: (no rule)")
    for rid in d.matched:
        r = by_id[rid]
        note = f"  # {r.note}" if r.note else ""
        mark = "*" if rid == d.rule_id else " "
        print(f"matched:{mark}{rid} [{r.verdict}]{note}")
    return 0


def _read_traces(path: str):
    try:
        with open(path, "rb") as fh:
            data = json.loads(fh.read().decode("utf-8"))
    except OSError as e:
        raise ValueError(f"cannot read {path}: {e}")
    except (ValueError, RecursionError) as e:
        raise ValueError(f"cannot read {path}: not valid JSON ({e})")
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON list of traces")
    props = []
    for ti, t in enumerate(data):
        steps = t.get("steps") if isinstance(t, dict) else None
        if not isinstance(steps, list):
            raise ValueError(f"{path}: trace {ti} has no steps list")
        for si, s in enumerate(steps):
            if not isinstance(s, dict):
                raise ValueError(f"{path}: trace {ti} step {si} is not an object")
            p = s.get("proposal")
            if p is None:
                continue
            if not isinstance(p, dict):
                raise ValueError(f"{path}: trace {ti} step {si} proposal is not an object")
            props.append(p)
    return props


def run_replay(pol, proposals, registry=None, server: str = "") -> dict:
    verdicts = {"allow": 0, "deny": 0, "ask": 0}
    by_label: dict = {}
    hits: dict = {}
    viol_allowed = benign_asked = 0
    for p in proposals:
        d = pol.evaluate(server, p.get("tool"), p.get("args"), registry=registry, alerts_present=False)
        label = p.get("label")
        label = label if isinstance(label, str) else "unlabeled"
        verdicts[d.verdict] += 1
        by_label.setdefault(label, {"allow": 0, "deny": 0, "ask": 0})[d.verdict] += 1
        hits[d.rule_id or "(default)"] = hits.get(d.rule_id or "(default)", 0) + 1
        if d.verdict == "allow" and label in VIOLATING_LABELS:
            viol_allowed += 1
        if d.verdict == "ask" and label in BENIGN_LABELS:
            benign_asked += 1
    return {
        "policy_digest": pol.digest(),
        "proposals": len(proposals),
        "verdicts": verdicts,
        "by_label": {k: by_label[k] for k in sorted(by_label)},
        "rule_hits": dict(sorted(hits.items(), key=lambda kv: (-kv[1], kv[0]))),
        "violating_allowed": viol_allowed,
        "benign_asked": benign_asked,
    }


def cmd_test(ns) -> int:
    pol, code = _policy_or_exit(ns.policy)
    if pol is None:
        return code
    try:
        proposals = _read_traces(ns.traces)
    except ValueError as e:
        return _err(str(e))
    reg, err = _load_registry(ns.registry)
    if err:
        return _err(err)
    out = run_replay(pol, proposals, reg, ns.server)
    if ns.json:
        print(json.dumps(out, indent=2))
        return 0
    v = out["verdicts"]
    print(f"policy {ns.policy} (digest {out['policy_digest']}), {out['proposals']} proposals")
    print(f"overall: allow {v['allow']}  deny {v['deny']}  ask {v['ask']}")
    print(f"{'label':14} {'allow':>6} {'deny':>6} {'ask':>6}")
    for label, c in out["by_label"].items():
        print(f"{label:14} {c['allow']:>6} {c['deny']:>6} {c['ask']:>6}")
    print("rule hits:")
    for rid, n in out["rule_hits"].items():
        print(f"  {n:>5}  {rid}")
    print(f"violating proposals the policy would ALLOW: {out['violating_allowed']}")
    print(f"benign proposals the policy would ASK: {out['benign_asked']}")
    return 0


def cmd_init(ns) -> int:
    """Write a copy of the built-in starter policy (mode 0600, like policy_writer) so it can be edited."""
    src = P.resolve_policy_path("builtin:starter")
    try:
        with open(src, "rb") as fh:
            data = fh.read()
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if ns.force else os.O_EXCL) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(ns.out, flags, 0o600)
    except FileExistsError:
        return _err(f"{ns.out} already exists (use --force to overwrite it)")
    except OSError as e:
        return _err(f"cannot write {ns.out}: {e}")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(ns.out, 0o600)
    print(f"wrote {ns.out} (the starter policy). Edit it, then set SENTINEL_POLICY={os.path.abspath(ns.out)}")
    return 0


def main(argv=None) -> int:
    ap = _Args(prog="policy_cli", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Args)
    p = sub.add_parser("lint", help="validate a policy file")
    p.add_argument("policy")
    p.set_defaults(fn=cmd_lint)
    p = sub.add_parser("explain", help="show how a tool call is decided")
    p.add_argument("policy")
    p.add_argument("--server", default="")
    p.add_argument("--tool", required=True)
    p.add_argument("--args", default="{}", help="tool arguments as a JSON object")
    p.add_argument("--registry")
    p.add_argument("--alert", action="store_true", help="assume a monitor alert is present on the call")
    p.set_defaults(fn=cmd_explain)
    p = sub.add_parser("test", help="replay recorded proposals of an eval trace file")
    p.add_argument("policy")
    p.add_argument("--traces", required=True)
    p.add_argument("--registry")
    p.add_argument("--server", default="")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_test)
    p = sub.add_parser("init", help="write an editable copy of the built-in starter policy")
    p.add_argument("out")
    p.add_argument("--starter", action="store_true", help="the starter policy (the only one, so this is the default)")
    p.add_argument("--force", action="store_true", help="overwrite OUT if it exists")
    p.set_defaults(fn=cmd_init)
    try:
        ns = ap.parse_args(argv)
        return ns.fn(ns)
    except BrokenPipeError:
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2


if __name__ == "__main__":
    sys.exit(main())
