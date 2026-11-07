"""Operator CLI for the event log (docs/plans/EVENT-LOG.md, ticket EL2).

    python -m eventlog_cli verify <db> [--key-env SENTINEL_LOG_KEY] [--anchor PATH]
    python -m eventlog_cli show <db> --session S [--call C]
    python -m eventlog_cli export <db> --jsonl [--session S]
    python -m eventlog_cli policy-test <db> <policy.json> [--registry reg.json] [--session S] [--json]

Run from the server/ directory (or with server/ on PYTHONPATH).  Every command opens the log READ-ONLY (nothing is created,
appended or recovered).  Exit status: 0 ok, 1 problems found (verify: tamper / inconsistencies; show: nothing matched;
policy-test: policy errors), 2 unreadable file / bad arguments.  Never a traceback for bad input.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import unicodedata

import eventlog as EL
from policy_cli import BENIGN_LABELS, VIOLATING_LABELS, _Args, _load_registry, _policy_or_exit

_BAD_CATS = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}


def _safe(v, limit: int = 300) -> str:
    """Printable, single-line, terminal-safe text (log data is attacker-influenced: no ANSI escapes, bidi, newlines)."""
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=True, sort_keys=True, default=str)
    out = []
    for ch in s[:limit * 2]:
        if unicodedata.category(ch) in _BAD_CATS or ch == "\x7f":
            out.append(f"\\u{ord(ch):04x}" if ord(ch) < 0x10000 else f"\\U{ord(ch):08x}")
        else:
            out.append(ch)
    t = "".join(out)
    return t if len(t) <= limit else t[:limit] + "..."


def _err(msg: str) -> int:
    print(f"ERROR: {_safe(msg, 500)}", file=sys.stderr)
    return 2


def _key(ns):
    try:
        return EL.load_key(os.environ, ns.key_env), None
    except EL.EventLogError as e:
        return None, str(e)


def _fmt_ts(ts) -> str:
    try:
        return datetime.datetime.fromtimestamp(float(ts), tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%fZ")[:-4] + "Z"
    except (ValueError, OverflowError, OSError, TypeError):
        return _safe(ts, 30)


def cmd_verify(ns) -> int:
    key, err = _key(ns)
    if err:
        return _err(err)
    try:
        r = EL.verify_file(ns.db, key=key, anchor_path=ns.anchor)
    except EL.EventLogError as e:
        return _err(str(e))
    for n in r.notes:
        print(f"NOTE:  {_safe(n, 500)}")
    if not r.ok:
        print(f"FIRST BAD SEQ: {r.first_bad_seq if r.first_bad_seq is not None else '(n/a)'}")
        for p in r.problems:
            print(f"PROBLEM: {_safe(p, 500)}")
        print(f"FAILED: {len(r.problems)} problem(s) in {_safe(ns.db, 200)} (events {r.n_events}, anchor {r.anchor}, "
              f"checkpoints {'ok' if r.checkpoints_ok else 'BAD'}, {'keyed' if r.keyed else 'unkeyed'})")
        return 1
    print(f"OK: {r.n_events} events, checkpoints ok, anchor {r.anchor}, {'keyed' if r.keyed else 'unkeyed'}")
    return 0


def _open_ro(ns):
    key, err = _key(ns) if hasattr(ns, "key_env") else (None, None)
    if err:
        raise EL.EventLogError(err)
    return EL.EventStore.open_readonly(ns.db, key=key)


def _warn_if_broken(ns) -> None:
    try:
        r = EL.verify_file(ns.db)
    except EL.EventLogError:
        return
    if not r.ok:
        print(f"WARNING: the log does not verify (first bad seq {r.first_bad_seq}); run `verify` - what follows may be tampered",
              file=sys.stderr)


def _describe(e: EL.Event) -> "list[str]":
    p = e.payload if isinstance(e.payload, dict) else {}
    head = f"[{e.seq}] {_fmt_ts(e.ts)}"
    if e.kind == "call_proposed":
        lines = [f"{head} PROPOSED call {_safe(e.call_id, 80)}: {_safe(p.get('server'), 80)}.{_safe(p.get('tool'), 80)} "
                 f"args={_safe(p.get('args'), 300)} auto={_safe(p.get('auto'), 10)}"]
        for a in p.get("alerts") or []:
            if isinstance(a, dict):
                lines.append(f"      alert: {_safe(a.get('severity'), 20)} {_safe(a.get('trigger'), 60)} "
                             f"score={_safe(a.get('score'), 20)} threshold={_safe(a.get('threshold'), 20)} {_safe(a.get('message'), 200)}")
            else:
                lines.append(f"      alert: {_safe(a, 200)}")
        if isinstance(p.get("policy"), dict):
            pol = p["policy"]
            lines.append(f"      policy: {_safe(pol.get('verdict'), 20)} rule={_safe(pol.get('rule_id'), 80)} digest={_safe(pol.get('digest'), 20)}")
        return lines
    if e.kind == "decision":
        extra = f" rule={_safe(p.get('rule_id'), 80)}" if p.get("rule_id") else ""
        return [f"{head} DECISION call {_safe(e.call_id, 80)}: {_safe(p.get('decision'), 20).upper()} "
                f"(reason {_safe(p.get('reason'), 40)}, by {_safe(p.get('actor'), 20)}){extra}"]
    if e.kind == "call_result":
        return [f"{head} RESULT call {_safe(e.call_id, 80)}: {_safe(p.get('status'), 20)} {_safe(p.get('summary'), 200)}"]
    if e.kind == "proxy_hello":
        return [f"{head} SESSION START servers={_safe(p.get('servers'), 200)} auto_approve={_safe(p.get('auto_approve'), 10)} "
                f"monitor={_safe(p.get('monitor_mode'), 40)} policy={_safe(p.get('policy_digest'), 20)}"]
    if e.kind == "proxy_close":
        return [f"{head} SESSION END reason={_safe(p.get('reason'), 80)}"]
    return [f"{head} {_safe(e.kind, 40).upper()} {_safe(p, 200)}"]


def cmd_show(ns) -> int:
    try:
        store = _open_ro(ns)
    except EL.EventLogError as e:
        return _err(str(e))
    _warn_if_broken(ns)
    n = 0
    try:
        for e in store.events(session_id=ns.session):
            if ns.call is not None and e.call_id != ns.call:
                continue
            n += 1
            for line in _describe(e):
                print(line)
    except EL.EventLogError as e:
        return _err(str(e))
    finally:
        store.close()
    if n == 0:
        print(f"no events for session {_safe(ns.session, 100)}" + (f" call {_safe(ns.call, 100)}" if ns.call is not None else ""),
              file=sys.stderr)
        return 1
    return 0


def cmd_export(ns) -> int:
    try:
        store = _open_ro(ns)
    except EL.EventLogError as e:
        return _err(str(e))
    _warn_if_broken(ns)
    try:
        for e in store.events(session_id=ns.session):
            print(json.dumps({"seq": e.seq, "ts": e.ts, "session_id": e.session_id, "call_id": e.call_id, "kind": e.kind,
                              "payload": e.payload, "prev_hash": e.prev_hash, "hash": e.hash}, ensure_ascii=True, sort_keys=True))
    except EL.EventLogError as e:
        return _err(str(e))
    except BrokenPipeError:
        return 0
    finally:
        store.close()
    return 0


def run_policy_test(pol, store, registry=None, session=None) -> dict:
    """Evaluate every LOGGED proposal (with its own server name and recorded alerts) and compare with what actually happened."""
    decisions: dict = {}
    props: list = []
    for e in store.events(session_id=session):
        if e.kind == "call_proposed":
            props.append(e)
        elif e.kind == "decision":
            decisions[(e.session_id, e.call_id)] = e.payload
    verdicts = {"allow": 0, "deny": 0, "ask": 0}
    by_label: dict = {}
    hits: dict = {}
    viol_allowed = benign_asked = 0
    cmp = {"human_decided": 0, "agree": 0, "policy_would_allow_a_denied_call": 0, "policy_would_deny_an_approved_call": 0,
           "policy_would_ask": 0, "not_human_decided": 0}
    risky: list = []
    for e in props:
        p = e.payload if isinstance(e.payload, dict) else {}
        server = p.get("server") if isinstance(p.get("server"), str) else ""
        d = pol.evaluate(server, p.get("tool"), p.get("args"), registry=registry, alerts_present=bool(p.get("alerts")))
        dec = decisions.get((e.session_id, e.call_id))
        human = dec.get("decision") if isinstance(dec, dict) and dec.get("actor") == "human" else None
        label = {"approve": "ok", "deny": "violation"}.get(human, "unlabeled")
        verdicts[d.verdict] += 1
        by_label.setdefault(label, {"allow": 0, "deny": 0, "ask": 0})[d.verdict] += 1
        key = d.rule_id or "(default)"
        hits[key] = hits.get(key, 0) + 1
        if d.verdict == "allow" and label in VIOLATING_LABELS:
            viol_allowed += 1
            risky.append({"session_id": e.session_id, "call_id": e.call_id, "tool": p.get("tool"), "rule_id": d.rule_id})
        if d.verdict == "ask" and label in BENIGN_LABELS:
            benign_asked += 1
        if human is None:
            cmp["not_human_decided"] += 1
            continue
        cmp["human_decided"] += 1
        if d.verdict == "ask":
            cmp["policy_would_ask"] += 1
        elif (d.verdict == "allow") == (human == "approve"):
            cmp["agree"] += 1
        elif d.verdict == "allow":
            cmp["policy_would_allow_a_denied_call"] += 1
        else:
            cmp["policy_would_deny_an_approved_call"] += 1
    return {
        "policy_digest": pol.digest(), "proposals": len(props), "verdicts": verdicts,
        "by_label": {k: by_label[k] for k in sorted(by_label)},
        "rule_hits": dict(sorted(hits.items(), key=lambda kv: (-kv[1], kv[0]))),
        "violating_allowed": viol_allowed, "benign_asked": benign_asked,
        "comparison": cmp, "would_allow_denied": risky[:20],
    }


def cmd_policy_test(ns) -> int:
    pol, code = _policy_or_exit(ns.policy)
    if pol is None:
        return code
    reg, err = _load_registry(ns.registry)
    if err:
        return _err(err)
    try:
        store = _open_ro(ns)
    except EL.EventLogError as e:
        return _err(str(e))
    _warn_if_broken(ns)
    try:
        out = run_policy_test(pol, store, reg, ns.session)
    except EL.EventLogError as e:
        return _err(str(e))
    finally:
        store.close()
    if ns.json:
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    v, c = out["verdicts"], out["comparison"]
    print(f"policy {_safe(ns.policy, 200)} (digest {out['policy_digest']}) on {_safe(ns.db, 200)}: {out['proposals']} logged proposals")
    print("labels: ok = a human approved, violation = a human denied, unlabeled = no human decision (auto / policy / restart / pending)")
    print("args are the stored (redacted) form; each proposal is evaluated with its logged server name and alerts")
    print(f"overall: allow {v['allow']}  deny {v['deny']}  ask {v['ask']}")
    print(f"{'label':14} {'allow':>6} {'deny':>6} {'ask':>6}")
    for label, row in out["by_label"].items():
        print(f"{label:14} {row['allow']:>6} {row['deny']:>6} {row['ask']:>6}")
    print("rule hits:")
    for rid, n in out["rule_hits"].items():
        print(f"  {n:>5}  {_safe(rid, 80)}")
    print(f"violating proposals the policy would ALLOW: {out['violating_allowed']}")
    print(f"benign proposals the policy would ASK: {out['benign_asked']}")
    print("human decisions vs policy:")
    print(f"  human-decided calls: {c['human_decided']} (not human-decided: {c['not_human_decided']})")
    print(f"  agreement (policy allow = human approve, policy deny = human deny): {c['agree']}")
    print(f"  policy would auto-allow a call the human DENIED: {c['policy_would_allow_a_denied_call']}")
    print(f"  policy would deny a call the human approved: {c['policy_would_deny_an_approved_call']}")
    print(f"  policy would still ask the human: {c['policy_would_ask']}")
    for r in out["would_allow_denied"]:
        print(f"    ! session {_safe(r['session_id'], 60)} call {_safe(r['call_id'], 60)} tool {_safe(r['tool'], 60)} "
              f"allowed by {_safe(r['rule_id'] or '(default)', 60)}")
    return 0


def main(argv=None) -> int:
    ap = _Args(prog="eventlog_cli", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Args)
    p = sub.add_parser("verify", help="verify the hash chain, checkpoints and anchor file")
    p.add_argument("db")
    p.add_argument("--key-env", default=EL.KEY_ENV, help="environment variable holding the HMAC key (default SENTINEL_LOG_KEY)")
    p.add_argument("--anchor", help="anchor file (default <db>.anchor)")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("show", help="timeline of one session (or one call)")
    p.add_argument("db")
    p.add_argument("--session", required=True)
    p.add_argument("--call")
    p.set_defaults(fn=cmd_show)
    p = sub.add_parser("export", help="one JSON object per event")
    p.add_argument("db")
    p.add_argument("--jsonl", action="store_true", required=True)
    p.add_argument("--session")
    p.set_defaults(fn=cmd_export)
    p = sub.add_parser("policy-test", help="evaluate the logged proposals with a policy")
    p.add_argument("db")
    p.add_argument("policy")
    p.add_argument("--registry")
    p.add_argument("--session")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_policy_test)
    try:
        ns = ap.parse_args(argv)
        return ns.fn(ns)
    except BrokenPipeError:
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2


if __name__ == "__main__":
    sys.exit(main())
