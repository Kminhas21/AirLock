"""Operator CLI for the event log (docs/plans/EVENT-LOG.md, ticket EL2).

    python -m eventlog_cli verify <db> [--key-env SENTINEL_LOG_KEY] [--anchor PATH]
    python -m eventlog_cli show <db> --session S [--call C]
    python -m eventlog_cli export <db> --jsonl [--session S]
    python -m eventlog_cli policy-test <db> <policy.json> [--registry reg.json] [--session S] [--json]
    python -m eventlog_cli replay <db> --session S [--monitor rules|action_sim] [--json]
    python -m eventlog_cli rotate <db> [--archive-dir DIR] [--key-env NAME]     (hub STOPPED)
    (verify also takes --previous ARCHIVE_DB: check the link to a rotated-out log)

Run from the server/ directory (or with server/ on PYTHONPATH).  Every command opens the log READ-ONLY (nothing is created,
appended or recovered).  Exit status: 0 ok, 1 problems found (verify: tamper / inconsistencies; show: nothing matched;
policy-test: policy errors; replay: no proposals), 2 unreadable file / bad arguments.  Never a traceback for bad input.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import sqlite3
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


def _head_of(path, key, anchor=None):
    """(seq, hash) of the head of a log that verifies; raises EventLogError otherwise."""
    r = EL.verify_file(path, key=key, anchor_path=anchor)
    if not r.ok:
        raise EL.EventLogError(f"{path} does not verify (first bad seq {r.first_bad_seq}): {'; '.join(r.problems[:3])}")
    s = EL.EventStore.open_readonly(path, key=key)
    try:
        return s._head()
    finally:
        s.close()


def _first_events(db, key, n=2) -> list:
    s = EL.EventStore.open_readonly(db, key=key)
    try:
        return list(s.events(limit=n))
    finally:
        s.close()


def _link_problems(db, prev, key) -> list:
    """Problems with the claim 'the log at <db> continues the archive <prev>' (the log itself is verified separately)."""
    link = next((e for e in _first_events(db, key, 10) if e.kind == "log_continues"), None)
    if link is None:
        return [f"{db} has no log_continues event: it does not claim to continue {prev}"]
    try:
        seq, h = _head_of(prev, key)
    except EL.EventLogError as e:
        return [f"previous log: {e}"]
    p = link.payload if isinstance(link.payload, dict) else {}
    if (p.get("head_seq"), p.get("head_hash")) != (seq, h):
        return [f"previous log {prev} (head seq {seq}) does not match the log_continues event (head seq {p.get('head_seq')}): wrong or altered archive"]
    return []


def cmd_verify(ns) -> int:
    key, err = _key(ns)
    if err:
        return _err(err)
    try:
        r = EL.verify_file(ns.db, key=key, anchor_path=ns.anchor)
        extra = _link_problems(ns.db, ns.previous, key) if ns.previous else []
        first = _first_events(ns.db, key) if r.ok and not ns.previous else []
    except EL.EventLogError as e:
        return _err(str(e))
    for n in r.notes:
        print(f"NOTE:  {_safe(n, 500)}")
    if len(first) == 2 and first[1].kind == "log_continues" and isinstance(first[1].payload, dict):
        print(f"NOTE:  earlier history is in {_safe(first[1].payload.get('previous_file'), 200)}; pass --previous to check the link")
    if not r.ok or extra:
        print(f"FIRST BAD SEQ: {r.first_bad_seq if r.first_bad_seq is not None else '(n/a)'}")
        for p in r.problems + extra:
            print(f"PROBLEM: {_safe(p, 500)}")
        print(f"FAILED: {len(r.problems) + len(extra)} problem(s) in {_safe(ns.db, 200)} (events {r.n_events}, anchor {r.anchor}, "
              f"checkpoints {'ok' if r.checkpoints_ok else 'BAD'}, {'keyed' if r.keyed else 'unkeyed'})")
        return 1
    print(f"OK: {r.n_events} events, checkpoints ok, anchor {r.anchor}, {'keyed' if r.keyed else 'unkeyed'}"
          + (f"; continues {_safe(ns.previous, 200)} (verified, head matches)" if ns.previous else ""))
    return 0


def _archive_locked(ns, key, conn):
    """With the log exclusively locked (nobody can append): verify it, then move db + anchor to the archive name.  Returns
    (dest, head_seq, head_hash).  Raises EventLogError (message says what state things are in); on a failed move it rolls back."""
    try:
        was_keyed = bool(json.loads(conn.execute("SELECT payload FROM events WHERE seq = 1").fetchone()[0]).get("keyed"))
    except (sqlite3.Error, TypeError, ValueError, AttributeError) as e:
        raise EL.EventLogError(f"cannot read the log_open event ({e}); nothing was moved")
    if was_keyed != (key is not None):
        raise EL.EventLogError(f"the log is {'keyed' if was_keyed else 'unkeyed'} but {ns.key_env} is {'set' if key else 'not set'}: "
                               f"a log and the one that continues it must both be keyed with the same key (or both unkeyed); nothing was moved")
    r = EL.verify_file(ns.db, key=key)
    if not r.ok:
        raise EL.EventLogError(f"{ns.db} does not verify (first bad seq {r.first_bad_seq}): {'; '.join(r.problems[:3])}; nothing was moved")
    seq, h = conn.execute("SELECT seq, hash FROM head WHERE id = 1").fetchone()
    dest_dir = ns.archive_dir or os.path.dirname(os.path.abspath(ns.db))
    if not os.path.isdir(dest_dir):
        raise EL.EventLogError(f"archive directory {dest_dir} does not exist; nothing was moved")
    stem = os.path.splitext(os.path.basename(ns.db))[0]
    dest = os.path.join(dest_dir, f"{stem}-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')}-seq{seq}.db")
    pairs = [(ns.db, dest)] + ([(ns.db + ".anchor", dest + ".anchor")] if os.path.exists(ns.db + ".anchor") else [])
    if os.path.exists(ns.db + "-wal") and os.path.getsize(ns.db + "-wal"):
        raise EL.EventLogError("the log has unfolded WAL data (another reader/writer?); stop the hub; nothing was moved")
    claimed = []
    try:                                    # exclusive creation = never overwrite an existing archive (race-free)
        for _, dst in pairs:
            open(dst, "x").close()
            claimed.append(dst)
    except OSError as e:
        for dst in claimed:
            os.remove(dst)
        raise EL.EventLogError(f"{dest} or its anchor already exists or cannot be created ({e}); nothing was moved")
    moved = []
    try:
        for src, dst in pairs:
            shutil.move(src, dst)
            moved.append((src, dst))
            os.chmod(dst, 0o600)
    except OSError as e:
        for src, dst in reversed(moved):
            try:
                shutil.move(dst, src)
            except OSError:
                pass
        for dst in claimed:
            if os.path.exists(dst) and os.path.getsize(dst) == 0:
                os.remove(dst)
        left = [dst for _, dst in moved if os.path.exists(dst)]
        raise EL.EventLogError(f"moving the log failed ({e}); rolled back" + (f", but {', '.join(left)} could not be moved back" if left else "; nothing was moved"))
    return dest, seq, h


def cmd_rotate(ns) -> int:
    """Archive a verified, idle log and start a new one that records the archive's head (no event is ever deleted)."""
    key, err = _key(ns)
    if err:
        return _err(err)
    if not os.path.isfile(ns.db):
        print(f"REFUSED: cannot read {_safe(ns.db, 300)}: no such file; nothing was moved", file=sys.stderr)
        return 1
    try:                                    # fold the WAL in, then take the exclusive lock and KEEP it until the files are moved
        conn = sqlite3.connect(ns.db, timeout=1, isolation_level=None)
    except sqlite3.Error as e:
        return _err(f"cannot open {ns.db}: {e}")
    try:
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("BEGIN EXCLUSIVE")
        except sqlite3.OperationalError as e:
            raise EL.EventLogError(f"the log looks in use ({e}); stop the hub first; nothing was moved")
        except sqlite3.DatabaseError as e:
            raise EL.EventLogError(f"{ns.db} is not a readable log ({e}); nothing was moved")
        dest, seq, h = _archive_locked(ns, key, conn)
    except EL.EventLogError as e:
        print(f"REFUSED: {_safe(e, 700)}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    try:
        store = EL.EventStore(ns.db, key=key)
        store.open()
        try:
            store.append("log_continues", payload={"previous_file": os.path.basename(dest), "head_seq": seq, "head_hash": h})
        finally:
            store.close()
    except (OSError, EL.EventLogError) as e:
        return _err(f"the old log was archived to {dest} but creating the new log failed ({e}); the new log has no log_continues event")
    print(f"rotated {_safe(ns.db, 200)} (head seq {seq}) to {_safe(dest, 300)}; new log started")
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


def run_replay(store, session, factory) -> dict:
    """Feed the LOGGED proposals of one session, in order, through a fresh monitor; the logged decisions are fed back like live."""
    mon, calls, seen = factory.new_session(), [], {}
    for e in store.events(session_id=session):
        p = e.payload if isinstance(e.payload, dict) else {}
        if e.kind == "call_proposed" and isinstance(p.get("args"), dict) and isinstance(p.get("tool"), str):
            alerts = [{"severity": a.get("severity"), "trigger": a.get("trigger"), "score": a.get("drift_score"), "threshold": a.get("threshold")}
                      for a in mon.on_proposal("", p["tool"], p["args"], str(e.call_id)) if isinstance(a, dict)]
            seen[e.call_id] = {"seq": e.seq, "tool": p["tool"], "args": p["args"], "decision": None, "actor": None, "alerts": alerts}
            calls.append(seen[e.call_id])
        elif e.kind == "decision" and e.call_id in seen and p.get("decision") in ("approve", "deny"):
            c = seen[e.call_id]
            c["decision"], c["actor"] = p["decision"], p.get("actor")
            if p.get("reason") == "cancelled":      # the live hub registers no monitor decision for a proxy_cancel
                continue
            mon.register_decision(c["tool"], c["args"], c["decision"])
    approved = sum(1 for c in calls if c["alerts"] and c["decision"] == "approve" and c["actor"] == "human")
    return {"session": session, "mode": factory.mode, "requested": factory.requested, "fallback_reason": factory.reason,
            "calls": [{**{k: c[k] for k in ("seq", "tool", "decision", "actor", "alerts")}, "preview": _safe(c["args"], 80)} for c in calls],
            "summary": {"proposals": len(calls), "alerts": sum(len(c["alerts"]) for c in calls), "alert_but_human_approved": approved}}


def cmd_replay(ns) -> int:
    import proposal_monitor as pm
    factory = pm._resolve({**os.environ, pm.MODE_ENV: ns.monitor}) if ns.monitor else pm.get_monitor_factory()
    try:
        store = _open_ro(ns)
    except EL.EventLogError as e:
        return _err(str(e))
    _warn_if_broken(ns)
    try:
        out = run_replay(store, ns.session, factory)
    except EL.EventLogError as e:
        return _err(str(e))
    finally:
        store.close()
    if not out["calls"]:
        print(f"no proposals for session {_safe(ns.session, 100)}", file=sys.stderr)
        return 1
    if ns.json:
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    note = f" (requested {_safe(out['requested'], 40)}; FELL BACK: {_safe(out['fallback_reason'], 200)})" if out["mode"] != out["requested"] else ""
    print(f"replay of session {_safe(ns.session, 100)} from {_safe(ns.db, 200)}\nmonitor: {_safe(out['mode'], 40)}{note}")
    for c in out["calls"]:
        print(f"[{c['seq']}] {_safe(c['tool'], 80)} {_safe(c['preview'], 80)}  logged: {_safe(c['decision'] or 'none', 10)} by {_safe(c['actor'] or '-', 20)}"
              f"  alerts now: {len(c['alerts'])}")
        for a in c["alerts"]:
            print(f"      alert: {_safe(a['severity'], 20)} {_safe(a['trigger'], 60)} score={_safe(a['score'], 20)} threshold={_safe(a['threshold'], 20)}")
    s = out["summary"]
    print(f"summary: {s['proposals']} proposals, {s['alerts']} alerts, {s['alert_but_human_approved']} alert(s) where a human approved")
    return 0


def main(argv=None) -> int:
    ap = _Args(prog="eventlog_cli", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Args)
    p = sub.add_parser("verify", help="verify the hash chain, checkpoints and anchor file")
    p.add_argument("db")
    p.add_argument("--key-env", default=EL.KEY_ENV, help="environment variable holding the HMAC key (default SENTINEL_LOG_KEY)")
    p.add_argument("--anchor", help="anchor file (default <db>.anchor)")
    p.add_argument("--previous", help="archive written by `rotate`: also verify it and check the link to this log")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("rotate", help="archive the log and start a new one (hub must be stopped)")
    p.add_argument("db")
    p.add_argument("--archive-dir", help="default: the log's directory")
    p.add_argument("--key-env", default=EL.KEY_ENV)
    p.set_defaults(fn=cmd_rotate)
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
    p = sub.add_parser("replay", help="re-run one logged session through the monitors")
    p.add_argument("db")
    p.add_argument("--session", required=True)
    p.add_argument("--monitor", choices=["rules", "action_sim"], help="default: the live hub's choice (SENTINEL_MONITOR)")
    p.add_argument("--key-env", default=EL.KEY_ENV)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_replay)
    try:
        ns = ap.parse_args(argv)
        return ns.fn(ns)
    except BrokenPipeError:
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2


if __name__ == "__main__":
    sys.exit(main())
