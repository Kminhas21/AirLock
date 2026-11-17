#!/usr/bin/env python
"""Card noise: how often would the approval card (an `ask` decision) fire for a human operator?

    python scripts/card_noise.py --traces eval/traces_v3/*.json [--only-label ok]
    python scripts/card_noise.py --claude-projects ~/.claude/projects          # real Claude Code transcripts, read locally
    python scripts/card_noise.py ... [--policy builtin:starter] [--json]

Replays tool calls through `Policy.evaluate_call` (the starter's rules AND the D31 confinement floors, as the hub decides a proxied call) twice:
SANDBOXED (confinable servers: path allows are kernel-confined and stay allowed) and UNSANDBOXED (path allows ask: `unconfinable`).
Counts allow / ask / deny per tool and per rule, cards per 100 calls and per session, and the cause of every ask:
  rule:<id>      an explicit ask rule (the starter's sensitive-path rules)        default       no rule matched, the policy default is ask
  unconfined     an allow floored because its rule has no `confine` map or the call has a path argument outside it
  unconfinable   an allow floored because the server cannot be confined (unsandboxed server)
  write_unsupported   a doc write floored because the replay cannot know the file exists (D32; --assume-writes-confinable is the ceiling)
  alert / secrets / engine_error / rule_error:<id>   escalations and fail-closed paths

Claude Code tool names are MAPPED to the MCP-style tools the starter knows (MAPPING below); this is an approximation, not the MCP filesystem server:
  approx   Read, Glob, Grep  -> read_file / search_files (Grep searches file CONTENTS, search_files matches NAMES; a missing path is ".")
  analog   Write, Edit, NotebookEdit, Bash, WebFetch, WebSearch -> write_file, edit_file, start_process, fetch, web_search: the starter has no allow
           rule for those tools, so the verdict is the default ask whatever the arguments
  direct   mcp__<server>__<tool> calls: server, tool and arguments as logged
  not representable (counted, never evaluated): harness-internal tools (Agent, Monitor, SendMessage, ToolSearch, Skill, task and plan tools ...)
Nothing but counts, rule ids and tool names is ever printed: no paths, arguments, file names or third-party tool names.
Exit codes: 0 ok, 2 bad arguments or an unreadable corpus."""
from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO), str(REPO / "server")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import policy as P  # noqa: E402

load_policy = P.load_policy


def _fp(i, *keys):
    """The first string value among the keys (Claude Code spells a file argument file_path, some tool variants path)."""
    for k in keys or ("file_path", "path"):
        if isinstance(i.get(k), str):
            return i[k]
    return ""


def _read_args(i):
    a = {"path": _fp(i)}
    if "offset" in i:
        a["offset"] = i["offset"]
    if "limit" in i:
        a["length"] = i["limit"]
    return a


# Claude Code tool -> (mapped tool, fidelity, argument mapper)
MAPPING = {
    "Read": ("read_file", "approx", _read_args),
    "Glob": ("search_files", "approx", lambda i: {"path": i.get("path") or ".", "pattern": i.get("pattern")}),
    "Grep": ("search_files", "approx", lambda i: {"path": i.get("path") or ".", "pattern": i.get("pattern")}),
    "Write": ("write_file", "analog", lambda i: {"path": _fp(i), "content": i.get("content") or i.get("file_text") or ""}),
    "Edit": ("edit_file", "analog", lambda i: {"path": _fp(i), "edits": []}),
    "NotebookEdit": ("edit_file", "analog", lambda i: {"path": _fp(i, "notebook_path", "path"), "edits": []}),
    "Bash": ("start_process", "analog", lambda i: {"command": i.get("command")}),
    "WebFetch": ("fetch", "analog", lambda i: {"url": i.get("url")}),
    "WebSearch": ("web_search", "analog", lambda i: {"query": i.get("query")}),
}


def map_claude_call(name, inp):
    """A call dict for a Claude Code tool_use, or None when it is not representable (a harness-internal tool or an unknown name)."""
    inp = inp if isinstance(inp, dict) else {}
    if isinstance(name, str) and name.startswith("mcp__"):
        parts = name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return {"server": parts[1], "tool": parts[2], "args": inp, "display": "mcp:other", "fidelity": "direct", "label": None}
        return None
    m = MAPPING.get(name)
    if m is None:
        return None
    tool, fid, fn = m
    return {"server": "", "tool": tool, "args": fn(inp), "display": f"{name}->{tool}", "fidelity": fid, "label": None}


# ---- loaders ---------------------------------------------------------------------------------------------------------------

def load_traces(paths):
    """Eval traces (a JSON list of {id, steps:[{proposal:{tool,args,label}}]}): one session per trace. Raises ValueError."""
    files = []
    for p in paths:
        files += sorted(glob.glob(os.path.join(p, "*.json"))) if os.path.isdir(p) else [p]
    out = []
    for f in files:
        try:
            with open(f, "rb") as fh:
                data = json.loads(fh.read().decode("utf-8"))
        except (OSError, ValueError) as e:
            raise ValueError(f"cannot read {os.path.basename(f)}: {type(e).__name__}")
        if not isinstance(data, list):
            raise ValueError(f"{os.path.basename(f)}: expected a JSON list of traces")
        for n, t in enumerate(data):
            calls = []
            for s in (t.get("steps") or []) if isinstance(t, dict) else []:
                p = s.get("proposal") if isinstance(s, dict) else None
                if isinstance(p, dict) and isinstance(p.get("tool"), str):
                    lab = p.get("label")
                    calls.append({"server": "", "tool": p["tool"], "args": p.get("args"), "display": p["tool"], "fidelity": "direct",
                                  "label": lab if isinstance(lab, str) else None})
            out.append((str(t.get("id", f"trace{n}")) if isinstance(t, dict) else f"trace{n}", calls))
    return out


def load_claude_transcripts(root):
    """(sessions, excluded): one session per transcript file with at least one representable call; tool_use ids are deduplicated across files
    (a resumed session repeats earlier entries). Session ids are numbers, never file names. Raises ValueError for a missing directory."""
    if not os.path.isdir(root):
        raise ValueError("not a directory")
    seen, sessions, excluded = set(), [], 0
    for f in sorted(Path(root).rglob("*.jsonl")):
        calls = []
        try:
            fh = open(f, "r", encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                msg = o.get("message") if isinstance(o, dict) else None
                content = msg.get("content") if isinstance(msg, dict) else None
                if not isinstance(content, list):
                    continue
                for b in content:
                    if not (isinstance(b, dict) and b.get("type") == "tool_use"):
                        continue
                    key = b.get("id")
                    if key is not None:
                        if key in seen:
                            continue
                        seen.add(key)
                    c = map_claude_call(b.get("name"), b.get("input"))
                    if c is None:
                        excluded += 1
                    else:
                        calls.append(c)
        if calls:
            sessions.append((f"s{len(sessions) + 1}", calls))
    return sessions, excluded


def filter_label(sessions, label):
    kept = [(sid, [c for c in calls if c.get("label") == label]) for sid, calls in sessions]
    return [(sid, calls) for sid, calls in kept if calls]


# ---- measurement ---------------------------------------------------------------------------------------------------------

def _bump(d, k, n=1):
    d[k] = d.get(k, 0) + n


def measure(pol, sessions, *, confinable, write_confinable=False):
    verdicts = {"allow": 0, "ask": 0, "deny": 0}
    by_tool, causes, ask_rules, allow_rules, deny_rules, unconfinable_by_rule, by_fid = {}, {}, {}, {}, {}, {}, {}
    per_session, calls_n = [], 0
    for _sid, calls in sessions:
        asks = 0
        for c in calls:
            d = pol.evaluate_call(c["server"], c["tool"], c["args"], confinable=confinable, write_confinable=write_confinable, registry=None,
                                  alerts_present=False)
            calls_n += 1
            verdicts[d.verdict] += 1
            t = by_tool.setdefault(c["display"], {"allow": 0, "ask": 0, "deny": 0})
            t[d.verdict] += 1
            f = by_fid.setdefault(c["fidelity"], {"calls": 0, "asks": 0})
            f["calls"] += 1
            if d.verdict == "allow":
                _bump(allow_rules, d.rule_id or "(default)")
            elif d.verdict == "deny":
                _bump(deny_rules, d.rule_id or "(default)")
            else:
                asks += 1
                f["asks"] += 1
                _bump(causes, d.reason)
                if d.reason.startswith("rule:"):
                    _bump(ask_rules, d.rule_id)
                elif d.reason == "unconfinable":
                    _bump(unconfinable_by_rule, d.rule_id or "(default)")
        per_session.append(asks)
    n = len(per_session)
    return {
        "calls": calls_n, "verdicts": verdicts,
        "asks_per_100_calls": round(100.0 * verdicts["ask"] / calls_n, 1) if calls_n else 0.0,
        "sessions": n, "sessions_with_a_card": sum(1 for a in per_session if a),
        "asks_per_session": {"mean": round(statistics.mean(per_session), 1) if n else 0, "median": statistics.median(per_session) if n else 0,
                             "max": max(per_session) if n else 0, "zero": sum(1 for a in per_session if not a)},
        "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -sum(kv[1].values()))),
        "by_fidelity": by_fid, "causes": dict(sorted(causes.items(), key=lambda kv: -kv[1])),
        "ask_rules": dict(sorted(ask_rules.items(), key=lambda kv: -kv[1])), "allow_rules": dict(sorted(allow_rules.items(), key=lambda kv: -kv[1])),
        "deny_rules": deny_rules, "unconfinable_by_rule": dict(sorted(unconfinable_by_rule.items(), key=lambda kv: -kv[1])),
    }


# ---- report ----------------------------------------------------------------------------------------------------------------

def _fmt_mode(title, r):
    v = r["verdicts"]
    s = r["asks_per_session"]
    L = [f"  {title}: {r['calls']} calls: allow {v['allow']}  ask {v['ask']}  deny {v['deny']}",
         f"    cards per 100 calls: {r['asks_per_100_calls']}   per session: mean {s['mean']}, median {s['median']}, max {s['max']}; "
         f"{r['sessions_with_a_card']} of {r['sessions']} sessions saw a card ({s['zero']} none)"]
    if r["causes"]:
        L.append("    asks by cause: " + ", ".join(f"{k} {n}" for k, n in r["causes"].items()))
    if r["unconfinable_by_rule"]:
        L.append("    unconfinable asks by allow rule: " + ", ".join(f"{k} {n}" for k, n in r["unconfinable_by_rule"].items()))
    if r["by_fidelity"]:
        L.append("    by mapping fidelity (calls/asks): " + ", ".join(f"{k} {x['calls']}/{x['asks']}" for k, x in sorted(r["by_fidelity"].items())))
    L.append("    by tool (allow/ask/deny): " + ", ".join(f"{k} {x['allow']}/{x['ask']}/{x['deny']}" for k, x in list(r["by_tool"].items())[:12]))
    return L


def render(report):
    out = [f"card noise, policy digest {report['policy_digest']}"]
    for c in report["corpora"]:
        out.append(f"corpus {c['name']}: {c['sessions']} sessions, {c['calls']} evaluated calls"
                   + (f", {c['excluded']} harness-internal calls not representable (not evaluated)" if c.get("excluded") is not None else ""))
        out += _fmt_mode("sandboxed servers (path allows confined)", c["sandboxed"])
        out += _fmt_mode("unsandboxed servers (path allows ask: unconfinable)", c["unsandboxed"])
    return "\n".join(out)


def build_report(pol, corpora, write_confinable=False):
    rep = {"policy_digest": pol.digest(), "corpora": []}
    for name, sessions, excluded in corpora:
        rep["corpora"].append({"name": name, "sessions": len(sessions), "calls": sum(len(c) for _, c in sessions), "excluded": excluded,
                               "sandboxed": measure(pol, sessions, confinable=True, write_confinable=write_confinable),
                               "unsandboxed": measure(pol, sessions, confinable=False, write_confinable=write_confinable)})
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(description="how often would the approval card fire (policy replay)")
    ap.add_argument("--traces", nargs="+", help="eval trace JSON files or directories")
    ap.add_argument("--claude-projects", help="a Claude Code projects directory of *.jsonl transcripts (read locally, aggregate output only)")
    ap.add_argument("--policy", default="builtin:starter")
    ap.add_argument("--only-label", help="eval traces: keep only proposals with this label (ok = benign)")
    ap.add_argument("--assume-writes-confinable", action="store_true",
                    help="the CEILING for D32: assume every file a write names exists and the proxy vouched for it (default: no write is confinable)")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)
    if not ns.traces and not ns.claude_projects:
        print("card_noise: give --traces and/or --claude-projects", file=sys.stderr)
        return 2
    try:
        pol = load_policy(ns.policy)
        corpora = []
        if ns.traces:
            s = load_traces(ns.traces)
            corpora.append(("eval-traces" + (f" (label {ns.only_label})" if ns.only_label else ""),
                            filter_label(s, ns.only_label) if ns.only_label else s, None))
        if ns.claude_projects:
            s, excl = load_claude_transcripts(ns.claude_projects)
            corpora.append(("claude-transcripts", s, excl))
    except (ValueError, P.PolicyError) as e:
        print(f"card_noise: {e}", file=sys.stderr)
        return 2
    rep = build_report(pol, corpora, ns.assume_writes_confinable)
    print(json.dumps(rep, indent=2) if ns.json else render(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
