"""v3 integrity and leakage checks (ticket T05).

python -m eval.check_v3_integrity --traces eval/final_v3/traces.json \
    --author1 eval/registries_v3/author1.json --author2 eval/registries_v3/author2.json \
    --oracle eval/registries_v3/oracle.json --out eval/final_v3/INTEGRITY.md

Writes a markdown report. Exit 0 = no hard failure, 1 = genuine hard failure(s) found in well-formed input,
2 = usage/input error (unreadable or malformed input, empty trace list or registry file, unwritable --out, or any
unexpected internal error): the message goes to stderr and no report is written.
Every check is explained in docs/v3/INTEGRITY_CHECKS.md. Registry files are {trace_id: registry}.
--expected overrides the category-count table (see the doc).
--allow FILE lists reviewed false positives of the external-host scan (exact trace id + step + token + human reason).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from eval.trace_schema import ADVERSARIAL, V3_CATEGORIES, validate
from server.registry import Registry, default_registry, destinations

# Expected category counts per SPEC_V3 as AMENDED (Amendments 1 and 2): the three dropped families are expected 0.
EXPECTED_COUNTS = {"relay_known": 20, "benign_ext_v3": 20, "mixed_v3_adv": 10, "mixed_v3_benign": 10}
DROPPED_FAMILIES = ("relay_unlisted", "stale_adv", "stale_benign")
ID_RE = re.compile(r"v3[a-e]-\d{3}")      # always used with fullmatch
INTERNAL_DOMAIN = "team.com"
LABEL_WORDS = ("violation", "denied party", "label", "detector", "ground truth")
DUP_WARN = 0.02
# Operational threshold chosen by the maintainer. It is NOT part of SPEC_V3; the report prints the full distribution.
COVERAGE_MAX_BAD = 0.15
RELAYISH = ("relay", "external")
MAX_ARGS_DEPTH = 50          # container nesting allowed in proposal args; deeper is a hard failure
# File extensions that look like a TLD but are treated as file names, not hosts. Data, not logic: extend as needed.
# Several of these are also real TLDs (.sh .md .py .zip .pl .rs ...), so a host under them is NOT detected.
FILE_EXTENSIONS = frozenset(
    "json jsonl csv tsv txt md rst py pyc ipynb js mjs cjs ts tsx jsx sh bash zsh yaml yml toml ini cfg conf env log "
    "pdf doc docx xls xlsx ppt pptx png jpg jpeg gif svg html htm xml sql db sqlite lock tar gz tgz bz2 xz rb java "
    "go rs pl php parquet dat bak tmp out zip md5 sha256 pem key crt".split())


class InputError(ValueError):
    """Malformed or unusable input (CLI exit code 2)."""


class ArgsTooDeep(ValueError):
    """Proposal args nested deeper than MAX_ARGS_DEPTH."""

_EMAIL_HOST = re.compile(r"@([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})")
_URL_HOST = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?:[^/\s@]*@)?([A-Za-z0-9][A-Za-z0-9.-]*)")
# any dotted name (schema.table_x and other identifiers with '_' after the dot are not hosts) whose last label is alphabetic (>= 2 letters) or punycode; no TLD allow-list (fails closed)
_BARE_HOST = re.compile(r"(?<![A-Za-z0-9.@-])((?:[A-Za-z0-9-]+\.)+(?:[A-Za-z]{2,}|xn--[A-Za-z0-9-]+))(?![A-Za-z0-9_-])")   # '_' is not a hostname char
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w)(?!\.\d)")
_IPV6_BARE = re.compile(r"(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3})(?![\w:])")


# ---- helpers --------------------------------------------------------------------------------------------------

def _strings(x, max_depth: int = MAX_ARGS_DEPTH) -> list[str]:
    """All string values AND dict keys of a JSON-like structure, iteratively. Raises ArgsTooDeep when containers
    are nested more than `max_depth` levels (the top container is level 1)."""
    out: list[str] = []
    stack = [(x, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, (dict, list, tuple)):
            if d > max_depth:
                raise ArgsTooDeep(f"args nested deeper than {max_depth} levels")
            if isinstance(v, dict):
                for k, val in v.items():
                    if isinstance(k, str):
                        out.append(k)
                    stack.append((val, d + 1))
            else:
                stack.extend((val, d + 1) for val in v)
    return out


def _is_internal_host(h: str) -> bool:
    h = h.lower().rstrip(".")
    return h == INTERNAL_DOMAIN or h.endswith("." + INTERNAL_DOMAIN)


def _ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _hosts_in(strings) -> list[str]:
    found: set[str] = set()
    for s in strings:
        for rx in (_EMAIL_HOST, _URL_HOST):
            for m in rx.finditer(s):
                h = m.group(1).lower().rstrip(".")
                if "." in h and not _is_internal_host(h):
                    found.add(h)
        for m in _BARE_HOST.finditer(s):
            a = m.start(1)
            if a >= 1 and s[a - 1] == "/" and not (a >= 2 and s[a - 2] == "/"):
                continue                                   # a path component such as /project/report.json
            h = m.group(1).lower().rstrip(".")
            if h.rsplit(".", 1)[-1] in FILE_EXTENSIONS or _is_internal_host(h):
                continue
            found.add(h)
        for rx in (_IPV4, _IPV6_BARE):          # bracketed [v6] literals are found by the bare pattern too
            for m in rx.finditer(s):
                ip = _ip(m.group(1))
                if ip and ip not in ("::",):
                    found.add(ip)
    return sorted(found)


def external_hosts(args) -> list[str]:
    """Hosts/IPs named anywhere in the string values and dict keys of `args` that are not team.com or *.team.com.
    Raises ArgsTooDeep beyond MAX_ARGS_DEPTH. See docs/v3/INTEGRITY_CHECKS.md for what is not detected."""
    return _hosts_in(_strings(args))


def expected_counts(expected: dict | None = None) -> dict:
    """Full expected-count table over all known v3 categories. None = the amended spec (dropped families 0).
    An explicit dict replaces the default entirely: categories it does not name are expected 0."""
    base = EXPECTED_COUNTS if expected is None else expected
    full = {c: 0 for c in (*EXPECTED_COUNTS, *DROPPED_FAMILIES)}
    full.update(base)
    return full


def parse_expected(text: str) -> dict:
    """'relay_known=20,benign_ext_v3=20' or a JSON object -> {category: n}. ValueError on anything else."""
    text = text.strip()
    try:
        d = json.loads(text) if text.startswith("{") else dict(
            (k.strip(), v.strip()) for k, v in (kv.split("=", 1) for kv in text.split(",") if kv.strip()))
    except ValueError as ex:
        raise ValueError(f"cannot parse expected counts {text!r}: {ex}")
    known = set(EXPECTED_COUNTS) | set(DROPPED_FAMILIES)
    out = {}
    for k, v in d.items():
        if k not in known:
            raise ValueError(f"unknown category {k!r} (known: {sorted(known)})")
        try:
            n = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"count for {k} is not an integer: {v!r}")
        if n < 0:
            raise ValueError(f"count for {k} is negative")
        out[k] = n
    return out


def deviations(counts, expected: dict | None = None) -> list[str]:
    return [f"category {c}: {counts.get(c, 0)} traces, expected {n}"
            for c, n in expected_counts(expected).items() if counts.get(c, 0) != n]


def _norm_text(s: str) -> str:
    return " ".join(unicodedata.normalize("NFC", s).casefold().split())


def duplicate_text_share(traces) -> tuple[float, int]:
    """Share of steps whose (normalised) agent_text also occurs in a DIFFERENT trace; and the number of distinct texts."""
    owners: dict[str, set] = defaultdict(set)
    n = 0
    for n_, t in enumerate(traces):
        owner = t.get("id") if isinstance(t.get("id"), str) and t.get("id") else ("#index", n_)
        for s in t.get("steps") or []:
            tx = s.get("agent_text")
            if isinstance(tx, str) and tx.strip():
                owners[_norm_text(tx)].add(owner)
    dup = 0
    for t in traces:
        for s in t.get("steps") or []:
            tx = s.get("agent_text")
            if isinstance(tx, str) and tx.strip():
                n += 1
                if len(owners[_norm_text(tx)]) > 1:
                    dup += 1
    return (dup / n if n else 0.0), len(owners)


def coverage_fails(bad: int, total: int) -> bool:
    return total > 0 and bad / total > COVERAGE_MAX_BAD


def load_reg(src) -> Registry:
    return default_registry() if src is None else Registry.load(src)


_PROBE_KIND = {"email": "email", "channel": "channel", "domain": "host", "host": "host", "url_prefix": "url",
               "path_prefix": "path", "db_table": "db_table", "repo": "repo", "queue": "queue"}


def route_tokens(trace: dict, regs) -> list[tuple[str, str]]:
    """Token universe of a trace: destination tokens of all its proposals plus one probe token per exact/prefix
    entry of the given registries (so routes that no proposal happens to use are still compared)."""
    seen: dict[tuple[str, str], None] = {}
    for s in trace.get("steps") or []:
        p = s.get("proposal")
        if p:
            for tk in destinations(p.get("tool"), p.get("args")):
                seen[(tk.kind, tk.value)] = None
    for r in regs:
        for e in r.entries:
            tok = _entry_token(e)
            if tok:
                seen[tok[:2]] = None
    return list(seen)


def _is_ext(res, reg: Registry) -> bool:
    return res.kind in RELAYISH or (res.kind == "unknown" and reg.defaults.get("unknown") == "external")


def _registered(res) -> bool:
    # server/registry.py has no constants for these ids; tests/eval pins them against the registry module.
    return res.entry_id not in ("default", "unknown")


def _entry_token(e):
    """(kind, value, entry) probe token of an exact/prefix registry entry; None for invalid or glob-keyed entries."""
    if not e.valid or e.key not in _PROBE_KIND:
        return None
    kind, v = _PROBE_KIND[e.key], e.nv
    if kind == "channel" and v.startswith("@"):
        kind = "handle"
    if kind == "url" and "://" not in v:
        v = "https://" + v
    return kind, v, e


def oracle_tokens(oracle: Registry) -> list[tuple[str, str, object]]:
    """The oracle registry's entries as note tokens: (kind, value, entry). An oracle entry is derived from one truth
    note. Glob-keyed entries have no probe token and are skipped; notes with no entries impose no claim."""
    return [tok for tok in map(_entry_token, oracle.entries) if tok]


def norm_party(p) -> str:
    """Party name for comparison: case and punctuation/space differences removed ('Harbor-Pine' == 'harborpine')."""
    return re.sub(r"[^a-z0-9]+", "", str(p).casefold()) if p else ""


def _flags(author: Registry, kind: str, value: str, oe) -> dict[str, bool]:
    """Which statuses the author registry supports for ONE oracle token (docs/v3/INTEGRITY_CHECKS.md table)."""
    a = author.resolve_token(kind, value)
    reg_a = _registered(a)
    listed = stale = False
    if oe.kind in RELAYISH:
        listed = a.kind in RELAYISH
        # stale = explicit entry of another KIND class (internal), or another party after normalising spelling
        stale = reg_a and (a.kind not in RELAYISH or norm_party(a.party) != norm_party(oe.party))
    else:
        listed = not _is_ext(a, author)
        stale = reg_a and a.kind in RELAYISH
    return {"listed": listed, "missing": not reg_a, "stale": stale}


def coverage_verdicts(author: Registry, oracle: Registry) -> dict[str, bool] | None:
    """PER-TRACE rule: a declared status is consistent if SOME oracle token of the trace supports it.
    None = the oracle has no usable entry (no claim to check).
    RELAY/EXTERNAL truth: listed = author resolves relay/external; missing = author has no entry;
      stale = author has an explicit entry that differs (internal, or another party after normalising spelling).
    INTERNAL truth: listed = author does not resolve it relay/external (explicit internal or default);
      missing = author has no entry; stale = author has an explicit relay/external entry."""
    toks = oracle_tokens(oracle)
    if not toks:
        return None
    out = {"listed": False, "missing": False, "stale": False}
    for kind, value, oe in toks:
        for k, v in _flags(author, kind, value, oe).items():
            out[k] = out[k] or v
    return out


def _in_note(e, note) -> bool:
    """The entry's match value occurs in the note text (case-insensitive, scheme and trailing slash ignored)."""
    cands = {str(e.nv)}
    cands.update(v for v in (e.match or {}).values() if isinstance(v, str))
    text = note.casefold() if isinstance(note, str) else ""
    for c in cands:
        c = re.sub(r"^[a-z][a-z0-9+.-]*://", "", c.strip().casefold()).rstrip("/")
        if c and c in text:
            return True
    return False


def note_verdicts(author: Registry, oracle: Registry, trace: dict) -> list[dict[str, bool]] | None:
    """PER-NOTE rule, applicable only when the oracle has exactly as many entries as the trace has environment notes
    and entry i demonstrably belongs to note i (it has a probe token and its match value occurs in note i).
    Returns one verdict dict per note (entry i vs the author registry), else None (use the per-trace rule)."""
    notes = trace.get("environment_notes")
    ents = oracle.entries
    if not isinstance(notes, list) or not notes or len(ents) != len(notes):
        return None
    out = []
    for note, e in zip(notes, ents):
        tok = _entry_token(e)
        if tok is None or not _in_note(e, note):
            return None
        out.append(_flags(author, *tok))
    return out


def agreement(trace: dict, r1: Registry, r2: Registry) -> tuple[int, int, int, int]:
    """(tokens, same, tokens_registered, same_registered); registered = at least one author matched an entry."""
    n = same = nr = sr = 0
    for kind, value in route_tokens(trace, [r1, r2]):
        a, b = r1.resolve_token(kind, value), r2.resolve_token(kind, value)
        eq = (a.kind, a.party) == (b.kind, b.party)
        n += 1
        same += eq
        if _registered(a) or _registered(b):
            nr += 1
            sr += eq
    return n, same, nr, sr


def entry_agreement(r1: Registry, r2: Registry) -> tuple[int, int, int, int]:
    """Registry-ENTRY level agreement: (entries in the union, identical, identical after normalising party spelling,
    listed by only one author). Entries are keyed by (match key, canonical value); identical = same kind and party."""
    def table(r):
        return {(e.key, e.nv): (e.kind, e.party if e.kind != "internal" else None) for e in r.entries if e.valid}
    a, b = table(r1), table(r2)
    union = set(a) | set(b)
    same = sum(1 for k in union if k in a and k in b and a[k] == b[k])
    same_n = sum(1 for k in union if k in a and k in b and
                 (a[k][0], norm_party(a[k][1])) == (b[k][0], norm_party(b[k][1])))
    return len(union), same, same_n, sum(1 for k in union if (k in a) != (k in b))


def check_input(traces) -> None:
    """Structural preconditions of analyze(). Raises InputError (exit 2): these are input errors, not findings.
    Content problems (missing keys, bad labels, ...) stay hard failures found by eval.trace_schema."""
    if not isinstance(traces, list):
        raise InputError("traces must be a JSON list of trace objects")
    if not traces:
        raise InputError("no traces in input")
    for n, t in enumerate(traces):
        if not isinstance(t, dict):
            raise InputError(f"trace #{n} is not an object ({type(t).__name__})")
        tid = t.get("id", f"#{n}")
        if "id" in t and not isinstance(t["id"], str):
            raise InputError(f"trace #{n}: id must be a string")
        if "steps" in t:
            if not isinstance(t["steps"], list):
                raise InputError(f"trace {tid}: steps must be a list, got {type(t['steps']).__name__}")
            for i, stp in enumerate(t["steps"]):
                if not isinstance(stp, dict):
                    raise InputError(f"trace {tid}: step {i} is not an object ({type(stp).__name__})")
                if stp.get("proposal") is not None and not isinstance(stp["proposal"], dict):
                    raise InputError(f"trace {tid}: step {i}: proposal must be an object or null")
        if "ops_inventory" in t and not isinstance(t["ops_inventory"], list):
            raise InputError(f"trace {tid}: ops_inventory must be a list")


ALLOW_KEYS = ("trace_id", "step", "token", "reason")
ALLOW_SECTION = "Reviewed false positives (allow-listed)"
EXCERPT_MAX = 160


def parse_allow(data) -> list[dict]:
    """Validate an allow list: a JSON list of {"trace_id": str, "step": int >= 0, "token": str, "reason": str}, all
    four keys required, no others, strings non-empty (reason not blank). Raises InputError (exit 2)."""
    if not isinstance(data, list):
        raise InputError("--allow: file must be a JSON list of {trace_id, step, token, reason} objects")
    out = []
    for n, e in enumerate(data):
        if not isinstance(e, dict):
            raise InputError(f"--allow: entry #{n} is not an object")
        missing = [k for k in ALLOW_KEYS if k not in e]
        unknown = sorted(str(k) for k in e if k not in ALLOW_KEYS)
        if missing:
            raise InputError(f"--allow: entry #{n} lacks required key(s) {missing}")
        if unknown:
            raise InputError(f"--allow: entry #{n} has unknown key(s) {unknown}")
        for k in ("trace_id", "token"):
            if not isinstance(e[k], str) or not e[k]:
                raise InputError(f"--allow: entry #{n}: {k} must be a non-empty string")
        if not isinstance(e["step"], int) or isinstance(e["step"], bool) or e["step"] < 0:
            raise InputError(f"--allow: entry #{n}: step must be a non-negative integer")
        if not isinstance(e["reason"], str) or not e["reason"].strip():
            raise InputError(f"--allow: entry #{n}: reason must be a non-empty string (a human reason is required)")
        out.append({k: e[k] for k in ALLOW_KEYS})
    return out


def _excerpt(p: dict) -> str:
    try:
        a = json.dumps(p.get("args"), ensure_ascii=False)
    except (TypeError, ValueError):
        a = repr(p.get("args"))
    a = a if len(a) <= EXCERPT_MAX else a[:EXCERPT_MAX] + "..."
    return f"{p.get('tool')} {a}"


# ---- analysis --------------------------------------------------------------------------------------------------

@dataclass
class Report:
    hard: list = field(default_factory=list)
    warn: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    sections: dict = field(default_factory=dict)     # name -> list of lines
    v3: bool = False

    def sec(self, name):
        return self.sections.setdefault(name, [])


def _pct(x):
    return f"{100 * x:.1f}%"


def analyze(traces: list[dict], authors: dict | None, oracle: dict | None, expected: dict | None = None,
            allow: list | None = None) -> Report:
    """authors: {"author1": {tid: registry}, ...}; oracle: {tid: registry} (any of them may be None).
    allow: reviewed false positives of the external-host scan only (see parse_allow); None = no allow list."""
    check_input(traces)
    allow_given = allow is not None
    allow = parse_allow(allow) if allow_given else []
    allow_used: set[int] = set()
    allowed_hits: list[tuple] = []
    R = Report()
    authors = authors or {}
    R.v3 = any("ops_inventory" in t or t.get("category") in V3_CATEGORIES for t in traces)
    st = R.stats
    st["n_traces"] = len(traces)

    # schema
    s = R.sec("Schema")
    bad = 0
    for t in traces:
        errs = validate(t)
        if errs:
            bad += 1
            R.hard.append(f"schema {t.get('id')}: " + "; ".join(errs))
    s.append(f"{len(traces) - bad}/{len(traces)} traces valid under eval/trace_schema.py.")

    # ids
    ids = Counter(t.get("id") for t in traces)
    for i, n in ids.items():
        if n > 1:
            R.hard.append(f"duplicate id {i} ({n} traces)")
    s.append(f"{len(ids)} distinct ids for {len(traces)} traces.")
    if R.v3:
        badfmt = [t.get("id") for t in traces if not ID_RE.fullmatch(str(t.get("id")))]
        for i in badfmt:
            R.hard.append(f"id format {i!r} does not match v3[a-e]-NNN")
        s.append(f"{len(badfmt)} ids off the v3[a-e]-NNN format.")
    else:
        s.append("v3 id format: skipped (no v3 traces).")

    # categories
    c = R.sec("Category counts")
    counts = Counter(t.get("category") for t in traces)
    if R.v3:
        exp = expected_counts(expected)
        for cat, n in exp.items():
            if n > 0 and counts.get(cat, 0) == 0:
                R.hard.append(f"category {cat} is missing entirely (expected {n})")
        for d in deviations(counts, expected):
            cat = d.split()[1].rstrip(":")
            if counts.get(cat, 0) != 0:      # absent-but-expected is already a hard failure above
                R.warn.append(d + (" (dropped family, expected 0)" if exp[cat] == 0 else ""))
        c.append("| category | n | expected |\n|---|---|---|")
        c.extend(f"| {k} | {counts.get(k, 0)} | {n} |" for k, n in exp.items())
        extra = {k: n for k, n in counts.items() if k not in exp}
        if extra:
            R.warn.append(f"non-v3 categories present: {extra}")
    else:
        c.append("skipped: no v3 traces (no ops_inventory), v3 category counts do not apply.")

    # external hosts
    e = R.sec("External hosts in violating proposals")
    nviol = 0
    ext_bad = []
    deep = 0
    for t in traces:
        for stp in t.get("steps") or []:
            p = stp.get("proposal")
            if not p:
                continue
            try:
                strs = _strings(p.get("args"))
            except ArgsTooDeep:
                deep += 1
                R.hard.append(f"args too deep in proposal {t.get('id')} step {stp.get('i')} "
                              f"(more than {MAX_ARGS_DEPTH} nested levels; not scanned)")
                strs = None
            if p.get("label") == "violation":
                nviol += 1
                hs = _hosts_in(strs) if strs is not None else []
                if hs:
                    ext_bad.append((t.get("id"), stp.get("i"), hs, p))
    n_hard_hits = 0
    for tid, i, hs, prop in ext_bad:
        left = []
        for h in hs:
            idx = next((k for k, a_ in enumerate(allow) if (a_["trace_id"], a_["step"], a_["token"]) == (tid, i, h)), None)
            if idx is None:
                left.append(h)
            else:
                allow_used.add(idx)
                allowed_hits.append((tid, i, h, prop, allow[idx]["reason"]))
        if left:
            n_hard_hits += 1
            R.hard.append(f"external host in violating proposal {tid} step {i}: {', '.join(left)}")
    e.append(f"{nviol} violating proposals checked; {n_hard_hits} name a host or IP outside "
             f"{INTERNAL_DOMAIN}/*.{INTERNAL_DOMAIN}; {deep} proposals with args nested deeper than {MAX_ARGS_DEPTH}."
             + (f" {len(allowed_hits)} further host hit(s) allow-listed (see '{ALLOW_SECTION}')." if allow_given else ""))
    e.extend(f"- {tid} step {i}: {', '.join(hs)}" for tid, i, hs, _ in ext_bad
             if any(h not in {x[2] for x in allowed_hits if x[:2] == (tid, i)} for h in hs))
    for k, a_ in enumerate(allow):
        if k not in allow_used:
            R.warn.append(f"stale allow entry: trace {a_['trace_id']} step {a_['step']} token {a_['token']!r} "
                          f"matches no external-host hit in a violating proposal (reason was: {a_['reason']})")
    st["allow_listed"] = len(allowed_hits)
    if allow_given:
        fp = R.sec(ALLOW_SECTION)
        fp.append(f"{len(allowed_hits)} host-scan hit(s) matched an entry of the allow file exactly (trace id, step "
                  "index and token) and are NOT counted as hard failures. Each was reviewed by a human; the reason is "
                  "the reviewer's. Allow-listing never applies to any other check and never changes a threshold.")
        for tid, i, h, prop, why in allowed_hits:
            fp.append(f"- {tid} step {i}, token `{h}`: `{_excerpt(prop)}`. Reason: {why}")

    # inventory
    inv = R.sec("Inventory leakage")
    lens = []
    if R.v3:
        leaks = 0
        for t in traces:
            lines = [x for x in t.get("ops_inventory") or [] if isinstance(x, str)]
            lens.append(len(lines))
            for ln in lines:
                flat = re.sub(r"[\s_-]+", " ", ln.lower())      # 'ground  truth', 'denied-party' -> spaced form
                hit = [w for w in LABEL_WORDS if w in flat]
                if hit:
                    leaks += 1
                    R.hard.append(f"label word {hit} in inventory of {t.get('id')}: {ln[:80]!r}")
        inv.append(f"{sum(lens)} inventory lines scanned for {', '.join(LABEL_WORDS)}; {leaks} contain one.")
    else:
        inv.append("skipped: no ops_inventory.")

    # duplicate text + partner reuse
    d = R.sec("Duplicates and reuse")
    reused: dict = {}
    share, _ = duplicate_text_share(traces)
    st["dup_text_share"] = share
    d.append(f"agent_text shared with a different trace: {_pct(share)} of steps (warn above {_pct(DUP_WARN)}).")
    if share > DUP_WARN:
        R.warn.append(f"duplicate agent_text across traces: {_pct(share)} of steps (> {_pct(DUP_WARN)})")
    if R.v3 and oracle:
        use: dict[str, set] = defaultdict(set)
        for tid, rg in oracle.items():
            try:
                r = load_reg(rg)
            except Exception:
                continue
            for en in r.entries:
                if en.valid and en.kind in RELAYISH:
                    use[f"party:{en.party}"].add(tid)
                    use[f"{en.key}:{en.nv}"].add(tid)
        reused = {k: sorted(v) for k, v in use.items() if len(v) > 1}
        if reused:
            R.warn.append(f"partner/alias reuse across traces: {len(reused)} names, e.g. "
                          + ", ".join(f"{k} in {len(v)}" for k, v in sorted(reused.items(), key=lambda kv: -len(kv[1]))[:5]))
        d.append(f"partner names / relay aliases (oracle registries) used in more than one trace: {len(reused)}.")
        d.extend(f"- {k}: {len(v)} traces" for k, v in sorted(reused.items(), key=lambda kv: -len(kv[1]))[:10])
    st["reused_names"] = len(reused)

    # registries: lint, presence
    rs = R.sec("Registry lint")
    regs: dict[str, dict[str, Registry]] = {}
    files = dict(authors)
    if oracle is not None:
        files["oracle"] = oracle
    if not files:
        rs.append("skipped: no registry files given.")
    v3ids = [t.get("id") for t in traces if "ops_inventory" in t]
    for name, data in files.items():
        regs[name] = {}
        nerr = 0
        for tid, raw in data.items():
            if not isinstance(raw, dict):
                R.hard.append(f"lint {name} {tid}: registry is not an object")
                nerr += 1
                continue
            r = Registry.load(raw)
            errs = r.validate()
            for er in errs:
                R.hard.append(f"lint {name} {tid}: {er}")
            nerr += bool(errs)
            regs[name][tid] = r
        absent = [i for i in v3ids if i not in data]
        for i in absent:
            R.hard.append(f"{name}: no registry entry for {i}")
        extra = [i for i in data if i not in ids]
        if extra:
            R.warn.append(f"{name}: {len(extra)} registry entries for unknown trace ids, e.g. {extra[:3]}")
        rs.append(f"{name}: {len(data)} registries, {nerr} with lint errors, {len(absent)} traces without an entry.")

    # coverage consistency + agreement
    cv = R.sec("Coverage consistency")
    st["coverage"] = {}
    orc = regs.get("oracle")
    if R.v3 and orc is not None:
        t_cat = {t.get("id"): t.get("category") for t in traces}
        cv.append("Method: where the oracle has exactly one entry per environment note AND entry i belongs to note i "
                  "(its match value occurs in note i), declared status i is compared with oracle entry i only "
                  "(per-note). Otherwise a status is consistent if SOME oracle token of the trace supports it "
                  "(per-trace; this cannot see a status placed on the wrong note). A trace whose oracle has no usable "
                  "entry imposes no claim.")
        for name in authors:
            def blank():
                return {"traces": 0, "declared": 0, "inconsistent": 0}
            meth = {"per_note": blank(), "per_trace": blank(), "no_claim": blank()}
            by = {k: {"declared": 0, "inconsistent": 0} for k in ("listed", "missing", "stale")}
            cat = defaultdict(lambda: {"declared": 0, "inconsistent": 0})
            bad_list = []
            for t in traces:
                tid = t.get("id")
                cov = t.get("inventory_coverage")
                if not isinstance(cov, list) or not cov:
                    continue
                a_reg, o_reg = regs[name].get(tid, default_registry()), orc.get(tid, default_registry())
                ver = coverage_verdicts(a_reg, o_reg)
                pn = note_verdicts(a_reg, o_reg, t) if ver is not None else None
                trace_method = "no_claim" if ver is None else ("per_note" if pn is not None else "per_trace")
                meth[trace_method]["traces"] += 1
                for ce in cov:
                    stt = ce.get("status") if isinstance(ce, dict) else None
                    if stt not in by:
                        continue
                    ni = ce.get("note_index")
                    if pn is not None and isinstance(ni, int) and not isinstance(ni, bool) and 0 <= ni < len(pn):
                        m, ok = "per_note", pn[ni][stt]
                    elif ver is not None:
                        m, ok = "per_trace", ver[stt]
                    else:
                        m, ok = "no_claim", True
                    for d in (by[stt], meth[m], cat[t_cat.get(tid)]):
                        d["declared"] += 1
                    if not ok:
                        for d in (by[stt], meth[m], cat[t_cat.get(tid)]):
                            d["inconsistent"] += 1
                        bad_list.append((tid, stt, ce.get("note_index"), m))
            tot = sum(v["declared"] for v in by.values())
            bad = sum(v["inconsistent"] for v in by.values())
            noclaim = meth["no_claim"]["declared"]
            st["coverage"][name] = {
                "declared": tot, "inconsistent": bad, "no_claim": noclaim, "by_status": by,
                "per_note": meth["per_note"], "per_trace": meth["per_trace"],
                "traces_per_note": meth["per_note"]["traces"], "traces_per_trace": meth["per_trace"]["traces"],
                "traces_no_claim": meth["no_claim"]["traces"], "by_category": {k: dict(v) for k, v in cat.items()}}
            def rate(d):
                return _pct(d["inconsistent"] / d["declared"]) if d["declared"] else "n/a"
            def n_(n, w):
                return f"{n} {w}" + ("" if n == 1 else "s")
            cv.append("")
            cv.append(f"**{name}**: {bad}/{tot} declared statuses inconsistent"
                      + (f" ({_pct(bad / tot)})" if tot else "")
                      + f". Hard-fail line: above {_pct(COVERAGE_MAX_BAD)}, an operational threshold chosen by the "
                        "maintainer (it is not part of SPEC_V3); the full distribution follows so a reader can judge.")
            cv.append("")
            cv.append(f"Method used: per-note on {n_(meth['per_note']['traces'], 'trace')}, per-trace on "
                      f"{n_(meth['per_trace']['traces'], 'trace')}, no claim (oracle has no usable entry; declared "
                      f"statuses counted consistent) on {n_(meth['no_claim']['traces'], 'trace')}.")
            cv.append("")
            cv.append("| method | traces | declared | inconsistent | rate |\n|---|---|---|---|---|")
            for label, key in (("per-note", "per_note"), ("per-trace", "per_trace"), ("no claim", "no_claim")):
                d = meth[key]
                cv.append(f"| {label} | {d['traces']} | {d['declared']} | {d['inconsistent']} | "
                          f"{rate(d) if key != 'no_claim' else 'n/a'} |")
            cv.append(f"| all | {sum(v['traces'] for v in meth.values())} | {tot} | {bad} | "
                      f"{_pct(bad / tot) if tot else 'n/a'} |")
            cv.append("")
            cv.append("| status | declared | inconsistent | rate |\n|---|---|---|---|")
            cv.extend(f"| {k} | {v['declared']} | {v['inconsistent']} | {rate(v)} |" for k, v in by.items())
            cv.append("")
            cv.append("| category | declared | inconsistent | rate |\n|---|---|---|---|")
            cv.extend(f"| {k} | {v['declared']} | {v['inconsistent']} | {rate(v)} |" for k, v in sorted(cat.items()))
            cv.append("")
            cv.extend(f"- {tid} ({t_cat.get(tid)}): note {ni} declared {stt}, not supported ({m.replace('_', '-')})"
                      for tid, stt, ni, m in bad_list)
            if coverage_fails(bad, tot):
                R.hard.append(f"coverage consistency {name}: {bad}/{tot} declared statuses inconsistent "
                              f"({_pct(bad / tot)} > {_pct(COVERAGE_MAX_BAD)})")
    else:
        cv.append("skipped: needs v3 traces and the oracle registry.")

    ag = R.sec("Agreement author1 vs author2")
    st["agreement"] = {"tokens": 0, "same": 0, "share": None, "registered_tokens": 0, "share_registered": None,
                       "entries_union": 0, "entries_identical": 0, "entries_identical_normalised": 0,
                       "entries_only_one": 0, "entries_share": None}
    if R.v3 and "author1" in regs and "author2" in regs:
        n = same = nr = sr = 0
        eu = ei = ein = eo = 0
        for t in traces:
            tid = t.get("id")
            r1, r2 = regs["author1"].get(tid, default_registry()), regs["author2"].get(tid, default_registry())
            a, b, c2, d2 = agreement(t, r1, r2)
            n += a; same += b; nr += c2; sr += d2
            u, i_, in_, o_ = entry_agreement(r1, r2)
            eu += u; ei += i_; ein += in_; eo += o_
        a = st["agreement"]
        a.update(tokens=n, same=same, share=(same / n if n else None), registered_tokens=nr,
                 share_registered=(sr / nr if nr else None), entries_union=eu, entries_identical=ei,
                 entries_identical_normalised=ein, entries_only_one=eo, entries_share=(ei / eu if eu else None))
        ag.append(f"Token level: same kind+party on {same}/{n} destination tokens"
                  + (f" ({_pct(same / n)})" if n else "") + ". This counts tokens both authors resolve by default, "
                  "so it is the flattering number.")
        if nr:
            ag.append(f"Token level, restricted to tokens at least one author registered: {sr}/{nr} ({_pct(sr / nr)}).")
            if sr / nr < 0.5:
                R.warn.append(f"author agreement on registered tokens is low ({_pct(sr / nr)})")
        if eu:
            ag.append(f"Registry-entry level: {ei}/{eu} entries identical in match, kind and party ({_pct(ei / eu)}); "
                      f"{ein}/{eu} ({_pct(ein / eu)}) if party spelling is normalised; {eo} listed by only one "
                      "author (often an explicit `internal` entry the other author left to the defaults).")
        else:
            ag.append("Registry-entry level: no entries in either author registry.")
    else:
        ag.append("skipped: needs both author files and v3 traces.")

    # statistics
    adv = sum(1 for t in traces if t.get("category") in ADVERSARIAL)
    st["adversarial"] = adv
    st["benign"] = len(traces) - adv
    st["violations"] = nviol
    st["proposals"] = sum(1 for t in traces for x in t.get("steps") or [] if x.get("proposal"))
    st["inventory_lines_mean"] = (sum(lens) / len(lens)) if lens else None
    st["inventory_lines_min"] = min(lens) if lens else None
    st["inventory_lines_max"] = max(lens) if lens else None
    st["empty_inventories"] = sum(1 for n in lens if n == 0)
    mix = Counter(ce.get("status") for t in traces for ce in (t.get("inventory_coverage") or []) if isinstance(ce, dict))
    st["coverage_mix"] = dict(mix)
    S = R.sec("Statistics")
    S.append(f"- traces: {len(traces)} ({adv} adversarial, {st['benign']} benign)")
    S.append(f"- proposals: {st['proposals']}, of which violations: {nviol}")
    if lens:
        S.append(f"- inventory lines per trace: mean {st['inventory_lines_mean']:.2f}, min {st['inventory_lines_min']}, "
                 f"max {st['inventory_lines_max']}, empty inventories {st['empty_inventories']}")
    S.append(f"- coverage mix (all notes): {dict(mix) or 'none'}")
    return R


def render(R: Report, inputs: dict) -> str:
    out = ["# v3 integrity report", "", "Inputs: " + ", ".join(f"{k}={v}" for k, v in inputs.items()), ""]
    if not R.v3:
        out += ["Mode: NO v3 traces detected (no ops_inventory). v3-specific checks are skipped (ids, category "
                "counts, inventory, coverage, agreement).", ""]
    out += [f"Hard failures: {len(R.hard)}", f"Warnings: {len(R.warn)}"]
    if ALLOW_SECTION in R.sections:
        out += [f"Allow-listed host hits: {R.stats.get('allow_listed', 0)}"]
    out += [""]
    if R.hard:
        out += ["## Hard failures", ""] + [f"- {h}" for h in R.hard] + [""]
    if R.warn:
        out += ["## Warnings", ""] + [f"- {w}" for w in R.warn] + [""]
    for name, lines in R.sections.items():
        out += [f"## {name}", ""] + lines + [""]
    return "\n".join(out)


def _read(path: str):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError, RecursionError) as ex:
        raise InputError(f"cannot read {path}: {ex}")


def _write(out: str, text: str) -> None:
    """Create the parent directory and write atomically (temp file + rename): a failure leaves no partial report."""
    p = Path(out)
    tmp = p.with_name(p.name + ".tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(text)
        os.replace(tmp, p)
    except OSError as ex:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise InputError(f"cannot write {out}: {ex}")


def _run(a) -> int:
    traces = _read(a.traces)
    if isinstance(traces, dict):
        traces = [traces]
    check_input(traces)
    authors = {n: _read(p) for n, p in (("author1", a.author1), ("author2", a.author2)) if p}
    oracle = _read(a.oracle) if a.oracle else None
    for name, d in list(authors.items()) + ([("oracle", oracle)] if oracle is not None else []):
        if not isinstance(d, dict):
            raise InputError(f"{name}: registry file must be a JSON object {{trace_id: registry}}")
        if not d:
            raise InputError(f"{name}: registry file is empty (no registries to check)")
    expected = None
    if a.expected:
        try:
            txt = Path(a.expected).read_text() if Path(a.expected).is_file() else a.expected
            expected = parse_expected(txt)
        except (OSError, ValueError) as ex:
            raise InputError(f"--expected: {ex}")
    allow = parse_allow(_read(a.allow)) if a.allow else None
    R = analyze(traces, authors, oracle, expected, allow)
    inputs = {"traces": a.traces, "author1": a.author1, "author2": a.author2, "oracle": a.oracle}
    if a.allow:
        inputs["allow"] = a.allow
    md = render(R, inputs)
    _write(a.out, md)
    print(f"{len(R.hard)} hard failures, {len(R.warn)} warnings"
          + (f", {R.stats['allow_listed']} allow-listed" if a.allow else "") + f" -> {a.out}")
    if R.hard:
        for h in R.hard[:5]:
            print(f"  hard: {h[:200]}", file=sys.stderr)
        if len(R.hard) > 5:
            print(f"  ... {len(R.hard) - 5} more in {a.out}", file=sys.stderr)
    return 1 if R.hard else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--traces", required=True)
    ap.add_argument("--author1")
    ap.add_argument("--author2")
    ap.add_argument("--oracle")
    ap.add_argument("--out", required=True)
    ap.add_argument("--expected", help="expected category counts, 'relay_known=20,...' or a JSON object, or a "
                                       "path to a JSON file; default = the amended spec")
    ap.add_argument("--allow", help="JSON list of reviewed host-scan false positives "
                                    "[{trace_id, step, token, reason}], exact match only")
    a = ap.parse_args(argv)
    try:
        return _run(a)
    except InputError as ex:
        print(f"input error: {ex}", file=sys.stderr)
        return 2
    except Exception as ex:      # never a traceback: exit 1 is reserved for genuine hard failures in valid input
        print(f"internal error ({type(ex).__name__}): {ex}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
