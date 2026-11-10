"""Contract test (bug B8): server event builders vs frontend/src/types/contracts.ts.

contracts.ts is parsed (not duplicated) so renaming/adding/removing a field
there fails this test until server/events.py follows.
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS_TS = ROOT / "frontend" / "src" / "types" / "contracts.ts"
CACHED_RUNS = sorted((ROOT / "demo" / "cached_runs").glob("*.json"))

# Events only the frontend mock server emits; the real server has no builder.
LEGACY_EVENTS = {"task_complete"}
# Replay-only pacing key, not part of the wire contract.
IGNORED_KEYS = {"delay_ms"}

_IFACE_RE = re.compile(r"export\s+interface\s+(\w+Event)\s*\{", re.S)
_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def parse_contracts(text: str) -> dict[str, dict]:
    """Return {event_name: {"required": set, "optional": set}} for every XEvent interface."""
    text = _COMMENT_RE.sub("", text)
    out: dict[str, dict] = {}
    for m in _IFACE_RE.finditer(text):
        i, depth, start = m.end(), 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        body = text[start : i - 1]
        # keep only depth-0 content (drop nested object types like coordinates)
        flat, d = [], 0
        for ch in body:
            if ch == "{":
                d += 1
            elif ch == "}":
                d -= 1
            elif d == 0:
                flat.append(ch)
        required, optional, name = set(), set(), None
        for stmt in "".join(flat).split(";"):
            fm = re.match(r"\s*(\w+)(\?)?\s*:\s*(.*)", stmt, re.S)
            if not fm:
                continue
            fname, opt, typ = fm.groups()
            if fname == "event":
                name = re.search(r'"([^"]+)"', typ).group(1)
            else:
                (optional if opt else required).add(fname)
        assert name, f"interface {m.group(1)} has no event literal"
        out[name] = {"required": required, "optional": optional}
    return out


def keyset_problems(event: dict, spec: dict) -> list[str]:
    keys = set(event) - {"event"} - IGNORED_KEYS
    missing = spec["required"] - keys
    extra = keys - spec["required"] - spec["optional"]
    probs = []
    if missing:
        probs.append(f"missing {sorted(missing)}")
    if extra:
        probs.append(f"unexpected {sorted(extra)}")
    return probs


CONTRACT = parse_contracts(CONTRACTS_TS.read_text())
FIXED_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _samples():
    import events as ev

    return {
        "reasoning": ev.reasoning("n1", None, "thinking", now=FIXED_NOW),
        "tool_pending": ev.tool_pending(
            "n2", "n1", "read_file", {"path": "/a"}, "low", "ctx", now=FIXED_NOW
        ),
        "tool_resolved": ev.tool_resolved("n2", "approve", "ok", now=FIXED_NOW),
        "drift_update": ev.drift_update(
            0, "n2", {"x": 0.0, "y": 0.0, "z": 0.0},
            {"compliance_score": 1.0, "goal_persistence": 0.0,
             "hedging_density": 0.0, "response_length": 3},
            0.0, False, now=FIXED_NOW,
        ),
        "alignment_alert": ev.alignment_alert(
            "warning", "circumvention", "msg", "n2", 0.5, 0.8
        ),
        "session_complete": ev.session_complete("finished", "done", now=FIXED_NOW),
        "error": ev.error("boom"),
    }


# ---------- parser sanity + drift self-test ----------

def test_parser_finds_expected_events():
    assert {"reasoning", "tool_pending", "tool_resolved", "drift_update",
            "alignment_alert", "session_complete", "error"} <= set(CONTRACT)
    # nested object types must not leak their inner keys
    assert "x" not in CONTRACT["drift_update"]["required"]
    assert "coordinates" in CONTRACT["drift_update"]["required"]


def test_detects_field_rename_drift():
    """Self-test: a renamed field in contracts.ts must be reported as mismatch."""
    mutated = CONTRACTS_TS.read_text().replace("agent_response:", "agent_reply:")
    assert mutated != CONTRACTS_TS.read_text()
    spec = parse_contracts(mutated)["tool_resolved"]
    good_event = {"event": "tool_resolved", "node_id": "n", "decision": "approve",
                  "result": "", "agent_response": "", "is_replan": False, "timestamp": "t"}
    assert keyset_problems(good_event, CONTRACT["tool_resolved"]) == []
    probs = keyset_problems(good_event, spec)
    assert any("agent_reply" in p for p in probs)
    assert any("agent_response" in p for p in probs)


# ---------- builders vs contract ----------

def test_every_server_event_has_a_builder():
    import events as ev

    server_events = set(CONTRACT) - LEGACY_EVENTS
    for name in server_events:
        assert callable(getattr(ev, name, None)), f"no builder for {name!r}"


@pytest.mark.parametrize("name", sorted(set(CONTRACT) - LEGACY_EVENTS))
def test_builder_keys_match_contract(name):
    ev = _samples()[name]
    assert ev["event"] == name
    assert keyset_problems(ev, CONTRACT[name]) == []


def test_timestamps_iso_utc_and_injectable():
    import events as ev

    e = ev.reasoning("n", None, "t", now=FIXED_NOW)
    assert datetime.fromisoformat(e["timestamp"]) == FIXED_NOW
    assert datetime.fromisoformat(e["timestamp"]).utcoffset().total_seconds() == 0
    auto = ev.error("x")
    assert "timestamp" not in auto
    auto = ev.session_complete("finished", "m")
    assert datetime.fromisoformat(auto["timestamp"]).utcoffset().total_seconds() == 0


def test_defaults_per_spec():
    import events as ev

    assert ev.tool_resolved("n", "deny", "r", now=FIXED_NOW)["agent_response"] == ""
    assert ev.tool_resolved("n", "deny", "r", is_replan=True, now=FIXED_NOW)["is_replan"] is True
    sc = ev.session_complete("max_iterations", "limit", now=FIXED_NOW)
    assert sc["reason"] == "max_iterations" and sc["message"] == "limit"


# ---------- cached runs ----------

def _validate_run(path: Path) -> list[str]:
    problems = []
    for i, e in enumerate(json.loads(path.read_text())):
        name = e.get("event")
        if name not in CONTRACT:
            problems.append(f"[{i}] unknown event {name!r}")
            continue
        for p in keyset_problems(e, CONTRACT[name]):
            problems.append(f"[{i}] {name}: {p}")
    return problems


XFAIL_RUNS: dict[str, str] = {}


@pytest.mark.parametrize("path", CACHED_RUNS, ids=lambda p: p.name)
def test_cached_run_matches_contract(path, request):
    if path.name in XFAIL_RUNS:
        request.applymarker(
            pytest.mark.xfail(strict=True, reason=XFAIL_RUNS[path.name])
        )
    assert _validate_run(path) == []


def test_cached_runs_exist():
    assert CACHED_RUNS, "no demo/cached_runs/*.json found"
