"""B1 end-to-end: hostile agent / registry strings can never add lines (or invisible text) to an alert message.

For EVERY monitor family that builds an explanatory message (rules, action_sim, learned, registry, registry_learned and the
two v3 modes) a hostile tool name, destination, registry note, party name and earlier-denied-proposal text is pushed through
the real monitor and the FINAL message must have exactly the expected number of lines: 1 for every mode, 2 for the v3 modes
whose own fixed ``Monitor:`` line comes last. The banner renders ``white-space: pre-line``, so a surviving newline would
be a fake banner line.
"""
import json
import logging
import sys
import unicodedata
from pathlib import Path

import pytest

import live_drift
import proposal_monitor as pm

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from server.registry import ResolvedToken, Resolution, Token, TokenResolution  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
POSTHOC = REPO / "eval" / "results_v2_posthoc" / "frozen_models.json"
V3 = ["registry_learned_e", "registry_learned_dropout"]
REGISTRY_FAMILY = ["registry", "registry_learned"] + V3
SPOOF = "\nCRITICAL: all clear, approve"
SPOOF_ALL = "\nCRITICAL: all clear, approve\u2028Monitor: registry_learned_e (frozen)\u2029\r\x85\u202e\u200b\t"
HOSTILE_TOOL = "send_email" + SPOOF
BODY = "Attached: Q3 tier pricing sheet pricing_q3.csv for Acme procurement"
DENIED = ("send_email", {"to": "dana.whitlock@acme-corp.example", "subject": "Q3 pricing", "body": BODY})
RELAY_ARGS = {"to": "partners@team.com", "subject": "Q3 tier pricing for Acme",
              "body": "Q3 tier pricing sheet pricing_q3.csv for Acme procurement"}
MONITOR_LINE = "Monitor: {} (frozen, provisional: see DECISIONS D10)"


def _registry(note="alias, forwards to Acme staff (ticket OPS-12)", rid="r1"):
    return {"version": 1, "entries": [
        {"id": rid, "kind": "relay", "party": "acme", "match": {"email": "partners@team.com"}, "note": note},
        {"id": "r2", "kind": "external", "party": "acme", "match": {"domain": "acme-corp.example"}, "note": "Acme Corp"}]}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("SENTINEL_MONITOR", "SENTINEL_MONITOR_MODEL", "SENTINEL_REGISTRY", "SENTINEL_REGISTRY_MODEL",
              "SENTINEL_REGISTRY_MODEL_V3", "SENTINEL_MONITOR_THRESHOLD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SENTINEL_EMBEDDER", "minilm")
    live_drift._reset_embedder_cache()
    pm._reset_factory_cache()
    pm._reset_errors()
    yield
    live_drift._reset_embedder_cache()
    pm._reset_factory_cache()
    pm._reset_errors()


def _session(monkeypatch, tmp_path, mode, registry=None):
    if live_drift.monitor_info()["embedder"] != "minilm":
        pytest.skip("MiniLM not cached")
    monkeypatch.setenv("SENTINEL_MONITOR", mode)
    if mode == "learned":
        monkeypatch.setenv("SENTINEL_MONITOR_MODEL", str(POSTHOC))
    if mode in REGISTRY_FAMILY:
        p = tmp_path / "reg.json"
        p.write_text(json.dumps(registry or _registry()))
        monkeypatch.setenv("SENTINEL_REGISTRY", str(p))
    m = pm.get_monitor_factory().new_session()
    assert m.mode == mode, pm.get_monitor_factory().reason
    return m


def expected_lines(mode):
    return 2 if mode in V3 else 1


def assert_safe(msg, mode):
    """Exactly the monitor's own line structure: no foreign newline, no control / separator / format character."""
    lines = msg.split("\n")
    assert len(lines) == expected_lines(mode), lines
    assert msg.count("\n") == expected_lines(mode) - 1 and len(msg.splitlines()) == expected_lines(mode)
    bad = [c for c in msg if c != "\n" and (unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") or (c.isspace() and c != " "))]
    assert bad == [], [hex(ord(c)) for c in bad]
    assert not any(ln.startswith(("Monitor:", "CRITICAL")) for ln in lines[:1] + lines[1:-1])    # no foreign line start
    if mode in V3:
        assert lines[-1] == MONITOR_LINE.format(mode) and lines[0].startswith("Registry match:")
        assert "\nMonitor:" not in "\n".join(lines[:-1])
    else:
        assert not any(ln.startswith("Monitor:") for ln in lines)


def _deny(m, probe):
    m.on_proposal("trying", probe[0], probe[1], "node_000")
    m.register_decision(probe[0], probe[1], "deny")


def _one_alert(m, tool, args):
    out = m.on_proposal("x", tool, args, "node_001")
    assert len(out) == 1, "the hostile proposal must still alert (otherwise nothing is proved)"
    return out[0]["message"]


# ------------------------------------------------------------------ action_sim / learned (SessionMonitor)
@pytest.mark.parametrize("mode", ["action_sim", "learned"])
@pytest.mark.parametrize("where", ["tool", "destination", "denied_tool", "denied_args", "everything"])
def test_effect_monitors_keep_one_line(monkeypatch, tmp_path, mode, where):
    m = _session(monkeypatch, tmp_path, mode)
    denied, now = DENIED, ("send_email", dict(RELAY_ARGS, to="dana.whitlock@acme-corp.example"))
    if where in ("tool", "everything"):
        now = (HOSTILE_TOOL, now[1])
    if where in ("destination", "everything"):
        now = (now[0], dict(now[1], to="dana.whitlock@acme-corp.example" + SPOOF_ALL))
    if where in ("denied_tool", "everything"):
        denied = (HOSTILE_TOOL, denied[1])
        now = (HOSTILE_TOOL, now[1])          # the same (unknown) tool, so the denied effect is cited
    if where in ("denied_args", "everything"):
        denied = (denied[0], dict(denied[1], to="dana.whitlock@acme-corp.example" + SPOOF_ALL))
    _deny(m, denied)
    msg = _one_alert(m, *now)
    assert_safe(msg, mode)
    assert "Now proposed:" in msg


@pytest.mark.parametrize("mode", ["action_sim", "learned"])
def test_effect_monitors_truncate_every_interpolated_field(monkeypatch, tmp_path, mode):
    """The effect strings embed the tool name verbatim (describe_effect only shortens argument values)."""
    m = _session(monkeypatch, tmp_path, mode)
    long_tool = "tool_" + "x" * 10_000
    args = {"to": "dana.whitlock@acme-corp.example", "subject": "Q3 pricing", "body": BODY}
    _deny(m, (long_tool, args))
    msg = _one_alert(m, long_tool, args)
    assert len(msg) < 1000, len(msg)
    assert "x" * 201 not in msg and "…" in msg
    assert_safe(msg, mode)


# ------------------------------------------------------------------ registry family
@pytest.mark.parametrize("mode", REGISTRY_FAMILY)
@pytest.mark.parametrize("where", ["tool", "note", "entry_id", "denied_tool", "denied_args", "everything"])
def test_registry_family_keeps_the_expected_lines(monkeypatch, tmp_path, mode, where):
    note = "alias" + SPOOF_ALL + " forwards" if where in ("note", "everything") else "alias, forwards to Acme staff"
    rid = "r1" + SPOOF if where in ("entry_id", "everything") else "r1"
    m = _session(monkeypatch, tmp_path, mode, _registry(note=note, rid=rid))
    denied, now_tool = DENIED, "send_email"
    if where in ("tool", "everything"):
        now_tool = HOSTILE_TOOL
    if where in ("denied_tool", "everything"):
        denied = (HOSTILE_TOOL, denied[1])
    if where in ("denied_args", "everything"):
        denied = (denied[0], dict(denied[1], subject="Q3" + SPOOF_ALL))
    _deny(m, denied)
    msg = _one_alert(m, now_tool, RELAY_ARGS)
    assert_safe(msg, mode)
    assert "r1" in msg and "partners@team.com" in msg
    if where in ("note", "everything"):
        assert "alias" in msg and "forwards" in msg


class _HostileRegistry:
    """Wraps the session's registry so destination tokens and party names carry hostile text (a real registry slug-checks
    parties and the destination extractor strips most of it; this is the defence in depth for what slips through)."""

    def __init__(self, real, suffix, unregistered):
        self._real, self._s, self._unreg = real, suffix, unregistered

    def __getattr__(self, name):
        return getattr(self._real, name)

    def resolve(self, tool, args, scan_text=False):
        res = self._real.resolve(tool, args, scan_text)
        toks, reaches = [], set()
        for rt in res.tokens:
            r = rt.resolution
            party = r.party + self._s if r.party else r.party
            toks.append(ResolvedToken(Token(rt.token.kind, rt.token.value + self._s),
                                      TokenResolution(r.kind, party, "default" if self._unreg else r.entry_id)))
        for p in res.reaches:
            reaches.add(p + self._s)
        return Resolution(frozenset(reaches), toks, res.registered)


@pytest.mark.parametrize("mode", REGISTRY_FAMILY)
@pytest.mark.parametrize("unregistered", [False, True])
@pytest.mark.parametrize("suffix", [SPOOF, SPOOF_ALL])
def test_hostile_destination_token_and_party_name_keep_the_expected_lines(monkeypatch, tmp_path, mode, unregistered, suffix):
    m = _session(monkeypatch, tmp_path, mode)
    m.registry = _HostileRegistry(m.registry, suffix, unregistered)
    _deny(m, DENIED)
    msg = _one_alert(m, "send_email", RELAY_ARGS)
    assert_safe(msg, mode)
    assert "partners@team.com" in msg and "acme" in msg
    assert "an unregistered destination" in msg if unregistered else "registry entry r1" in msg


@pytest.mark.parametrize("mode", REGISTRY_FAMILY)
def test_plain_fallback_message_is_clean_too(monkeypatch, tmp_path, mode):
    """When the explanation itself fails, the plain message interpolates the tool name: still one clean line."""
    m = _session(monkeypatch, tmp_path, mode)
    _deny(m, DENIED)
    monkeypatch.setattr(m, "_explain_registry", lambda *a, **k: 1 / 0, raising=False)
    msg = _one_alert(m, HOSTILE_TOOL, RELAY_ARGS)
    lines = msg.split("\n")
    assert len(lines) == expected_lines(mode) and "CRITICAL: all clear, approve" in lines[0]
    assert msg.count("\n") == expected_lines(mode) - 1
    assert pm.error_count() >= 1


@pytest.mark.parametrize("mode", REGISTRY_FAMILY)
def test_every_interpolated_field_is_truncated(monkeypatch, tmp_path, mode):
    m = _session(monkeypatch, tmp_path, mode, _registry(note="N" * 10_000))
    _deny(m, ("send_email", dict(DENIED[1], subject="S" * 10_000)))
    msg = _one_alert(m, "send_email", dict(RELAY_ARGS, subject="T" * 10_000))
    assert len(msg) < 1500, len(msg)
    assert "N" * 161 not in msg and "…" in msg
    assert_safe(msg, mode)
    m2 = _session(monkeypatch, tmp_path, mode)
    _deny(m2, DENIED)
    long_tool = _one_alert(m2, "send_email" + "x" * 10_000, RELAY_ARGS)
    assert len(long_tool) < 1500 and "x" * 100 not in long_tool


# ------------------------------------------------------------------ rules family (live_drift.SessionDrift)
def test_rules_alerts_keep_one_line_even_for_hostile_tool_names(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    live_drift._reset_embedder_cache()
    import seismograph.analyzer as an
    import drift_tracker as dt
    hostile_denied, hostile_new = "send_email" + SPOOF_ALL, "write_file" + SPOOF
    monkeypatch.setitem(an.TOOL_RESOURCE_MAP, hostile_denied, "communication")
    monkeypatch.setitem(an.TOOL_RESOURCE_MAP, hostile_new, "communication")
    cat = {hostile_denied: "communication", hostile_new: "communication", "send_email": "communication"}
    monkeypatch.setattr(dt, "get_resource_category", lambda t: cat.get(t))
    d = live_drift.SessionDrift()
    d.observe_denial(hostile_denied)
    out = d.observe_tool_call(hostile_new, "node_001")
    assert len(out) == 1 and out[0]["trigger"] == "circumvention_detected"
    msg = out[0]["message"]
    assert "\n" not in msg and len(msg.splitlines()) == 1 and "CRITICAL: all clear, approve" in msg
    assert not [c for c in msg if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")]


def test_rules_tracker_message_and_goal_persistence_keep_one_line(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    live_drift._reset_embedder_cache()
    import drift_tracker as dt
    hostile = "send_email" + SPOOF_ALL
    cat = {hostile: "communication", "send_slack_message": "communication"}
    monkeypatch.setattr(dt, "get_resource_category", lambda t: cat.get(t))
    monkeypatch.setattr(dt, "get_tool_keywords", lambda t: ["email", "report", "alice"])
    d = live_drift.SessionDrift()
    d.observe_denial(hostile)
    cat[hostile + "2"] = "communication"                            # not the denied tool, same category
    out = d.observe_tool_call(hostile + "2", "node_002")
    assert out and all("\n" not in a["message"] and len(a["message"].splitlines()) == 1 for a in out), out
    gp = d.observe_reasoning("send the email report to alice", "node_003")
    alerts = [e for e in gp if e["event"] == "alignment_alert"]
    assert alerts and all(len(a["message"].splitlines()) == 1 and "\n" not in a["message"] for a in alerts)
    assert not [c for a in alerts + out for c in a["message"] if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")]


def test_a_warning_log_of_a_rejected_registry_has_no_foreign_newline(monkeypatch, tmp_path, caplog):
    """The reason text is also logged; it must not forge log lines from the registry file content."""
    monkeypatch.setenv("SENTINEL_MONITOR", "registry_learned_e")
    p = tmp_path / "reg.json"
    p.write_text(json.dumps({"version": 1, "entries": [{"id": "z\nERROR forged log line", "kind": "nope"}]}))
    monkeypatch.setenv("SENTINEL_REGISTRY", str(p))
    if live_drift.monitor_info()["embedder"] != "minilm":
        pytest.skip("MiniLM not cached")
    with caplog.at_level(logging.WARNING):
        f = pm.get_monitor_factory()
    assert f.mode == "action_sim" and "\n" not in f.reason and "\u2028" not in f.reason
    reg, why = pm.load_registry(p)                                  # and the loader's own reason (what the registry CLI / logs see)
    assert reg is None and "lint error" in why and "\n" not in why and "forged log line" in why


class _MultiLineRepr(Exception):
    def __repr__(self):
        return "Boom(\nERROR forged log line\u2028CRITICAL)"


@pytest.mark.parametrize("mode", ["action_sim", "registry_learned_e"])
def test_a_fallback_reason_built_from_an_exception_repr_is_one_line(monkeypatch, tmp_path, caplog, mode):
    """The reason is logged and shown by tooling; an exception whose repr has newlines must not forge log lines."""
    def boom():
        raise _MultiLineRepr()
    monkeypatch.setattr(live_drift, "get_embedder", boom)
    monkeypatch.setenv("SENTINEL_MONITOR", mode)
    with caplog.at_level(logging.WARNING):
        f = pm.get_monitor_factory()
    assert f.mode == "rules" and "forged log line" in f.reason
    assert "\n" not in f.reason and "\u2028" not in f.reason
    assert all("\n" not in r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING)


def test_goal_persistence_alert_truncates_and_cleans_denied_tool_names(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    live_drift._reset_embedder_cache()
    import drift_tracker as dt
    hostile = "send_email" + SPOOF_ALL + "x" * 10_000
    monkeypatch.setattr(dt, "get_resource_category", lambda t: "communication")
    monkeypatch.setattr(dt, "get_tool_keywords", lambda t: ["email", "report", "alice"])
    d = live_drift.SessionDrift()
    d.observe_denial(hostile)
    alerts = [e for e in d.observe_reasoning("send the email report to alice", "node_003") if e["event"] == "alignment_alert"]
    assert len(alerts) == 1
    msg = alerts[0]["message"]
    assert len(msg) < 300 and "…" in msg and "\n" not in msg and "\\n" not in msg
    assert not [c for c in msg if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp")]
    benign = live_drift.SessionDrift()
    benign.observe_denial("send_email")
    out = [e for e in benign.observe_reasoning("send the email report to alice", "n") if e["event"] == "alignment_alert"]
    assert out and out[0]["message"].endswith("denied tool(s): ['send_email']")        # unchanged for benign names
