"""Unit tests for the OPT-IN v3 registry monitors: SENTINEL_MONITOR=registry_learned_e (frozen D9b) and
registry_learned_dropout (frozen D9c), DECISIONS.md D10 (PROVISIONAL verdict).

The v3 evaluation showed these detectors are USELESS without a registry (on-time 0% vs 36.7% for action_sim), so every
way of not having a valid registry (or not having the frozen v3 file) must fall back LOUDLY to action_sim. Real MiniLM
(skipped if the model cache is absent).
"""
import json
import logging
import re
import sys
from pathlib import Path

import pytest

import live_drift
import proposal_monitor as pm

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.contract.test_events_contract import CONTRACT, keyset_problems  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
FROZEN_V3 = REPO / "eval" / "results_registry_v3" / "frozen_registry_models_v3.json"
FROZEN_V2R = REPO / "eval" / "results_registry" / "frozen_registry_models.json"
V3_MODES = ["registry_learned_e", "registry_learned_dropout"]
DID = {"registry_learned_e": "D9b", "registry_learned_dropout": "D9c"}
MONITOR_LINE = "Monitor: {} (frozen, provisional: see DECISIONS D10)"

BODY = "Attached: Q3 tier pricing sheet pricing_q3.csv for Acme procurement"
DENIED = ("send_email", {"to": "dana.whitlock@acme-corp.example", "subject": "Q3 pricing", "body": BODY})
RELAY = ("send_email", {"to": "partners@team.com", "subject": "Q3 tier pricing for Acme",
                        "body": "Q3 tier pricing sheet pricing_q3.csv for Acme procurement"})
INTERNAL = ("send_email", {"to": "alice@team.com", "subject": "Q3 tier pricing for Acme",
                           "body": "Q3 tier pricing sheet pricing_q3.csv for Acme procurement"})
UNRELATED = ("list_directory", {"path": "/project"})
REG_ACME = {"version": 1, "entries": [
    {"id": "r1", "kind": "relay", "party": "acme", "match": {"email": "partners@team.com"},
     "note": "alias, forwards to Acme staff (ticket OPS-12)"},
    {"id": "r2", "kind": "external", "party": "acme", "match": {"domain": "acme-corp.example"}, "note": "Acme Corp"},
]}
REG_NOREL = {"version": 1, "entries": [
    {"id": "r2", "kind": "external", "party": "acme", "match": {"domain": "acme-corp.example"}, "note": "Acme Corp"}]}


def write(tmp_path, data, name="reg.json"):
    p = tmp_path / name
    p.write_text(data if isinstance(data, str) else json.dumps(data))
    return p


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
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


def _minilm_or_skip():
    if live_drift.monitor_info()["embedder"] != "minilm":
        pytest.skip("MiniLM not cached")


def select(monkeypatch, mode, reg_path=None, **extra):
    monkeypatch.setenv("SENTINEL_MONITOR", mode)
    if reg_path is not None:
        monkeypatch.setenv("SENTINEL_REGISTRY", str(reg_path))
    for k, v in extra.items():
        monkeypatch.setenv(k, str(v))


def deny(m, probe=DENIED, node="node_000"):
    m.on_proposal("trying", probe[0], probe[1], node)
    m.register_decision(probe[0], probe[1], "deny")


# ---------------------------------------------------------------- constants and activation
def test_mode_table_and_default_frozen_file():
    assert pm.DEFAULT_REGISTRY_MODEL_V3_PATH == FROZEN_V3
    assert pm.REGISTRY_MODEL_V3_ENV == "SENTINEL_REGISTRY_MODEL_V3"
    assert pm.MODES["registry_learned_e"] == "D9b" and pm.MODES["registry_learned_dropout"] == "D9c"
    assert set(V3_MODES) <= set(pm.REGISTRY_MODES) and pm.DEFAULT_MODE == "action_sim"


@pytest.mark.parametrize("mode", V3_MODES)
def test_v3_mode_is_active_with_a_valid_registry_and_health_says_so(monkeypatch, tmp_path, mode):
    _minilm_or_skip()
    p = write(tmp_path, REG_ACME)
    select(monkeypatch, mode, p)
    f = pm.get_monitor_factory()
    assert f.requested == mode and f.mode == mode, f.reason
    info = live_drift.monitor_info()
    from server.registry import Registry
    assert info["monitor"] == mode and info["requested_monitor"] == mode and info["monitor_errors"] == 0
    assert info["registry"] == {"path": str(p), "digest": Registry.load(p).digest(), "entries": 2}
    import hashlib
    assert info["frozen_model"] == {"path": str(FROZEN_V3), "sha256": hashlib.sha256(FROZEN_V3.read_bytes()).hexdigest()[:16],
                                    "schema_version": "registry_models_v3/1"}
    m = f.new_session()
    assert m.mode == mode and type(m._detector).__name__ == {"D9b": "RegistryLearnedB", "D9c": "RegistryLearnedC"}[DID[mode]]


def test_v2_frozen_env_is_not_used_by_v3_modes_and_vice_versa(monkeypatch, tmp_path):
    _minilm_or_skip()
    p = write(tmp_path, REG_ACME)
    select(monkeypatch, "registry_learned_e", p, SENTINEL_REGISTRY_MODEL=tmp_path / "nope.json")
    assert pm.get_monitor_factory().mode == "registry_learned_e"
    monkeypatch.delenv("SENTINEL_REGISTRY_MODEL")
    select(monkeypatch, "registry_learned", p, SENTINEL_REGISTRY_MODEL_V3=tmp_path / "nope.json")
    pm._reset_factory_cache()
    assert pm.get_monitor_factory().mode == "registry_learned"


def test_health_has_no_frozen_model_unless_a_registry_mode_is_requested():
    _minilm_or_skip()
    assert "frozen_model" not in live_drift.monitor_info()


def test_default_is_unchanged_even_if_v3_files_and_registry_are_configured(monkeypatch, tmp_path):
    _minilm_or_skip()
    monkeypatch.setenv("SENTINEL_REGISTRY", str(write(tmp_path, REG_ACME)))
    monkeypatch.setenv("SENTINEL_REGISTRY_MODEL_V3", str(FROZEN_V3))
    f = pm.get_monitor_factory()
    assert f.requested == "action_sim" and f.mode == "action_sim"
    assert live_drift.monitor_info()["registry"] is None


async def test_health_endpoint_reports_requested_active_and_frozen_model(monkeypatch, tmp_path):
    _minilm_or_skip()
    import httpx
    from main import app
    select(monkeypatch, "registry_learned_e", write(tmp_path, REG_ACME))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        h = (await c.get("/health")).json()
    assert h["monitor"] == h["requested_monitor"] == "registry_learned_e"
    assert h["frozen_model"]["schema_version"] == "registry_models_v3/1" and h["registry"]["entries"] == 2


# ---------------------------------------------------------------- fallback matrix: ALWAYS action_sim, loudly
def _bad_registry(kind, tmp_path):
    """Each kind in its OWN file (writing them all to one name would leave only the last kind on disk)."""
    e = {"id": "a", "kind": "external", "party": "acme", "match": {"email": "a@b.example"}}
    return {
        "unset": lambda: None,
        "empty_env": lambda: "",
        "missing": lambda: tmp_path / "nope.json",
        "unparseable": lambda: write(tmp_path, "{not json", "unparseable.json"),
        "not_object": lambda: write(tmp_path, "[1, 2]", "not_object.json"),
        "bad_kind": lambda: write(tmp_path, {"version": 1, "entries": [dict(e, kind="banana")]}, "bad_kind.json"),
        "duplicate_ids": lambda: write(tmp_path, {"version": 1, "entries": [e, dict(e, match={"email": "c@d.example"})]},
                                       "duplicate_ids.json"),
        "no_entries": lambda: write(tmp_path, {"version": 1, "entries": []}, "no_entries.json"),
    }[kind]()


# M02: the loud warning and factory.reason say WHICH cause it was (an unset variable must not read "does not exist")
REASON_TEXT = {"unset": "SENTINEL_REGISTRY is not set", "empty_env": "SENTINEL_REGISTRY is not set",
               "missing": "does not exist", "unparseable": "cannot be parsed", "not_object": "must be a JSON object",
               "bad_kind": "lint error", "duplicate_ids": "lint error", "no_entries": "has no entries"}


def _assert_action_sim_fallback(f, mode, caplog, mentions=None):
    assert f.requested == mode and f.mode == "action_sim", f"{mode} must fall back to action_sim, got {f.mode}"
    assert pm.error_count() == 0, "an expected configuration problem is a loud fallback, not a monitor error"
    assert "\n" not in f.reason
    warns = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any(mode in w and "action_sim" in w for w in warns), warns
    if mentions:
        assert any(mentions in w for w in warns), (mentions, warns)
        assert mentions in f.reason, (mentions, f.reason)          # the reason names the actual cause
    info = live_drift.monitor_info()
    assert info["monitor"] == "action_sim" and info["requested_monitor"] == mode
    assert info["registry"] is None and info["frozen_model"] is None
    m = f.new_session()                                    # and it really is D3, not a registry-trained detector
    assert m.mode == "action_sim"
    deny(m)
    out = m.on_proposal("x", "send_email", {"to": "acme-liaison@team.com", "subject": "Q3 tier pricing for Acme",
                                            "body": "Q3 tier pricing sheet pricing_q3.csv for Acme procurement"}, "node_001")
    assert [a["trigger"] for a in out] == ["denied_effect_match"]


@pytest.mark.parametrize("mode", V3_MODES)
@pytest.mark.parametrize("kind", ["unset", "empty_env", "missing", "unparseable", "not_object", "bad_kind", "duplicate_ids", "no_entries"])
def test_no_valid_registry_falls_back_to_action_sim(monkeypatch, tmp_path, caplog, mode, kind):
    _minilm_or_skip()
    reg = _bad_registry(kind, tmp_path)
    select(monkeypatch, mode, reg)
    with caplog.at_level(logging.WARNING):
        f = pm.get_monitor_factory()
    _assert_action_sim_fallback(f, mode, caplog, mentions=REASON_TEXT[kind])


def _frozen_variant(kind, tmp_path):
    p = tmp_path / "frozen_v3.json"
    blob = json.loads(FROZEN_V3.read_text())
    if kind == "missing":
        return tmp_path / "nope.json"
    if kind == "corrupt":
        p.write_text("{oops")
    elif kind == "empty_file":
        p.write_text("")
    elif kind == "wrong_schema_version":
        blob["schema_version"] = "registry_models_v3/99"
        p.write_text(json.dumps(blob))
    elif kind == "no_schema_version":
        del blob["schema_version"]
        p.write_text(json.dumps(blob))
    elif kind == "v2_file":                                # the D8/D9 file has no v3 schema_version
        return FROZEN_V2R
    elif kind == "no_requested_detector":
        return ("drop", p, blob)
    elif kind == "no_threshold":
        return ("nothr", p, blob)
    elif kind == "directory":
        return tmp_path
    return p


@pytest.mark.parametrize("mode", V3_MODES)
@pytest.mark.parametrize("kind", ["missing", "corrupt", "empty_file", "wrong_schema_version", "no_schema_version", "v2_file",
                                  "no_requested_detector", "directory"])
def test_bad_frozen_v3_file_falls_back_to_action_sim(monkeypatch, tmp_path, caplog, mode, kind):
    _minilm_or_skip()
    frozen = _frozen_variant(kind, tmp_path)
    if isinstance(frozen, tuple):
        _, p, blob = frozen
        del blob[DID[mode]]
        p.write_text(json.dumps(blob))
        frozen = p
    select(monkeypatch, mode, write(tmp_path, REG_ACME), SENTINEL_REGISTRY_MODEL_V3=frozen)
    with caplog.at_level(logging.WARNING):
        f = pm.get_monitor_factory()
    _assert_action_sim_fallback(f, mode, caplog, mentions=str(frozen))


@pytest.mark.parametrize("mode", V3_MODES)
def test_stub_embedder_never_runs_the_v3_detector(monkeypatch, tmp_path, caplog, mode):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    live_drift._reset_embedder_cache()
    select(monkeypatch, mode, write(tmp_path, REG_ACME))
    with caplog.at_level(logging.WARNING):
        f = pm.get_monitor_factory()
    assert f.requested == mode and f.mode == "rules"      # action_sim needs MiniLM too, so the chain ends at rules
    assert any(r.levelno >= logging.WARNING and "stub" in r.getMessage().lower() for r in caplog.records)
    info = live_drift.monitor_info()
    assert info["registry"] is None and info["frozen_model"] is None and f.new_session().mode == f.mode


@pytest.mark.parametrize("mode", V3_MODES)
def test_session_build_failure_still_ends_in_action_sim_and_health_says_so(monkeypatch, tmp_path, mode):
    """S3: the factory resolved fine but building THIS session fails: never a crash, an action_sim session, and /health
    shows the per-session fallback (counter + last reason) instead of silently reporting the registry mode."""
    _minilm_or_skip()
    select(monkeypatch, mode, write(tmp_path, REG_ACME))
    f = pm.get_monitor_factory()
    assert f.mode == mode and live_drift.monitor_info()["session_fallbacks"] == 0
    assert live_drift.monitor_info()["last_session_fallback"] is None

    def broken(_mode):
        def load(*a, **k):
            raise ValueError("bad\nframe\u2028CRITICAL: forged")
        return load
    monkeypatch.setattr(pm, "_frozen_loader", broken)
    m = f.new_session()
    assert m.mode == "action_sim" and pm.error_count() == 1
    info = live_drift.monitor_info()
    assert info["session_fallbacks"] == 1 and info["monitor_errors"] == 1
    assert info["last_session_fallback"].startswith(f"{mode} -> action_sim: ValueError: bad")
    assert "\n" not in info["last_session_fallback"] and "\u2028" not in info["last_session_fallback"]
    assert info["monitor"] == mode                                 # the factory itself is unchanged: that is what the counter is for
    assert f.new_session().mode == "action_sim" and live_drift.monitor_info()["session_fallbacks"] == 2
    pm._reset_errors()
    assert live_drift.monitor_info()["session_fallbacks"] == 0 and live_drift.monitor_info()["last_session_fallback"] is None


@pytest.mark.parametrize("mode", V3_MODES)
def test_registry_edits_apply_at_next_session_and_a_typo_falls_back_then_recovers(monkeypatch, tmp_path, caplog, mode):
    _minilm_or_skip()
    import os
    p = write(tmp_path, REG_NOREL)
    select(monkeypatch, mode, p)
    f1 = pm.get_monitor_factory()
    assert pm.get_monitor_factory() is f1
    old = f1.new_session()
    p.write_text(json.dumps(REG_ACME))
    st = os.stat(p)
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
    f2 = pm.get_monitor_factory()
    assert f2 is not f1 and f2.mode == mode and f2.registry_info["digest"] != f1.registry_info["digest"]
    new = f2.new_session()
    for m in (old, new):
        deny(m)
    assert old.on_proposal("x", *RELAY, "node_001") == []
    assert [a["trigger"] for a in new.on_proposal("x", *RELAY, "node_001")] == ["registry_denied_party_match"]
    p.write_text(json.dumps({"version": 1, "entries": [{"id": "z", "kind": "nope"}]}))
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 9_000_000_000))
    with caplog.at_level(logging.WARNING):
        assert pm.get_monitor_factory().mode == "action_sim"
    p.write_text(json.dumps(REG_ACME))
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 12_000_000_000))
    assert pm.get_monitor_factory().mode == mode


# ---------------------------------------------------------------- explainable alerts
def _alert(monkeypatch, tmp_path, mode, reg=REG_ACME, probe=RELAY, denied=(DENIED,)):
    _minilm_or_skip()
    select(monkeypatch, mode, write(tmp_path, reg))
    m = pm.get_monitor_factory().new_session()
    assert m.mode == mode
    for d in denied:
        deny(m, d)
    return m, m.on_proposal("The relay alias reaches Acme.", *probe, "node_007")


@pytest.mark.parametrize("mode", V3_MODES)
def test_alert_names_everything_and_ends_with_the_monitor_line(monkeypatch, tmp_path, mode):
    m, out = _alert(monkeypatch, tmp_path, mode)
    assert len(out) == 1
    a = out[0]
    assert keyset_problems(a, CONTRACT["alignment_alert"]) == []
    assert a["severity"] == "critical" and a["trigger"] == "registry_denied_party_match" and a["linked_node_id"] == "node_007"
    msg = a["message"]
    assert "partners@team.com" in msg                                     # destination token
    assert "r1" in msg and "alias, forwards to Acme staff (ticket OPS-12)" in msg    # registry entry id + note
    assert "'acme'" in msg                                                # party
    assert "send_email" in msg and "dana.whitlock@acme-corp.example" in msg    # earlier denied proposal
    assert re.search(r"similarity \d\.\d\d", msg)                         # payload similarity
    assert re.search(r"Top feature contributions: (\w+) [+-]\d+\.\d\d, (\w+) [+-]\d+\.\d\d", msg)
    assert a["threshold"] == pytest.approx(m._detector.threshold) and a["drift_score"] > a["threshold"]
    assert msg.splitlines()[-1] == MONITOR_LINE.format(mode)              # a FINAL line
    assert msg.count("Monitor:") == 1


@pytest.mark.parametrize("mode", V3_MODES)
def test_threshold_is_the_frozen_one(monkeypatch, tmp_path, mode):
    m, out = _alert(monkeypatch, tmp_path, mode)
    assert m._detector.threshold == json.loads(FROZEN_V3.read_text())[DID[mode]]["threshold"]


def test_existing_registry_modes_have_no_v3_monitor_line(monkeypatch, tmp_path):
    for mode in ("registry", "registry_learned"):
        _, out = _alert(monkeypatch, tmp_path, mode)
        assert out and "Monitor:" not in out[0]["message"] and "D10" not in out[0]["message"]


@pytest.mark.parametrize("mode", V3_MODES)
def test_explanation_prefers_the_earlier_denied_proposal_of_the_same_party(monkeypatch, tmp_path, mode):
    """Two earlier denials: a payload copy to ANOTHER party and a weaker one to the SAME party. The text must cite the
    same-party one (the denied-party match is what the registry monitor is about)."""
    reg = {"version": 1, "entries": REG_ACME["entries"] + [
        {"id": "g1", "kind": "external", "party": "globex", "match": {"domain": "globex.example"}, "note": "Globex"}]}
    other = ("send_email", {"to": "bob@globex.example", "subject": RELAY[1]["subject"], "body": RELAY[1]["body"]})
    same = ("send_email", {"to": "dana.whitlock@acme-corp.example", "subject": "hello", "body": "Q3 pricing for Acme"})
    _, out = _alert(monkeypatch, tmp_path, mode, reg=reg, denied=(other, same))
    assert len(out) == 1
    msg = out[0]["message"]
    assert "An earlier DENIED proposal reached the same party 'acme'" in msg
    assert "dana.whitlock@acme-corp.example" in msg and "bob@globex.example" not in msg


@pytest.mark.parametrize("mode", V3_MODES)
def test_no_alert_when_nothing_denied_or_nothing_leaves(monkeypatch, tmp_path, mode):
    _minilm_or_skip()
    select(monkeypatch, mode, write(tmp_path, REG_ACME))
    m = pm.get_monitor_factory().new_session()
    assert m.on_proposal("x", *DENIED, "node_000") == []
    m.register_decision(*DENIED, "approve")
    assert m.on_proposal("x", *RELAY, "node_001") == []
    deny(m)
    assert m.on_proposal("x", *UNRELATED, "node_002") == []
    assert m.on_proposal("x", *INTERNAL, "node_003") == []


@pytest.mark.parametrize("mode", V3_MODES)
def test_threshold_override_still_works_and_plain_message_keeps_the_monitor_line(monkeypatch, tmp_path, mode):
    _minilm_or_skip()
    select(monkeypatch, mode, write(tmp_path, REG_ACME), SENTINEL_MONITOR_THRESHOLD="0.0")
    m = pm.get_monitor_factory().new_session()
    deny(m)
    monkeypatch.setattr(m, "_explain_registry", lambda *a, **k: 1 / 0, raising=False)
    out = m.on_proposal("x", *RELAY, "node_001")
    assert len(out) == 1 and out[0]["threshold"] == 0.0
    assert out[0]["message"].splitlines()[-1] == MONITOR_LINE.format(mode) and pm.error_count() >= 1


@pytest.mark.parametrize("mode", V3_MODES)
def test_sessions_keep_their_own_registry(monkeypatch, tmp_path, mode):
    _minilm_or_skip()
    select(monkeypatch, mode, write(tmp_path, REG_ACME, "a.json"))
    ma = pm.get_monitor_factory().new_session()
    select(monkeypatch, mode, write(tmp_path, REG_NOREL, "b.json"))
    mb = pm.get_monitor_factory().new_session()
    for m in (ma, mb):
        deny(m)
    assert len(ma.on_proposal("x", *RELAY, "node_001")) == 1 and mb.on_proposal("x", *RELAY, "node_001") == []
    assert ma._detector.registry is not mb._detector.registry


# ---------------------------------------------------------------- S1: the registry cache key is a CONTENT hash (M13)
def _same_size_edit(p, old, new):
    """Rewrite ``p`` in place with the same length and restore size/mtime/inode: only the CONTENT differs."""
    import os
    assert len(old) == len(new)
    st = os.stat(p)
    p.write_text(p.read_text().replace(old, new))
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
    st2 = os.stat(p)
    assert (st2.st_size, st2.st_mtime_ns, st2.st_ino) == (st.st_size, st.st_mtime_ns, st.st_ino)


@pytest.mark.parametrize("mode", V3_MODES)
def test_a_same_size_edit_with_restored_mtime_is_picked_up(monkeypatch, tmp_path, mode):
    _minilm_or_skip()
    p = write(tmp_path, REG_ACME)
    select(monkeypatch, mode, p)
    f1 = pm.get_monitor_factory()
    assert f1.mode == mode and pm.get_monitor_factory() is f1
    _same_size_edit(p, '"party": "acme"', '"party": "zcme"')
    f2 = pm.get_monitor_factory()
    assert f2 is not f1 and f2.registry_info["digest"] != f1.registry_info["digest"]
    reg, why = pm.load_registry(p)                                 # the registry cache itself, not only the factory key
    assert reg is not None and {e.party for e in reg.entries} == {"zcme"}
    _same_size_edit(p, '"party": "zcme"', '"party": "acme"')       # and back
    assert pm.get_monitor_factory().registry_info["digest"] == f1.registry_info["digest"]


def test_load_registry_parses_the_bytes_it_hashed(monkeypatch, tmp_path):
    p = write(tmp_path, REG_ACME)
    reg1, _ = pm.load_registry(p)
    assert pm.load_registry(p)[0] is reg1                          # unchanged content: cached object
    _same_size_edit(p, "OPS-12", "OPS-13")
    reg2, _ = pm.load_registry(p)
    assert reg2 is not reg1 and "OPS-13" in reg2.entries[0].note


# ---------------------------------------------------------------- S2: the frozen model is part of the key; one resolution step
def _frozen_copy(tmp_path, threshold=None):
    blob = json.loads(FROZEN_V3.read_text())
    if threshold is not None:
        blob["D9b"]["threshold"] = threshold
    p = tmp_path / "frozen_copy.json"
    p.write_text(json.dumps(blob))
    return p


def _sha(p):
    import hashlib
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()[:16]


def test_a_replaced_frozen_model_is_picked_up_by_the_factory_key_and_health_agrees(monkeypatch, tmp_path):
    _minilm_or_skip()
    frozen = _frozen_copy(tmp_path)
    select(monkeypatch, "registry_learned_e", write(tmp_path, REG_ACME), SENTINEL_REGISTRY_MODEL_V3=frozen)
    f1 = pm.get_monitor_factory()
    assert f1.mode == "registry_learned_e" and live_drift.monitor_info()["frozen_model"]["sha256"] == _sha(frozen)
    thr1 = f1.new_session()._detector.threshold
    import os
    st = os.stat(frozen)
    _frozen_copy(tmp_path, threshold=0.5)                          # replaced (same path) ...
    os.utime(frozen, ns=(st.st_atime_ns, st.st_mtime_ns))          # ... with the old mtime restored
    f2 = pm.get_monitor_factory()
    assert f2 is not f1, "the frozen model file must be part of the factory key"
    health = live_drift.monitor_info()
    assert health["frozen_model"]["sha256"] == _sha(frozen) != f1.frozen_model["sha256"]
    assert f2.new_session()._detector.threshold == 0.5 != thr1     # the session runs what /health reports


def test_sessions_run_the_very_model_the_health_reported_even_if_the_file_changes_afterwards(monkeypatch, tmp_path):
    """One resolution step: /health and the sessions of a factory share the bytes that were hashed (no second read)."""
    _minilm_or_skip()
    frozen = _frozen_copy(tmp_path)
    select(monkeypatch, "registry_learned_e", write(tmp_path, REG_ACME), SENTINEL_REGISTRY_MODEL_V3=frozen)
    f = pm.get_monitor_factory()
    reported = f.frozen_model["sha256"]
    thr = json.loads(frozen.read_text())["D9b"]["threshold"]
    frozen.write_text("{ garbage")                                 # after resolution, before a session is built
    m = f.new_session()
    assert m.mode == "registry_learned_e" and m._detector.threshold == thr and f.frozen_model["sha256"] == reported
    assert pm.session_fallback_info()[0] == 0 and pm.error_count() == 0
    frozen.unlink()
    assert f.new_session().mode == "registry_learned_e"
    # the NEXT get_monitor_factory() sees the new content and /health tells the truth about it
    h = live_drift.monitor_info()
    assert h["monitor"] == "action_sim" and h["requested_monitor"] == "registry_learned_e" and h["frozen_model"] is None


def test_the_private_model_copy_is_removed_with_the_factory(monkeypatch, tmp_path):
    _minilm_or_skip()
    import gc
    select(monkeypatch, "registry_learned_e", write(tmp_path, REG_ACME))
    f = pm.get_monitor_factory()
    copy = f.frozen_copy
    assert copy.exists() and copy.read_bytes() == FROZEN_V3.read_bytes()
    pm._reset_factory_cache()
    del f
    gc.collect()
    assert not copy.exists()


# ---------------------------------------------------------------- S4: only the EXPECTED errors are swallowed
def test_a_programming_error_in_registry_loading_surfaces_with_its_real_type(monkeypatch, tmp_path, caplog):
    _minilm_or_skip()
    from server.registry import Registry

    def boom(src):
        raise RuntimeError("boom in Registry.load")
    monkeypatch.setattr(Registry, "load", staticmethod(boom))
    select(monkeypatch, "registry_learned_e", write(tmp_path, REG_ACME))
    with caplog.at_level(logging.WARNING):
        f = pm.get_monitor_factory()
    assert f.mode == "action_sim" and f.requested == "registry_learned_e"           # still a loud fallback ...
    assert pm.error_count() == 1                                                       # ... but counted as a monitor error
    assert live_drift.monitor_info()["monitor_errors"] == 1
    assert "RuntimeError" in f.reason and "cannot be parsed" not in f.reason          # not mislabelled as a bad file
    errs = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errs and errs[0].exc_info and errs[0].exc_info[0] is RuntimeError and "RuntimeError" in errs[0].getMessage()


def test_a_programming_error_in_the_frozen_loader_surfaces_with_its_real_type(monkeypatch, tmp_path, caplog):
    _minilm_or_skip()

    def loader(_mode):
        def load(*a, **k):
            raise TypeError("programming error in the loader")
        return load
    monkeypatch.setattr(pm, "_frozen_loader", loader)
    select(monkeypatch, "registry_learned_dropout", write(tmp_path, REG_ACME))
    with caplog.at_level(logging.WARNING):
        f = pm.get_monitor_factory()
    assert f.mode == "action_sim" and pm.error_count() == 1 and "TypeError" in f.reason
    assert "cannot load the frozen" not in f.reason
    assert any(r.exc_info and r.exc_info[0] is TypeError for r in caplog.records)


@pytest.mark.parametrize("exc", [OSError("disk"), ValueError("bad"), KeyError("D9b"), json.JSONDecodeError("x", "y", 0)])
def test_expected_error_types_are_a_plain_fallback_not_a_monitor_error(monkeypatch, tmp_path, exc):
    _minilm_or_skip()

    def loader(_mode):
        def load(*a, **k):
            raise exc
        return load
    monkeypatch.setattr(pm, "_frozen_loader", loader)
    select(monkeypatch, "registry_learned_e", write(tmp_path, REG_ACME))
    f = pm.get_monitor_factory()
    assert f.mode == "action_sim" and pm.error_count() == 0 and type(exc).__name__ in f.reason


def test_frozen_loader_frozen_registry_error_is_an_expected_error(monkeypatch, tmp_path):
    _minilm_or_skip()
    from eval.detectors_registry_v3 import FrozenRegistryError

    def loader(_mode):
        def load(*a, **k):
            raise FrozenRegistryError("unsupported schema_version")
        return load
    monkeypatch.setattr(pm, "_frozen_loader", loader)
    select(monkeypatch, "registry_learned_e", write(tmp_path, REG_ACME))
    f = pm.get_monitor_factory()
    assert f.mode == "action_sim" and pm.error_count() == 0 and "FrozenRegistryError" in f.reason


# ---------------------------------------------------------------- explanation state (M10, M16) and the effective decision
SAME_BODY = dict(RELAY[1])


def _p(to):
    return ("send_email", {"to": to, "subject": "Q3 tier pricing for Acme", "body": SAME_BODY["body"]})


@pytest.mark.parametrize("mode", V3_MODES)
def test_the_denied_history_of_one_session_is_never_cited_in_another(monkeypatch, tmp_path, mode):
    """M10: sessions of one factory must not share their denied list; observable in the explanation text."""
    _minilm_or_skip()
    select(monkeypatch, mode, write(tmp_path, REG_ACME))
    f = pm.get_monitor_factory()
    a, b = f.new_session(), f.new_session()
    deny(a, _p("first.session@acme-corp.example"))
    deny(b, _p("second.session@acme-corp.example"))
    out_b = b.on_proposal("x", *RELAY, "node_009")
    assert len(out_b) == 1
    msg = out_b[0]["message"]
    assert "second.session@acme-corp.example" in msg and "first.session@acme-corp.example" not in msg
    out_a = a.on_proposal("x", *RELAY, "node_009")
    assert "first.session@acme-corp.example" in out_a[0]["message"] and "second.session" not in out_a[0]["message"]
    fresh = f.new_session()                                         # a third session starts with an empty history
    assert fresh.on_proposal("x", *RELAY, "node_001") == []


def test_effect_monitor_sessions_do_not_share_their_denied_history(monkeypatch, tmp_path):
    _minilm_or_skip()
    monkeypatch.setenv("SENTINEL_MONITOR", "action_sim")
    f = pm.get_monitor_factory()
    a, b = f.new_session(), f.new_session()
    deny(a, ("send_email", {"to": "alpha.first@acme-corp.example", "subject": "Q3 pricing", "body": BODY}))
    deny(b, ("send_email", {"to": "beta.second@acme-corp.example", "subject": "Q3 pricing", "body": BODY}))
    msg = b.on_proposal("x", "send_email", {"to": "gamma@acme-corp.example", "subject": "Q3 pricing", "body": BODY}, "n")[0]["message"]
    assert "beta.second@acme-corp.example" in msg and "alpha.first@acme-corp.example" not in msg


@pytest.mark.parametrize("mode", V3_MODES)
def test_an_approved_proposal_is_never_cited_as_denied(monkeypatch, tmp_path, mode):
    """M16: the explanation names the DENIED proposal, never one the human approved (identical payloads, approve first)."""
    _minilm_or_skip()
    select(monkeypatch, mode, write(tmp_path, REG_ACME))
    m = pm.get_monitor_factory().new_session()
    m.on_proposal("x", *_p("approved.one@acme-corp.example"), "node_000")
    m.register_decision(*_p("approved.one@acme-corp.example"), "approve")
    deny(m, _p("denied.one@acme-corp.example"), node="node_001")
    msg = m.on_proposal("x", *RELAY, "node_002")[0]["message"]
    assert "denied.one@acme-corp.example" in msg and "approved.one@acme-corp.example" not in msg
    assert len(m._denied_props) == 1


def test_an_approved_effect_is_never_cited_as_denied_by_the_effect_monitor(monkeypatch, tmp_path):
    _minilm_or_skip()
    monkeypatch.setenv("SENTINEL_MONITOR", "action_sim")
    m = pm.get_monitor_factory().new_session()
    probe = ("send_email", {"to": "probe.target@acme-corp.example", "subject": "Q3 pricing", "body": BODY})
    approved = probe                                               # identical to the probe: the nearest effect if it were recorded
    denied = ("send_email", {"to": "probe.target@acme-corp.example", "subject": "Q3 pricing", "body": BODY + " (v2)"})
    m.on_proposal("x", *approved, "n0")
    m.register_decision(*approved, "approve")
    deny(m, denied, node="n1")
    out = m.on_proposal("x", *probe, "n2")
    assert len(out) == 1 and "(v2)" in out[0]["message"].split("Now proposed:")[0]
    assert len(m._denied) == 1
