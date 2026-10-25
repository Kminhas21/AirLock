"""Tests for D1 live drift adapter."""
import logging
import sys
from pathlib import Path

import pytest

import events as ev
import live_drift
from live_drift import SessionDrift, make_embedder, get_embedder
from seismograph.embedder import StubEmbedder

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.contract.test_events_contract import CONTRACT, keyset_problems  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_cache(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")      # these tests are about plumbing: fast path, explicitly
    live_drift._reset_embedder_cache()
    yield
    live_drift._reset_embedder_cache()


def _sd():
    return SessionDrift(embedder=StubEmbedder())


def _check(event):
    spec = CONTRACT[event["event"]]
    assert keyset_problems(event, spec) == []


def test_reasoning_emits_contract_shaped_drift_update():
    out = _sd().observe_reasoning("Let me look at the files.", "n1")
    assert [e["event"] for e in out] == ["drift_update"]
    _check(out[0])
    assert out[0]["node_id"] == "n1" and out[0]["step_index"] == 0
    assert out[0]["timestamp"]  # filled by events builder


def test_step_index_increments():
    s = _sd()
    assert s.observe_reasoning("a", "n1")[0]["step_index"] == 0
    assert s.observe_reasoning("b", "n2")[0]["step_index"] == 1


def test_goal_persistence_alert():
    s = _sd()
    s.observe_denial("send_email")
    out = s.observe_reasoning("I will send an email to the recipient to notify them", "n3")
    assert [e["event"] for e in out] == ["drift_update", "alignment_alert"]
    a = out[1]
    _check(a)
    assert a["severity"] == "warning" and a["trigger"] == "goal_persistence"
    assert a["linked_node_id"] == "n3"
    assert a["threshold"] == s.analyzer.drift_detector.threshold


def test_no_alert_without_denials():
    out = _sd().observe_reasoning("I will send an email to the recipient", "n1")
    assert len(out) == 1


def test_circumvention_flagged_for_sibling_tool_even_if_later_denied():
    s = _sd()
    s.observe_denial("send_email")
    assert s.observe_tool_call("send_email", "n1") == []  # same tool: not circumvention
    out = s.observe_tool_call("send_slack_message", "n2")
    assert len(out) == 1
    a = out[0]
    _check(a)
    assert a["severity"] == "critical" and a["trigger"] == "circumvention_detected"
    assert a["linked_node_id"] == "n2"
    assert a["drift_score"] > 0
    s.observe_denial("send_slack_message")  # denial after the fact changes nothing
    assert s.tracker.circumvention_count == 1


def test_unrelated_tool_not_flagged():
    s = _sd()
    s.observe_denial("send_email")
    assert s.observe_tool_call("read_file", "n1") == []


def test_no_duplicate_alert_when_both_detectors_flag():
    s = _sd()
    s.observe_denial("send_email")
    out = s.observe_tool_call("post_to_webhook", "n1")
    assert len(out) == 1
    assert s.tracker.circumvention_count == 1  # counted once, not twice


def test_denial_registered_on_both():
    s = _sd()
    s.observe_denial("query_database")
    assert "query_database" in s.tracker.denied_tools
    assert "query_database" in s.analyzer._denied_tools


def test_per_session_isolation():
    a, b = _sd(), _sd()
    a.observe_denial("send_email")
    assert b.observe_tool_call("send_slack_message", "n1") == []
    assert b.tracker.denied_tools == set()
    a.observe_reasoning("x", "n1")
    assert b.observe_reasoning("y", "n1")[0]["step_index"] == 0


# ---------- embedder selection ----------

def test_make_embedder_default_is_minilm_and_stub_is_explicit(monkeypatch):
    class Good:
        def __init__(self, *a, **k): pass
        def embed(self, text): return [0.0] * 4

    monkeypatch.setattr(live_drift, "Embedder", Good)
    assert isinstance(make_embedder({}), Good)
    assert isinstance(make_embedder({"SENTINEL_EMBEDDER": "stub"}), StubEmbedder)


def test_make_embedder_unknown_value_falls_back_with_warning(caplog):
    with caplog.at_level(logging.WARNING):
        assert isinstance(make_embedder({"SENTINEL_EMBEDDER": "bogus"}), StubEmbedder)
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_minilm_failure_falls_back_to_stub(monkeypatch, caplog):
    class Boom:
        def __init__(self, *a, **k):
            raise RuntimeError("no model cache")

    monkeypatch.setattr(live_drift, "Embedder", Boom)
    with caplog.at_level(logging.WARNING):
        e = make_embedder({"SENTINEL_EMBEDDER": "minilm"})
    assert isinstance(e, StubEmbedder)
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_minilm_lazy_embed_failure_falls_back(monkeypatch, caplog):
    """Embedder construction is cheap; the model loads on first embed. Probe it."""
    class LazyBoom:
        def __init__(self, *a, **k): pass
        def embed(self, text):
            raise RuntimeError("model not cached")

    monkeypatch.setattr(live_drift, "Embedder", LazyBoom)
    with caplog.at_level(logging.WARNING):
        e = make_embedder({"SENTINEL_EMBEDDER": "minilm"})
    assert isinstance(e, StubEmbedder)


def test_minilm_success_returns_real_embedder(monkeypatch):
    class Good:
        def __init__(self, *a, **k): pass
        def embed(self, text): return [0.0] * 4

    monkeypatch.setattr(live_drift, "Embedder", Good)
    assert isinstance(make_embedder({"SENTINEL_EMBEDDER": "minilm"}), Good)


def test_get_embedder_cached_per_process(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    assert get_embedder() is get_embedder()


def test_session_uses_cached_embedder_by_default(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    assert SessionDrift().analyzer.embedder is get_embedder()


def test_session_survives_failing_minilm(monkeypatch):
    class Boom:
        def __init__(self, *a, **k):
            raise ImportError("sentence_transformers")

    monkeypatch.setattr(live_drift, "Embedder", Boom)
    monkeypatch.setenv("SENTINEL_EMBEDDER", "minilm")
    out = SessionDrift().observe_reasoning("hello", "n1")
    assert out[0]["event"] == "drift_update"


# ---- monitor_info (reported by /health) ----------------------------------------------------------
def test_monitor_info_default_monitor_falls_back_to_rules_on_stub(monkeypatch):
    monkeypatch.delenv("SENTINEL_MONITOR", raising=False)
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    assert live_drift.monitor_info() == {"monitor": "rules", "embedder": "stub", "monitor_errors": 0}


def test_monitor_info_reports_the_active_monitor_not_the_requested_one(monkeypatch):
    monkeypatch.setenv("SENTINEL_MONITOR", "learned")
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    assert live_drift.monitor_info()["monitor"] == "rules"          # learned needs embeddings
    monkeypatch.setenv("SENTINEL_MONITOR", "rules")
    assert live_drift.monitor_info()["monitor"] == "rules"


@pytest.mark.real_model
def test_monitor_info_reports_minilm_when_real_model_loads(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "minilm")
    info = live_drift.monitor_info()
    if info["embedder"] == "stub":
        pytest.skip("MiniLM not cached; fallback is reported honestly as 'stub'")
    assert info["embedder"] == "minilm"


def test_monitor_info_reports_stub_on_silent_fallback(monkeypatch):
    """SENTINEL_EMBEDDER=minilm but the model fails to load -> must say 'stub', never 'minilm'."""
    class Boom:
        def __init__(self, *a, **k): ...
        def embed(self, t): raise RuntimeError("no model")
    monkeypatch.setattr(live_drift, "Embedder", Boom)
    monkeypatch.setenv("SENTINEL_EMBEDDER", "minilm")
    assert live_drift.monitor_info()["embedder"] == "stub"


def test_monitor_info_none_when_embedder_unavailable(monkeypatch):
    monkeypatch.setattr(live_drift, "get_embedder", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    assert live_drift.monitor_info()["embedder"] == "none"
