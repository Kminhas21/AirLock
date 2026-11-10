import events
import live_drift


def test_drift_update_carries_the_threshold_when_given_and_omits_it_otherwise():
    base = dict(step_index=1, node_id="n", coordinates={"x": 0.0}, metrics={"m": 1.0}, mahalanobis_distance=2.0, baseline_breached=False)
    assert "threshold" not in events.drift_update(**base)                       # recorded replays: unchanged shape
    assert events.drift_update(**base, threshold=3.368)["threshold"] == 3.368


def test_the_live_session_adapter_reports_its_detectors_active_threshold(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    live_drift._reset_embedder_cache()
    sd = live_drift.SessionDrift()
    out = sd.observe_reasoning("I will read the file and summarise it.", "n1")
    upd = [e for e in out if e["event"] == "drift_update"][0]
    assert upd["threshold"] == sd.threshold and upd["threshold"] > 0
    live_drift._reset_embedder_cache()
