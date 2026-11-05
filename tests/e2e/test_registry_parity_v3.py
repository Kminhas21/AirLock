"""Offline-vs-live parity for the OPT-IN v3 monitors SENTINEL_MONITOR=registry_learned_e (frozen D9b) / registry_learned_dropout (D9c).

ALL 60 traces of eval/final_v3/traces.json, each with its AUTHORED1 registry (eval/registries_v3/author1.json) written to a
tmp file as SENTINEL_REGISTRY: the live alert set (TestClient + scripted FakeClient, real MiniLM, human decisions from the
trace) must equal the OFFLINE frozen detector's alert set (eval.detectors.run_trace on the trace as the live loop sees it,
same registry), and every alert must precede the tool_pending it concerns. No detector or threshold is touched here: a
mismatch is a finding, not something to reconcile.
"""
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient  # noqa: F401  (used through run_live)

import live_drift
import proposal_monitor as pm
from fakes import of

from test_registry_parity import (TRIGGER, assert_frame_order, fake_models, live_ordinals, merged_trace,  # noqa: F401
                                  run_live)

REPO = Path(__file__).resolve().parents[2]
from eval.detectors import run_trace  # noqa: E402
from eval.detectors_registry_v3 import load_frozen_registry_v3  # noqa: E402
from eval.embed import get_shared_embedder  # noqa: E402

V3 = {t["id"]: t for t in json.loads((REPO / "eval/final_v3/traces.json").read_text())}
AUTHOR1 = json.loads((REPO / "eval/registries_v3/author1.json").read_text())
FROZEN_V3 = REPO / "eval/results_registry_v3/frozen_registry_models_v3.json"
MODE_TO_ID = {"registry_learned_e": "D9b", "registry_learned_dropout": "D9c"}
IDS = sorted(V3)
CASES = [(tid, mode) for mode in MODE_TO_ID for tid in IDS]


@pytest.fixture(scope="module", autouse=True)
def _real_model():
    mp = pytest.MonkeyPatch()
    mp.setenv("SENTINEL_EMBEDDER", "minilm")
    mp.delenv("SENTINEL_WS_TOKEN", raising=False)
    live_drift._reset_embedder_cache()
    pm._reset_factory_cache()
    if live_drift.monitor_info()["embedder"] != "minilm":
        mp.undo()
        pytest.skip("MiniLM not cached")
    yield
    mp.undo()
    live_drift._reset_embedder_cache()
    pm._reset_factory_cache()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SENTINEL_EMBEDDER", "minilm")
    for k in ("SENTINEL_MONITOR_MODEL", "SENTINEL_REGISTRY_MODEL", "SENTINEL_REGISTRY_MODEL_V3", "SENTINEL_MONITOR_THRESHOLD",
              "SENTINEL_WS_TOKEN"):
        monkeypatch.delenv(k, raising=False)


def offline_ordinals(trace: dict, mode: str, registry: dict) -> set[int]:
    did = MODE_TO_ID[mode]
    det = load_frozen_registry_v3(FROZEN_V3, get_shared_embedder(), registry, only=[did])[did]
    res = run_trace(det, merged_trace(trace))
    return {k for k, st in enumerate(s for s in res.steps if s.tool is not None) if st.alert}


def test_all_60_v3_traces_have_an_authored1_registry():
    assert len(V3) == 60 and set(V3) == set(AUTHOR1)


def test_selection_is_not_vacuous():
    for mode in MODE_TO_ID:
        per = {t: offline_ordinals(V3[t], mode, AUTHOR1[t]) for t in IDS}
        assert sum(len(v) for v in per.values()) >= 15 and sum(bool(v) for v in per.values()) >= 15, mode


@pytest.mark.parametrize("tid,mode", CASES)
def test_live_alerts_equal_offline_alerts(tid, mode, monkeypatch, tmp_path, fake_models):
    p = tmp_path / "registry.json"
    p.write_text(json.dumps(AUTHOR1[tid]))
    monkeypatch.setenv("SENTINEL_MONITOR", mode)
    monkeypatch.setenv("SENTINEL_REGISTRY", str(p))
    factory = pm.get_monitor_factory()
    assert factory.mode == mode, f"the v3 monitor was not active: {factory.reason}"      # not a silent fallback
    events = run_live(V3[tid], fake_models)
    assert events[-1]["event"] == "session_complete" and events[-1]["reason"] == "finished"
    assert live_ordinals(events) == offline_ordinals(V3[tid], mode, AUTHOR1[tid]), tid
    assert_frame_order(events)
    alerts = [a for a in of(events, "alignment_alert") if a["trigger"] == TRIGGER]
    assert all(a["message"].splitlines()[-1] == f"Monitor: {mode} (frozen, provisional: see DECISIONS D10)" for a in alerts)
    other = [e for e in of(events, "alignment_alert") if e["trigger"] not in (TRIGGER, "goal_persistence")]
    assert other == [], "a registry mode must not also raise the rules / D3 alerts"
