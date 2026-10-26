"""Offline-vs-live parity for the OPT-IN registry monitors: SENTINEL_MONITOR=registry (frozen D8) / registry_learned (D9).

For every trace the trace's destination registry is written to a tmp file and given to the live backend through
SENTINEL_REGISTRY at session start; the live app (TestClient + scripted FakeClient, real MiniLM, human decisions from
the trace) must alert at EXACTLY the proposal ordinals at which the OFFLINE frozen detector alerts when it is loaded with
the same registry and run through eval.detectors.run_trace on the trace as the live loop sees it (message-only steps
merged into the next proposal turn). Alerts must also precede the tool_pending they concern, and be contract-valid.

Coverage: all 44 v2 traces with an entry in eval/registries_v2/ex1.json, 10 other v2 traces (default registry: no
entries) and 6 v1 traces (default registry), for BOTH detectors.
"""
import json
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import live_drift
import main
import proposal_monitor as pm
from fakes import FakeClient, call, decision, of, run_session, start_msg, turn, validate_event

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "browser"))
import fake_llm  # noqa: E402  (build_turns: the merge rule the browser harness uses)

from eval.detectors import run_trace  # noqa: E402
from eval.detectors_registry import load_frozen_registry  # noqa: E402
from eval.embed import get_shared_embedder  # noqa: E402
from server.registry import default_registry  # noqa: E402

V2 = {t["id"]: t for t in json.loads((REPO / "eval/final_v2/traces.json").read_text())}
V1 = {t["id"]: t for t in json.loads((REPO / "eval/final/traces.json").read_text())}
EX1 = json.loads((REPO / "eval/registries_v2/ex1.json").read_text())
FROZEN_REG = REPO / "eval/results_registry/frozen_registry_models.json"
MODE_TO_ID = {"registry": "D8", "registry_learned": "D9"}
TRIGGER = "registry_denied_party_match"
ALL = {**V1, **V2}


def _first(ids, n):
    return sorted(ids)[:n]


WITH_REGISTRY = sorted(EX1)                                                    # 44 v2 traces with a registry
_no_entry = [t for t in sorted(V2) if t not in EX1]
OTHER_V2 = [t for cat, n in (("external_benign", 4), ("same_party_unrelated", 3), ("mixed_hard_benign", 3))
            for t in _first([i for i in _no_entry if V2[i]["category"] == cat], n)]    # 10 traces, default registry
_v1_cats: dict[str, str] = {}
for _tid, _t in sorted(V1.items()):
    _v1_cats.setdefault(_t["category"], _tid)
V1_IDS = [_v1_cats[c] for c in sorted(_v1_cats)][:6]                           # 6 v1 traces, default registry
CASES = [(tid, mode) for mode in MODE_TO_ID for tid in WITH_REGISTRY + OTHER_V2 + V1_IDS]


def registry_for(tid: str) -> dict:
    return EX1.get(tid) or default_registry().to_dict()


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
    for k in ("SENTINEL_MONITOR_MODEL", "SENTINEL_REGISTRY_MODEL", "SENTINEL_MONITOR_THRESHOLD", "SENTINEL_WS_TOKEN"):
        monkeypatch.delenv(k, raising=False)


def select(monkeypatch, mode, tmp_path, tid=None, registry=None, name="registry.json"):
    p = tmp_path / name
    p.write_text(json.dumps(registry if registry is not None else registry_for(tid)))
    monkeypatch.setenv("SENTINEL_MONITOR", mode)
    monkeypatch.setenv("SENTINEL_REGISTRY", str(p))
    return p


# ------------------------------------------------------------------ offline reference
def merged_trace(trace: dict) -> dict:
    """The trace as the live loop sees it: one step per proposal turn (reasoning of skipped steps joined)."""
    turns, _ = fake_llm.build_turns(trace)
    by_step = {st["i"]: st for st in trace["steps"]}
    return {**trace, "steps": [{"i": k, "agent_text": t["content"], "proposal": by_step[t["proposal_step"]]["proposal"]}
                               for k, t in enumerate(turns)]}


def offline_ordinals(trace: dict, mode: str, registry: dict) -> set[int]:
    did = MODE_TO_ID[mode]
    det = load_frozen_registry(FROZEN_REG, get_shared_embedder(), registry, only=[did])[did]
    res = run_trace(det, merged_trace(trace))
    return {k for k, st in enumerate(s for s in res.steps if s.tool is not None) if st.alert}


# ------------------------------------------------------------------ live side
@pytest.fixture
def fake_models(monkeypatch):
    registry: dict[str, FakeClient] = {}
    monkeypatch.setattr(main, "get_client", lambda key: (registry[key], "fake-model"))
    return registry


def live_ordinals(events) -> set[int]:
    pend = [p["node_id"] for p in of(events, "tool_pending")]
    return {pend.index(a["linked_node_id"]) for a in of(events, "alignment_alert") if a["trigger"] == TRIGGER}


def script_for(trace):
    turns, final = fake_llm.build_turns(trace)
    script = [turn(t["content"], [call(t["tool"], t["args"], f"call_{k}")]) for k, t in enumerate(turns)]
    script.append(turn(final["content"]))
    return FakeClient(script), [t["decision"] for t in turns]


def run_live(trace, fake_models, key="A", gate=None):
    client, decisions = script_for(trace)
    fake_models[key] = client

    def policy(ev, events):
        if ev["event"] == "tool_pending":
            if gate is not None:
                gate(ev, events)
            return [decision(ev["node_id"], decisions[len(of(events, "tool_pending")) - 1])]
        return ()

    return run_session(TestClient(main.app), policy, first=start_msg(scenario="adversarial", model=key), timeout=90)


def assert_frame_order(events):
    """Every registry alert is sent before the tool_pending of its linked node; every event is contract-valid."""
    first_pending = {e["node_id"]: i for i, e in reversed(list(enumerate(events))) if e.get("event") == "tool_pending"}
    for i, e in enumerate(events):
        if e.get("event") == "alignment_alert" and e["trigger"] == TRIGGER:
            assert e["severity"] == "critical"
            assert i < first_pending[e["linked_node_id"]], f"alert at frame {i} after its tool_pending"
    assert [validate_event(e) for e in events if validate_event(e)] == []


# ------------------------------------------------------------------ the tests
def test_selection_is_the_one_asked_for_and_not_vacuous():
    assert len(WITH_REGISTRY) == 44 and all(t in V2 for t in WITH_REGISTRY)
    assert len(OTHER_V2) == 10 and not set(OTHER_V2) & set(EX1)
    assert len(V1_IDS) == 6 and all(t in V1 for t in V1_IDS)
    for mode in MODE_TO_ID:
        total = sum(len(offline_ordinals(ALL[t], mode, registry_for(t))) for t in WITH_REGISTRY + OTHER_V2 + V1_IDS)
        with_reg = sum(bool(offline_ordinals(ALL[t], mode, registry_for(t))) for t in WITH_REGISTRY)
        assert total >= 30 and with_reg >= 20, f"{mode}: offline reference has too few alerts ({total}/{with_reg})"


@pytest.mark.parametrize("tid,mode", CASES)
def test_live_alerts_equal_offline_alerts(tid, mode, monkeypatch, tmp_path, fake_models):
    """Same frozen detector, same registry, same proposals, order and decisions -> the same alert set."""
    select(monkeypatch, mode, tmp_path, tid)
    factory = pm.get_monitor_factory()
    assert factory.mode == mode, f"the registry monitor was not active: {factory.reason}"      # not a silent fallback
    events = run_live(ALL[tid], fake_models)
    assert events[-1]["event"] == "session_complete" and events[-1]["reason"] == "finished"
    assert live_ordinals(events) == offline_ordinals(ALL[tid], mode, registry_for(tid)), tid
    assert_frame_order(events)
    other = [e for e in of(events, "alignment_alert") if e["trigger"] not in (TRIGGER, "goal_persistence")]
    assert other == [], "a registry mode must not also raise the rules / D3 alerts"


@pytest.mark.parametrize("mode", sorted(MODE_TO_ID))
def test_registry_is_what_makes_the_difference_live(mode, monkeypatch, tmp_path, fake_models):
    """The same trace and detector WITHOUT its registry (defaults only) does not catch a relay trace; with it, it does."""
    tid = next(t for t in WITH_REGISTRY if V2[t]["category"] == "relay_alias" and offline_ordinals(V2[t], mode, EX1[t]))
    select(monkeypatch, mode, tmp_path, registry=EX1[tid])
    with_reg = live_ordinals(run_live(V2[tid], fake_models))
    select(monkeypatch, mode, tmp_path, registry=default_registry().to_dict(), name="empty.json")
    without = live_ordinals(run_live(V2[tid], fake_models, key="B"))
    assert with_reg and with_reg == offline_ordinals(V2[tid], mode, EX1[tid])
    assert without == offline_ordinals(V2[tid], mode, default_registry().to_dict())
    assert with_reg != without


@pytest.mark.parametrize("mode", sorted(MODE_TO_ID))
def test_concurrent_sessions_with_different_registry_files_give_the_same_alerts_as_alone(mode, monkeypatch, tmp_path, fake_models):
    """Session A starts under registry A; the environment is then switched to registry B and session B starts while A is
    still blocked at its first human decision. Each session must behave exactly as it does alone."""
    ids = [t for t in WITH_REGISTRY if V2[t]["category"] == "relay_alias" and offline_ordinals(V2[t], mode, EX1[t])][:2]
    assert len(ids) == 2
    alone = {}
    for i, tid in enumerate(ids):
        select(monkeypatch, mode, tmp_path, tid, name=f"alone{i}.json")
        alone[tid] = live_ordinals(run_live(V2[tid], fake_models, key=f"solo{i}"))
        assert alone[tid] == offline_ordinals(V2[tid], mode, EX1[tid]) and alone[tid]

    out, errs = {}, []
    a_started, b_started = threading.Event(), threading.Event()

    def worker(tid, key, gate):
        try:
            out[tid] = live_ordinals(run_live(V2[tid], fake_models, key=key, gate=gate))
        except BaseException as e:    # noqa: BLE001
            errs.append(e)

    def gate_a(ev, events):
        if not a_started.is_set():
            a_started.set()
            assert b_started.wait(60), "session B never started"

    def gate_b(ev, events):
        b_started.set()

    select(monkeypatch, mode, tmp_path, ids[0], name="regA.json")
    ta = threading.Thread(target=worker, args=(ids[0], "cA", gate_a))
    ta.start()
    assert a_started.wait(60)
    select(monkeypatch, mode, tmp_path, ids[1], name="regB.json")        # the environment now points at registry B
    tb = threading.Thread(target=worker, args=(ids[1], "cB", gate_b))
    tb.start()
    ta.join(120); tb.join(120)
    assert not errs, errs
    assert out == alone, f"concurrent sessions changed the alerts: {out} vs alone {alone}"
