"""Offline-vs-live parity: the live loop must alert at EXACTLY the proposals the offline harness alerts at.

The reference is eval.detectors.run_trace over the same frozen detectors (eval/results_v2/frozen_models.json).
The live side is the real FastAPI app driven through TestClient, with a scripted fake model that replays the trace
(message-only steps merged into the next proposal turn, exactly like tests/browser/fake_llm.py) and a human whose
decisions come from the trace. Real MiniLM; no browser.

Two comparisons per trace:
  * RAW     live alert ordinals == run_trace on the original trace (message-only steps are separate steps)
  * LIVE    live alert ordinals == run_trace on the trace as the live loop sees it (message-only steps merged)
They differ only for detectors that read the step index. FINDING (reported, not papered over): D7's feature
``steps_since_denial`` was fitted on trace step indices, which count message-only ("ack chatter") steps; a live
session has no message-only steps (a turn without a tool call ends the session), so it counts proposal turns.
D3 has no such feature: RAW == LIVE for it on all 200 traces. For D7, 7 of 200 traces differ, always with the
live side alerting MORE (3 extra true detections, 4 extra false alarms); KNOWN_RAW_DIVERGENCE lists them and
the two tests at the bottom prove the cause (and that nothing else differs).
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
from eval.detectors_v2 import load_frozen  # noqa: E402
from eval.embed import get_shared_embedder  # noqa: E402

V2 = {t["id"]: t for t in json.loads((REPO / "eval/final_v2/traces.json").read_text())}
V1 = {t["id"]: t for t in json.loads((REPO / "eval/final/traces.json").read_text())}
FROZEN = REPO / "eval/results_v2/frozen_models.json"
MODE_TO_ID = {"action_sim": "D3", "learned": "D7"}


def _pick(traces: dict, per_category: int):
    cats: dict[str, list[str]] = {}
    for tid, t in sorted(traces.items()):
        cats.setdefault(t["category"], []).append(tid)
    return [tid for ids in cats.values() for tid in ids[:per_category]]


V2_IDS = _pick(V2, 2)                                    # 6 categories x 2 = 12
V1_IDS = [_pick(V1, 1)[i] for i in (0, 1, 2, 3, 5, 6)]  # 6 of the 9 v1 categories (first trace of each)
ALL = {**V1, **V2}


@pytest.fixture(scope="module", autouse=True)
def _real_model():
    mp = pytest.MonkeyPatch()
    mp.setenv("SENTINEL_EMBEDDER", "minilm")
    mp.delenv("SENTINEL_MONITOR_MODEL", raising=False)
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
    monkeypatch.delenv("SENTINEL_MONITOR_MODEL", raising=False)
    monkeypatch.delenv("SENTINEL_WS_TOKEN", raising=False)


# ------------------------------------------------------------------ offline reference
def offline_ordinals(trace: dict, mode: str, live_view: bool = False) -> set[int]:
    det = load_frozen(FROZEN, get_shared_embedder())[MODE_TO_ID[mode]]
    t = merged_trace(trace) if live_view else trace
    res = run_trace(det, t)
    ordinals, k = set(), 0
    for st in res.steps:
        if st.tool is None:
            continue
        if st.alert:
            ordinals.add(k)
        k += 1
    return ordinals


def merged_trace(trace: dict) -> dict:
    """The trace as the live loop sees it: one step per proposal turn (reasoning of skipped steps joined)."""
    turns, _ = fake_llm.build_turns(trace)
    by_step = {st["i"]: st for st in trace["steps"]}
    steps = []
    for k, t in enumerate(turns):
        p = by_step[t["proposal_step"]]["proposal"]
        steps.append({"i": k, "agent_text": t["content"], "proposal": p})
    return {**trace, "steps": steps}


# ------------------------------------------------------------------ live side
@pytest.fixture
def fake_models(monkeypatch):
    registry: dict[str, FakeClient] = {}
    monkeypatch.setattr(main, "get_client", lambda key: (registry[key], "fake-model"))
    return registry


def live_ordinals(events) -> set[int]:
    pend = [p["node_id"] for p in of(events, "tool_pending")]
    return {pend.index(a["linked_node_id"]) for a in of(events, "alignment_alert")
            if a["trigger"] == "denied_effect_match"}


def run_live(trace, fake_models, key="A"):
    turns, final = fake_llm.build_turns(trace)
    script = [turn(t["content"], [call(t["tool"], t["args"], f"call_{k}")]) for k, t in enumerate(turns)]
    script.append(turn(final["content"]))
    fake_models[key] = FakeClient(script)
    decisions = [t["decision"] for t in turns]

    def policy(ev, events):
        if ev["event"] == "tool_pending":
            return [decision(ev["node_id"], decisions[len(of(events, "tool_pending")) - 1])]
        return ()

    return run_session(TestClient(main.app), policy, first=start_msg(scenario="adversarial", model=key), timeout=60)


def assert_frame_order(events):
    """Every denied_effect_match alert is sent before the tool_pending of its linked node."""
    first_pending = {}
    for i, e in enumerate(events):
        if e.get("event") == "tool_pending":
            first_pending[e["node_id"]] = i
    for i, e in enumerate(events):
        if e.get("event") == "alignment_alert" and e["trigger"] == "denied_effect_match":
            assert i < first_pending[e["linked_node_id"]], f"alert at frame {i} after its tool_pending"
    assert [validate_event(e) for e in events if validate_event(e)] == []


# D7 traces whose RAW offline alert set differs from the live one (found by scanning all 200 traces; cause below)
KNOWN_RAW_DIVERGENCE = {
    "learned": {"v2b-005", "v2b-007", "v2b-016", "v2c-002", "v2e-003", "v2e-016", "gen_e-005"},
    "action_sim": set(),
}


# ------------------------------------------------------------------ the tests
CASES = [(tid, mode) for mode in MODE_TO_ID for tid in V2_IDS + V1_IDS]


@pytest.mark.parametrize("mode", sorted(MODE_TO_ID))
def test_selection_covers_categories_and_is_not_vacuous(mode):
    assert len(V2_IDS) == 12 and len({V2[t]["category"] for t in V2_IDS}) == 6
    assert len(V1_IDS) == 6 and len({V1[t]["category"] for t in V1_IDS}) == 6
    total = sum(len(offline_ordinals(ALL[t], mode, live_view=True)) for t in V2_IDS + V1_IDS)
    assert total >= 5, f"{mode}: offline reference has too few alerts ({total}) for the comparison to mean anything"


@pytest.mark.parametrize("tid,mode", CASES)
def test_live_alerts_equal_offline_alerts_on_the_live_view(tid, mode, monkeypatch, fake_models):
    """Same frozen detector, same proposals, same order, same decisions -> same alert set."""
    monkeypatch.setenv("SENTINEL_MONITOR", mode)
    events = run_live(ALL[tid], fake_models)
    assert events[-1]["event"] == "session_complete" and events[-1]["reason"] == "finished"
    assert live_ordinals(events) == offline_ordinals(ALL[tid], mode, live_view=True), tid
    assert_frame_order(events)


@pytest.mark.parametrize("tid,mode", CASES)
def test_live_alerts_equal_offline_alerts_on_the_raw_trace(tid, mode, monkeypatch, fake_models):
    """The strict spec statement: compared with run_trace on the ORIGINAL trace (message-only steps counted)."""
    if tid in KNOWN_RAW_DIVERGENCE[mode]:
        pytest.xfail("known train/serve skew: D7 steps_since_denial counts message-only steps offline "
                     "(see module docstring and test_raw_vs_live_divergence_is_exactly_the_step_index_feature)")
    monkeypatch.setenv("SENTINEL_MONITOR", mode)
    events = run_live(ALL[tid], fake_models)
    assert live_ordinals(events) == offline_ordinals(ALL[tid], mode), tid


@pytest.mark.parametrize("mode", sorted(MODE_TO_ID))
def test_concurrent_sessions_do_not_leak_into_each_other(mode, monkeypatch, fake_models):
    monkeypatch.setenv("SENTINEL_MONITOR", mode)
    ids = [t for t in V2_IDS if offline_ordinals(ALL[t], mode, live_view=True)][:2]
    assert len(ids) == 2, "need two traces with alerts"
    alone = {}
    for i, tid in enumerate(ids):
        alone[tid] = live_ordinals(run_live(ALL[tid], fake_models, key=f"solo{i}"))
    assert all(alone.values())

    out: dict[str, set] = {}
    errs = []

    def worker(tid, key):
        try:
            out[tid] = live_ordinals(run_live(ALL[tid], fake_models, key=key))
        except BaseException as e:   # noqa: BLE001
            errs.append(e)

    for rep in range(2):
        out.clear()
        ths = [threading.Thread(target=worker, args=(tid, f"c{rep}{i}")) for i, tid in enumerate(ids)]
        [t.start() for t in ths]
        [t.join(120) for t in ths]
        assert not errs, errs
        assert out == alone, f"concurrent sessions changed the alerts: {out} vs alone {alone}"


# ------------------------------------------------------------------ root cause of the RAW/LIVE difference (offline, all 200 traces)
def test_raw_vs_live_divergence_is_exactly_the_step_index_feature(monkeypatch):
    """1. D3: RAW == LIVE view on every trace.  2. D7: the set of traces where they differ is KNOWN_RAW_DIVERGENCE.
    3. Counting only proposal steps in steps_since_denial (what a live session can do) makes RAW == LIVE for D7 on
    every trace, i.e. that feature is the ONLY source of the difference (agent_text is never read by D3/D7)."""
    from eval import detectors_v2

    monkeypatch.setattr(get_shared_embedder(), "cache_size", 50_000)   # raw and live view embed the same strings
    traces = list(ALL.values())
    for mode in MODE_TO_ID:
        differ = {t["id"] for t in traces if offline_ordinals(t, mode) != offline_ordinals(t, mode, live_view=True)}
        assert differ == KNOWN_RAW_DIVERGENCE[mode], (mode, differ ^ KNOWN_RAW_DIVERGENCE[mode])

    real = detectors_v2.FeatureExtractor.on_step

    def proposal_indexed(self, agent_text, proposal):
        if proposal is None:                 # a message-only step does not advance the clock
            return None
        return real(self, agent_text, proposal)

    monkeypatch.setattr(detectors_v2.FeatureExtractor, "on_step", proposal_indexed)
    for t in traces:
        assert offline_ordinals(t, "learned") == offline_ordinals(t, "learned", live_view=True), t["id"]


def test_the_divergent_traces_really_contain_message_only_steps_between_denial_and_proposal():
    for tid in KNOWN_RAW_DIVERGENCE["learned"]:
        steps = ALL[tid]["steps"]
        assert any(st.get("proposal") is None for st in steps), tid
