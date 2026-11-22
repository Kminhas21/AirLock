"""The hub under concurrent load (docs/TESTING_REALITY.md, rung 6). Scaled for the gate; LOAD_SESSIONS / LOAD_CALLS / LOAD_SECONDS scale it up
(or run `python -m tests.load.loadlib` for a soak). Invariants, not just speed:
  * no session error, no unhandled server error, /health stays responsive while loaded;
  * every decision a client saw is in the tamper-evident log EXACTLY ONCE with the SAME verdict (concurrent operators race to decide);
  * calls held when their agent vanished are logged as denied, not lost, and nothing stays pending;
  * the log verifies after a graceful stop; memory does not balloon."""
import os
from collections import Counter

import pytest

from tests.harness import Backend
from tests.load.loadlib import KEY, run_load, verify_log

pytestmark = pytest.mark.reality            # real processes, minutes: own gate stage (pytest -m reality), deselected by default

SESSIONS = int(os.environ.get("LOAD_SESSIONS", "40"))
CALLS = int(os.environ.get("LOAD_CALLS", "10"))
SECONDS = float(os.environ.get("LOAD_SECONDS", "240"))


@pytest.fixture(scope="module")
def loaded(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("load")
    b = Backend(tmp / "backend.log", {"SENTINEL_EVENT_LOG": str(tmp / "events.db"), "SENTINEL_LOG_KEY": KEY})
    import asyncio
    rep = asyncio.run(run_load(b, sessions=SESSIONS, calls=CALLS, operators=3, abort_fraction=0.1, seconds=SECONDS))
    log = b.log_text()
    b.stop()                                                    # graceful: final checkpoint
    yield rep, log, tmp / "events.db"


def test_no_errors_and_the_hub_stays_responsive(loaded):
    rep, log, _ = loaded
    print(rep.summary())
    assert rep.errors == [], rep.errors[:5]
    assert rep.calls_decided >= SESSIONS * (CALLS // 2), rep.summary()
    for bad in ("unexpected server error", "Task exception was never retrieved", "Traceback"):
        assert bad not in log, f"{bad!r} in the hub log:\n{log[-1500:]}"
    assert max(rep.health_samples) < 2.0, f"/health took {max(rep.health_samples):.2f}s under load"
    assert rep.calls_decided / rep.seconds > 5, f"throughput collapsed: {rep.summary()}"
    assert rep.pct(0.99) < 30, f"p99 decision latency {rep.pct(0.99):.1f}s"
    assert rep.rss_end_mb - rep.rss_start_mb < 300, f"memory grew {rep.rss_end_mb - rep.rss_start_mb:.0f} MB"


def test_every_decision_a_client_saw_is_in_the_log_exactly_once_with_the_same_verdict(loaded):
    rep, _, db = loaded
    code, out, events = verify_log(db)
    assert code == 0, out
    decisions = [e for e in events if e["kind"] == "decision"]
    per_call = Counter(e["call_id"] for e in decisions)
    assert not [c for c, n in per_call.items() if n != 1], "a call has more than one decision event"
    by_call = {e["call_id"]: e["payload"]["decision"] for e in decisions}
    wrong = {c: (v, by_call.get(c)) for c, v in rep.decisions.items() if by_call.get(c) != v}
    assert not wrong, f"client saw a different verdict than the log recorded: {list(wrong.items())[:3]}"
    proposed = {e["call_id"] for e in events if e["kind"] == "call_proposed"}
    assert proposed == set(by_call), "every proposed call must end with a decision (nothing left pending, nothing decided without a proposal)"


def test_calls_held_when_the_agent_vanished_are_denied_not_lost(loaded):
    """Half the aborting sessions close in the same instant as the proposal, half after it was held: every such call is logged as proposed, then denied by the system as disconnected."""
    rep, _, db = loaded
    _, _, events = verify_log(db)
    proposed = {e["call_id"] for e in events if e["kind"] == "call_proposed"}
    assert rep.aborted_calls <= proposed, f"aborted calls missing from the log: {len(rep.aborted_calls - proposed)}"
    gone = [e for e in events if e["kind"] == "decision" and e["payload"].get("reason") == "disconnected" and e["payload"].get("actor") == "system"]
    assert rep.aborted_sessions == 0 or gone, f"{rep.aborted_sessions} sessions vanished mid-call but no 'agent gone' decision was logged"
