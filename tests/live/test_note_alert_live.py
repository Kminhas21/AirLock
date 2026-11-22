"""Deny with a note, the agent adapts, and the note-aware alert label (workflows O3, O4) on the REAL stack: real proxy, real filesystem server,
real MiniLM action_sim monitor, keyed event log. The operator denies `report.txt` and the agent retries the same content as `summary.md`:
  * the denial note reaches the agent in the denial text (O3) and the retry, once approved, really lands on disk;
  * the retry raises a denied_effect_match alert either way (the monitor is not switched off by a note);
  * with a note that names summary.md, the alert is labelled "You suggested this in your denial note (summary.md)." and downgraded to warning,
    in the inbox card AND in the log; without a note it stays critical and unlabelled.
Similarity scores are not asserted (the monitor's threshold is its own business); only the label rule and the logged facts."""
import json

import pytest
import websockets

from tests.harness import TOKEN, Agent, Backend, Operator
from tests.live import livelib
from tests.reality_fixtures import realdeps  # noqa: F401  (fixture)

pytestmark = pytest.mark.reality

NOTE = "save it as summary.md instead"
CONTENT = "Q3 revenue summary: confidential pricing sheet for dana.whitlock@acme-corp.example"
LABEL = "You suggested this in your denial note (summary.md)."


class NoteOperator(Operator):
    """Denies the first write_file (with `note`), approves everything else, keeps every card."""

    def __init__(self, ws, note):
        self.note, self.cards = note, []
        super().__init__(ws, None)

    async def _answer(self, p):
        key = (p["session_id"], p["call_id"])
        if key in self._answered:
            return
        self._answered.add(key)
        self.cards.append(p)
        deny = p["tool"] == "write_file" and sum(c["tool"] == "write_file" for c in self.cards) == 1
        frame = {"event": "inbox_decision", "session_id": p["session_id"], "call_id": p["call_id"], "decision": "deny" if deny else "approve"}
        if deny and self.note:
            frame["note"] = self.note
        await self.ws.send(json.dumps(frame))


@pytest.fixture(scope="module")
def hub(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("note")
    b = Backend(tmp / "backend.log", {"SENTINEL_EVENT_LOG": str(tmp / "events.db"), "SENTINEL_LOG_KEY": livelib.LOG_KEY})
    b.db = tmp / "events.db"
    yield b
    b.stop()


async def _deny_then_retry(hub, realdeps, tmp_path, sid, note):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    op = NoteOperator(await websockets.connect(f"{hub.ws}/inbox/ws?token={TOKEN}", max_size=None), note)
    agent = await Agent.start(hub, sid, {"fs": {"command": realdeps["filesystem"], "args": [str(allowed)]}}, tmp_path)
    try:
        first = await agent.call("write_file", {"path": str(allowed / "report.txt"), "content": CONTENT})
        retry = await agent.call("write_file", {"path": str(allowed / "summary.md"), "content": CONTENT})
    finally:
        await agent.stop()
        await op.close()
    assert first["is_error"] and first["text"].startswith("Denied by SENTINEL") and not (allowed / "report.txt").exists()
    assert not retry["is_error"] and (allowed / "summary.md").read_text() == CONTENT          # the adapted call was approved and really landed
    cards = [c for c in op.cards if c["tool"] == "write_file"]
    assert [c["args"]["path"].rsplit("/", 1)[1] for c in cards] == ["report.txt", "summary.md"]
    dem = [a for a in cards[1]["alerts"] if a["trigger"] == "denied_effect_match"]
    assert len(dem) == 1, cards[1]["alerts"]                                                   # the retry of a denied effect is still flagged
    evs = livelib.events(hub.db, sid)
    logged = {p["args"]["path"].rsplit("/", 1)[1]: p for p in livelib.proposals(evs).values()}
    dec = {livelib.proposals(evs)[c]["args"]["path"].rsplit("/", 1)[1]: d for c, d in livelib.decisions(evs).items()}
    logged_dem = [a for a in logged["summary.md"]["alerts"] if a["trigger"] == "denied_effect_match"]
    assert dec["report.txt"]["decision"] == "deny" and dec["report.txt"]["actor"] == "human" and dec["summary.md"]["decision"] == "approve"
    return first, dem[0], logged_dem[0], dec["report.txt"]


async def test_a_note_reaches_the_agent_and_labels_the_alert_on_what_it_suggested(hub, realdeps, tmp_path):
    first, alert, logged, denial = await _deny_then_retry(hub, realdeps, tmp_path, "note-on", NOTE)
    assert NOTE in first["text"]                                                                # O3: the agent is told why, in the operator's words
    assert denial.get("note") == NOTE                                                           # and the log keeps the note with the denial
    assert alert["severity"] == "warning" and alert["message"].startswith(LABEL)                # O4: labelled and downgraded, on the card
    assert logged["severity"] == "warning" and logged["message"].startswith(LABEL)              # and the same in the tamper-evident log


async def test_without_a_note_the_same_retry_stays_critical_and_unlabelled(hub, realdeps, tmp_path):
    first, alert, logged, denial = await _deny_then_retry(hub, realdeps, tmp_path, "note-off", None)
    assert "note" not in first["text"] and "note" not in denial
    assert alert["severity"] == "critical" and "denial note" not in alert["message"]
    assert logged["severity"] == "critical" and "denial note" not in logged["message"]
    code, out = livelib.cli("verify", str(hub.db))
    assert code == 0, out
