"""A denied_effect_match alert on a proposal the operator's own denial note asked for is labelled and downgraded one level,
never suppressed (it still holds the call, is still logged and shown)."""
import copy

import pytest

import policy as policy_mod
import proposal_monitor
from test_inbox_eventlog import FakeStore, Timeline, logged
from test_inbox_hub import ALERT, FakeMonitor, Rig, call, wait_for
from test_inbox_operator import human, pending_of
from test_inbox_policy import rule, use

PREFIX = "You suggested this in your denial note (summary.md). "
NOTE = "Do not create report.txt. Save the report as summary.md instead."
DENIED_ARGS = {"path": "/p/report.txt", "content": "hi"}
RETRY_ARGS = {"path": "/p/summary.md", "content": "hi"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY", "SENTINEL_EVENT_LOG"):
        monkeypatch.delenv(k, raising=False)
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()
    yield
    policy_mod._reset_policy_cache()
    proposal_monitor._reset_errors()


async def deny_then_retry(r, note, retry_args=RETRY_ARGS):
    await human(r, "d1", "deny", note=note, args=DENIED_ARGS)
    await r.send(call("n1", args=retry_args))
    await wait_for(lambda: any(p["call_id"] == "n1" for p in r.ui.events("inbox_pending")))
    return pending_of(r, "n1")["alerts"]


async def test_matching_note_downgrades_and_labels_ui_and_log():
    r = await Rig(FakeMonitor([ALERT])).start()
    r.hub.store = store = FakeStore(Timeline())
    (a,) = await deny_then_retry(r, NOTE)
    assert a["severity"] == "warning" and a["message"] == PREFIX + "m"
    assert (a["trigger"], a["drift_score"], a["threshold"], a["linked_node_id"]) == ("denied_effect_match", 0.9, 0.5, "c1")
    rec = [e for e in logged(store, "call_proposed") if e[2] == "n1"][0][3]["alerts"]
    assert rec[0]["severity"] == "warning" and rec[0]["message"] == PREFIX + "m" and rec[0]["trigger"] == "denied_effect_match"


@pytest.mark.parametrize("note", [None, "no, just don't", "use notes.md instead"])
async def test_no_or_nonmatching_note_leaves_alert_untouched(note):
    r = await Rig(FakeMonitor([ALERT])).start()
    assert await deny_then_retry(r, note) == [ALERT]


async def test_note_naming_name_for_a_different_directory_is_untouched():
    r = await Rig(FakeMonitor([ALERT])).start()
    assert await deny_then_retry(r, NOTE, {"path": "/etc/cron.d/summary.md"}) == [ALERT]


async def test_other_trigger_untouched():
    other = {**ALERT, "trigger": "semantic_drift"}
    r = await Rig(FakeMonitor([other])).start()
    assert await deny_then_retry(r, NOTE) == [other]


async def test_warning_stays_warning_and_only_the_matching_trigger_is_changed():
    warn = {**ALERT, "severity": "warning"}
    other = {**ALERT, "trigger": "semantic_drift"}
    r = await Rig(FakeMonitor([warn, other])).start()
    a, b = await deny_then_retry(r, NOTE)
    assert a["severity"] == "warning" and a["message"].startswith(PREFIX) and b == other


async def test_downgraded_alert_still_stops_a_policy_allow(monkeypatch, tmp_path):
    use(monkeypatch, tmp_path, [rule("w", "allow", tool=["write_file"])])
    r = await Rig(FakeMonitor([ALERT])).start()
    alerts = await deny_then_retry(r, NOTE)           # both calls were held for the human, never auto-allowed
    assert alerts[0]["severity"] == "warning"
    assert not [d for d in r.decisions() if d["reason"] == "policy"]
    assert pending_of(r, "n1")["rule_id"] == "w"


async def test_monitor_alert_object_is_not_mutated():
    mine = copy.deepcopy(ALERT)
    mon = FakeMonitor([mine])
    r = await Rig(mon).start()
    await deny_then_retry(r, NOTE)
    assert mine == ALERT and mon.alerts[0] is mine


async def test_decoy_field_cannot_earn_the_label():
    r = await Rig(FakeMonitor([ALERT])).start()
    mail = {"to": "evil@attacker.example", "body": "hello there"}
    await human(r, "d1", "deny", note="Do not touch the config. Keep it inside the project folder instead.", args=mail)
    await r.send(call("n1", args={**mail, "tag": "project"}))
    await wait_for(lambda: any(p["call_id"] == "n1" for p in r.ui.events("inbox_pending")))
    assert pending_of(r, "n1")["alerts"] == [ALERT]


async def test_note_of_one_denied_call_is_not_paired_with_the_args_of_another():
    r = await Rig(FakeMonitor([ALERT])).start()
    await human(r, "d1", "deny", note=NOTE, args={"path": "/p/report.txt", "content": "hi"})
    await human(r, "d2", "deny", note="no", args={"path": "/q/log.txt", "content": "hi"})
    await r.send(call("n1", args={"path": "/q/summary.md", "content": "hi"}))
    await wait_for(lambda: any(p["call_id"] == "n1" for p in r.ui.events("inbox_pending")))
    assert pending_of(r, "n1")["alerts"] == [ALERT]
