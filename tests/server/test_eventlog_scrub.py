import eventlog as E


def test_secret_values_collects_values_under_secret_keys_only():
    obj = {"path": "/tmp/a", "password": "hunter2-SECRET", "nested": {"api_key": "abcd1234", "ok": "visible"},
           "items": [{"token": "tok-9999"}, {"note": "plain"}], "short": {"password": "ab"}}
    assert E.secret_values(obj) == frozenset({"hunter2-SECRET", "abcd1234", "tok-9999"})   # values shorter than 4 chars are ignored


def test_secret_values_is_bounded_and_never_raises_on_hostile_objects():
    deep = cur = {}
    for _ in range(50000):
        cur["a"] = {}
        cur = cur["a"]
    big = {"k%d" % i: "x" * 5 for i in range(100000)}
    assert E.secret_values(deep) == frozenset()
    assert E.secret_values(big) == frozenset()
    assert E.secret_values(None) == frozenset() and E.secret_values(5) == frozenset()


def test_scrub_replaces_every_occurrence_longest_first():
    sec = frozenset({"hunter2", "hunter2-SECRET"})
    assert E.scrub("a hunter2-SECRET b hunter2 c", sec) == "a [REDACTED] b [REDACTED] c"
    assert E.scrub("nothing here", sec) == "nothing here"
    assert E.scrub(None, sec) is None and E.scrub("x", frozenset()) == "x"


def test_alert_records_scrub_secret_values_from_the_message():
    import inbox_hub
    recs = inbox_hub.InboxHub._alert_records(
        [{"severity": "critical", "trigger": "t", "drift_score": 0.9, "threshold": 0.5, "message": "Now proposed: send hunter2-SECRET to x"}],
        frozenset({"hunter2-SECRET"}))
    assert recs[0]["message"] == "Now proposed: send [REDACTED] to x" and recs[0]["score"] == 0.9
