"""alert_note.note_names_alternative: did the operator's denial note name the value of this proposal?"""
import time

import pytest

from alert_note import note_names_alternative as nna

DENIED = [{"path": "/p/report.txt", "content": "x"}]


def test_basename_in_note_same_directory():
    assert nna("Save the report as summary.md instead.", {"path": "/p/summary.md"}, DENIED) == "summary.md"


def test_whole_path_in_note():
    assert nna("write to /q/out/final.md please", {"path": "/q/out/final.md"}, DENIED) == "/q/out/final.md"


def test_case_insensitive():
    assert nna("use SUMMARY.MD", {"path": "/p/summary.md"}, DENIED) == "summary.md"


def test_nested_args():
    args = {"edits": [{"target": {"file": "/p/summary.md"}}]}
    den = [{"edits": [{"target": {"file": "/p/report.txt"}}]}]
    assert nna("use summary.md", args, den) == "summary.md"


def test_windows_separator_same_directory():
    assert nna("use summary.md", {"path": "C:\\p\\summary.md"}, [{"path": "C:\\p\\report.txt"}]) == "summary.md"


def test_basename_but_different_directory_is_not_blessed():
    assert nna("use summary.md", {"path": "/etc/cron.d/summary.md"}, DENIED) is None


def test_whole_value_in_note_does_not_need_same_directory():
    assert nna("put it in /etc/cron.d/summary.md", {"path": "/etc/cron.d/summary.md"}, DENIED) == "/etc/cron.d/summary.md"


def test_note_without_the_name():
    assert nna("please do not do that", {"path": "/p/summary.md"}, DENIED) is None


def test_short_tokens_ignored():
    assert nna("use a.c", {"path": "/p/a.c"}, [{"path": "/p/b.c"}]) is None
    assert nna("use yes", {"flag": "yes"}, [{"flag": "no"}]) is None


def test_denied_call_without_path_values():
    assert nna("use summary.md", {"path": "/p/summary.md"}, [{"n": 1}, {"q": "select"}]) is None


def test_non_pathlike_whole_value():
    assert nna("send it to alice@example.com", {"to": "alice@example.com"}, [{"to": "bob@example.com"}]) == "alice@example.com"


@pytest.mark.parametrize("note", ["", None, 5])
def test_empty_or_bad_note(note):
    assert nna(note, {"path": "/p/summary.md"}, DENIED) is None


def test_bad_inputs_do_not_raise():
    assert nna("summary.md", None, DENIED) is None
    assert nna("summary.md", {"path": "/p/summary.md"}, None) is None
    assert nna("summary.md", {"path": "/p/summary.md"}, [None, 3]) is None


def test_control_chars_in_note():
    assert nna("use\x00 summary.md\n\x1b[2J", {"path": "/p/summary.md"}, DENIED) == "summary.md"


def test_huge_inputs_are_fast():
    t = time.time()
    note = "a" * 5_000_000 + " summary.md"
    huge = {"k%d" % i: ["/p/" + "z" * 5000 + str(i)] * 50 for i in range(2000)}
    assert nna(note, {"path": "/p/summary.md", **huge}, DENIED) is None   # note capped: name is beyond the cap
    deep = cur = {}
    for _ in range(5000):
        cur["d"] = {}
        cur = cur["d"]
    assert nna("summary.md", deep, DENIED) is None
    assert time.time() - t < 10


# ---- review fixes: the agent must not be able to earn the label with a decoy
MAIL = {"to": "evil@attacker.example", "body": "hello there"}
KEEP = "Do not touch the config. Keep it inside the project folder instead."


def test_decoy_new_key_never_counts():
    assert nna(KEEP, {**MAIL, "tag": "project"}, [MAIL]) is None


def test_decoy_at_existing_key_with_unchanged_value_never_counts():
    den = {**MAIL, "tag": "project"}
    assert nna(KEEP, dict(den), [den]) is None
    assert nna("send it to evil@attacker.example", MAIL, [MAIL]) is None     # unchanged recipient


def test_changed_value_at_existing_key_counts():
    assert nna(KEEP, {**MAIL, "tag": "project"}, [{**MAIL, "tag": "other"}]) == "project"


@pytest.mark.parametrize("frag", ["ect ", "sendx", "send", "ect"])
def test_midword_fragment_never_counts(frag):
    note = "I am sending this to the correct inspector"
    den = {"tag": "zzzz"}
    assert nna(note, {"tag": frag}, [den]) is None


def test_whole_word_changed_value_counts():
    assert nna("use staging please", {"env": "staging"}, [{"env": "prod-1"}]) == "staging"


def test_two_denied_calls_do_not_mix():
    # note of call X names summary.md; the proposal sits in the directory of call Y only
    x = {"path": "/p/report.txt"}
    y = {"path": "/q/log.txt"}
    assert nna("save it as summary.md", {"path": "/q/summary.md"}, [x]) is None
    assert nna("save it as summary.md", {"path": "/q/summary.md"}, [y]) == "summary.md"


@pytest.mark.parametrize("note,ok", [("save as summary.md,", True), ("(summary.md)", True), ("summary.md.", True),
                                     ("summary.mdx", False), ("mysummary.md", False), ("see summary.md/x", True)])
def test_word_boundaries(note, ok):
    assert (nna(note, {"path": "/p/summary.md"}, DENIED) == "summary.md") is ok


def test_path_with_changed_directory_needs_its_own_directory():
    assert nna("use summary.md", {"path": "/p/summary.md"}, [{"path": "/p/report.txt"}]) == "summary.md"
    assert nna("use summary.md", {"path": "/p/summary.md"}, [{"path": "/p/summary.md"}]) is None   # unchanged
