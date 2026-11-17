"""`eventlog_cli show` of an auto-allowed write (DECISIONS D32): the timeline names the file, the sha256 before and after, the inode and where the
before-image is, so an operator can see (and undo with `cp <undo> <path>`) what a policy allow wrote. Never content."""
import os
import sys

import pytest

import eventlog_cli as C
from eventlog import EventStore

W = {"path": "/w/notes.md", "dev": 2049, "ino": 1234, "size_before": 6, "sha256_before": "ab" * 32, "size_after": 12, "sha256_after": "cd" * 32,
     "replaced": False, "undo": "/state/undo/c1/0"}


def make(tmp_path, payload):
    path = str(tmp_path / "e.db")
    s = EventStore(path, key=None)
    s.open()
    s.append("proxy_hello", session_id="s1", payload={"servers": ["fs"], "auto_approve": False, "monitor_mode": "x", "policy_digest": None})
    s.append("call_proposed", session_id="s1", call_id="c1", payload={"server": "fs", "tool": "write_file", "args": {"path": "/w/notes.md", "content": "x"},
                                                                    "auto": False, "alerts": [], "policy": None, "confinable": True})
    s.append("call_result", session_id="s1", call_id="c1", payload=payload)
    s.close()
    return path


def show(tmp_path, payload, capsys):
    path = make(tmp_path, payload)
    assert C.main(["show", path, "--session", "s1"]) == 0
    return capsys.readouterr().out


def test_a_result_with_a_write_shows_path_hashes_inode_and_undo(tmp_path, capsys):
    out = show(tmp_path, {"status": "ok", "summary_len": 4, "writes": [W]}, capsys)
    line = next(ln for ln in out.splitlines() if "auto-written" in ln)
    assert "/w/notes.md" in line and ("ab" * 32)[:12] in line and ("cd" * 32)[:12] in line and "/state/undo/c1/0" in line
    assert "2049:1234" in line and "6 -> 12 bytes" in line
    assert ("ab" * 32) not in out                                          # the short digest is shown, not the whole line of hex


def test_a_replaced_name_is_flagged(tmp_path, capsys):
    out = show(tmp_path, {"status": "error", "writes": [{**W, "replaced": True, "size_after": None, "sha256_after": None}]}, capsys)
    assert "REPLACED" in out and "auto-written" in out


def test_a_result_without_writes_prints_as_before(tmp_path, capsys):
    out = show(tmp_path, {"status": "ok", "summary": "done"}, capsys)
    assert "RESULT call c1: ok done" in out and "auto-written" not in out


def test_hostile_text_in_a_write_record_is_made_safe(tmp_path, capsys):
    out = show(tmp_path, {"status": "ok", "writes": [{**W, "path": "/w/a\x1b[31m\n.md", "undo": "/u\x07"}]}, capsys)
    assert "\x1b" not in out and "\x07" not in out


def test_a_malformed_writes_value_does_not_crash_show(tmp_path, capsys):
    out = show(tmp_path, {"status": "ok", "writes": "nope"}, capsys)
    assert "RESULT call c1" in out
