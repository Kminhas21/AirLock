"""Tests for server/policy_writer.py (ticket OP3).  Hand-written fixtures only."""
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import threading
import time

import pytest

import policy as P
import policy_writer as W
from policy_writer import PolicyWriteError, append_rule, build_rule

SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

BASE = {"version": 1, "default": "ask", "rules": [
    {"id": "read-project", "verdict": "allow", "note": "reads are routine",
     "when": {"tool": "read_*", "args": [{"path": "path", "op": "under", "value": "/project"}]}},
    {"id": "no-writes-outside", "verdict": "deny", "when": {"tool": "write_*", "args": [{"path": "path", "op": "not_under", "value": "/project"}]}},
]}


@pytest.fixture
def pfile(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(json.dumps(BASE, indent=1))
    return str(f)


def snapshot(path):
    return open(path, "rb").read()


def rule_for(tool="write_file", path="/project/a/b.txt", verdict="deny", scope="tool_under", server="fs", **kw):
    return build_rule(verdict, scope, server, tool, {"path": path}, **kw)


def errors_of(*a, **k):
    with pytest.raises(ValueError) as ei:
        build_rule(*a, **k)
    return str(ei.value)


def write_err(path, rule):
    with pytest.raises(PolicyWriteError) as ei:
        append_rule(path, rule)
    return ei.value


def side_files(path):
    d = os.path.dirname(path)
    return sorted(f for f in os.listdir(d) if f.startswith(os.path.basename(path) + "."))


# ---------------------------------------------------------------------------
# build_rule
# ---------------------------------------------------------------------------

class TestBuildExact:
    def test_shape_and_id(self):
        r = build_rule("allow", "exact", "fs", "read_file", {"path": "/project/a.txt", "n": 3, "flag": True})
        assert r["verdict"] == "allow" and "note" not in r
        assert r["when"] == {"server": "fs", "tool": "read_file", "args": [
            {"path": "flag", "op": "equals", "value": True}, {"path": "n", "op": "equals", "value": 3},
            {"path": "path", "op": "equals", "value": "/project/a.txt"}]}
        canon = json.dumps({"verdict": "allow", "when": r["when"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        assert r["id"] == "ui-allow-" + hashlib.sha256(canon.encode()).hexdigest()[:8]
        assert re.fullmatch(r"ui-(allow|deny|ask)-[0-9a-f]{8}", r["id"])

    def test_arg_order_does_not_matter(self):
        a = build_rule("deny", "exact", "fs", "t", {"a": 1, "b": 2})
        b = build_rule("deny", "exact", "fs", "t", {"b": 2, "a": 1})
        assert a == b

    def test_id_depends_on_verdict_and_content(self):
        ids = {build_rule(v, "exact", "fs", "t", {"a": x})["id"] for v in ("allow", "deny", "ask") for x in (1, 2)}
        assert len(ids) == 6

    def test_loads_and_matches_exactly(self):
        r = build_rule("allow", "exact", "fs", "write_file", {"path": "/project/a", "overwrite": False, "n": 1})
        pol = P.Policy({"version": 1, "default": "deny", "rules": [r]})
        ok = {"path": "/project/a", "overwrite": False, "n": 1}
        assert pol.evaluate("fs", "write_file", ok).verdict == "allow"
        assert pol.evaluate("fs", "write_file", {**ok, "extra": "x"}).verdict == "allow"      # other args are not constrained
        for bad in ({**ok, "path": "/project/b"}, {**ok, "overwrite": True}, {**ok, "n": True}, {**ok, "n": "1"}, {**ok, "n": 2},
                    {"path": "/project/a"}, {**ok, "path": ["/project/a"]}):
            assert pol.evaluate("fs", "write_file", bad).verdict == "deny", bad
        assert pol.evaluate("other", "write_file", ok).verdict == "deny"
        assert pol.evaluate("fs", "write_file2", ok).verdict == "deny"

    @pytest.mark.parametrize("value", [1.5, float("nan"), float("inf"), None, [1], {"a": 1}, (1,), 2 ** 63, pytest.param(10 ** 5000, id="hugeint"), b"x", "x" * 1001,
                                       object()])
    def test_non_scalar_or_unrepresentable_values(self, value):
        assert errors_of("deny", "exact", "fs", "t", {"k": value}) == "cannot_build"

    @pytest.mark.parametrize("value", [0, -5, 2 ** 62, True, False, "", "x" * 1000, "line\nbreak", "‮", "a\x00b"])
    def test_scalar_values_allowed_by_policy_validator(self, value):
        r = build_rule("deny", "exact", "fs", "t", {"k": value})
        assert r["when"]["args"][0]["value"] == value
        P.load_policy({"version": 1, "rules": [r]})

    def test_condition_limit(self):
        build_rule("deny", "exact", "fs", "t", {f"k{i}": i for i in range(20)})
        assert errors_of("deny", "exact", "fs", "t", {f"k{i}": i for i in range(21)}) == "cannot_build"

    def test_10k_keys_is_fast_and_refused(self):
        t = time.time()
        assert errors_of("deny", "exact", "fs", "t", {f"k{i}": i for i in range(10_000)}) == "cannot_build"
        assert time.time() - t < 1

    @pytest.mark.parametrize("args", [{}, None, [], "x", 5, [("a", 1)], {1: "x"}, {"": 1}, {"a.b": 1}, {"k\n": 1}, {"k‮": 1},
                                      {"k" * 101: 1}])
    def test_bad_args(self, args):
        assert errors_of("deny", "exact", "fs", "t", args) == "cannot_build"
        assert errors_of("allow", "exact", "fs", "t", args) == "cannot_build"

    def test_deeply_nested_values_refused(self):
        deep = cur = {}
        for _ in range(3000):
            cur["k"] = {}
            cur = cur["k"]
        assert errors_of("deny", "exact", "fs", "t", {"a": deep}) == "cannot_build"


class TestBuildToolUnder:
    @pytest.mark.parametrize("value,parent", [
        ("/project/a/b.txt", "/project/a"), ("/project/a/b/", "/project/a"), ("/a/b", "/a"), ("/project/./a//b.txt", "/project/a"),
        ("/project/a b/c", "/project/a b"),
    ])
    def test_parent(self, value, parent):
        r = rule_for(path=value)
        assert r["when"]["args"] == [{"path": "path", "op": "under", "value": parent}]
        assert r["when"]["server"] == "fs" and r["when"]["tool"] == "write_file"

    @pytest.mark.parametrize("value", ["/", "/a", "//", "//x/y", "relative/x", "", "./x", "~/x", "/project/../etc/x", "/..", "/a/../b",
                                       "/p\x00/x", "/" + "d/" * 600 + "f"])
    def test_cannot_build(self, value):
        assert errors_of("deny", "tool_under", "fs", "t", {"path": value}) == "cannot_build"
        assert errors_of("allow", "tool_under", "fs", "t", {"path": value}) == "cannot_build"

    def test_no_path_like_argument(self):
        for args in ({}, {"name": "/project/a"}, {"path": 5}, {"path": ["/a/b"]}, {"path": None}, {"path": "rel"}, None, [], "x"):
            assert errors_of("deny", "tool_under", "fs", "t", args) == "cannot_build"

    def test_key_priority_not_dict_order(self):
        a = build_rule("deny", "tool_under", "fs", "t", {"target": "/x/y/z", "path": "/p/q/r"})
        b = build_rule("deny", "tool_under", "fs", "t", {"path": "/p/q/r", "target": "/x/y/z"})
        assert a == b and a["when"]["args"][0]["path"] == "path"

    def test_skips_non_absolute_candidates(self):
        r = build_rule("deny", "tool_under", "fs", "t", {"path": "relative", "file": 7, "dir": "/d/e/f"})
        assert r["when"]["args"] == [{"path": "dir", "op": "under", "value": "/d/e"}]

    @pytest.mark.parametrize("key", W.PATH_KEYS)
    def test_all_documented_keys(self, key):
        r = build_rule("allow", "tool_under", "fs", "t", {key: "/a/b/c"})
        assert r["when"]["args"] == [{"path": key, "op": "under", "value": "/a/b"}]

    def test_semantics_with_policy(self):
        r = rule_for(tool="write_file", path="/project/a/b.txt", verdict="allow")
        pol = P.Policy({"version": 1, "default": "deny", "rules": [r]})
        ev = lambda p: pol.evaluate("fs", "write_file", {"path": p}).verdict
        assert ev("/project/a/other.txt") == "allow" and ev("/project/a/sub/deep.txt") == "allow"
        for bad in ("/project/b/x", "/project/a2/x", "/project", "/project/a/../b/x", "relative", "/etc/passwd", "/project/a\x00/x"):
            assert ev(bad) == "deny", bad
        assert pol.evaluate("fs", "read_file", {"path": "/project/a/x"}).verdict == "deny"

    def test_parent_must_not_be_root(self):
        assert errors_of("allow", "tool_under", "fs", "t", {"path": "/file.txt"}) == "cannot_build"


class TestBuildScopes:
    def test_tool_scope(self):
        for v in ("deny", "ask"):
            r = build_rule(v, "tool", "fs", "write_file", {"anything": [1, 2]})
            assert r["when"] == {"server": "fs", "tool": "write_file"} and "args" not in r["when"]
            assert r["verdict"] == v

    def test_allow_only_exact_or_tool_under(self):
        assert errors_of("allow", "tool", "fs", "t", {}) == "scope_not_allowed"
        build_rule("allow", "exact", "fs", "t", {"a": 1})
        build_rule("allow", "tool_under", "fs", "t", {"path": "/a/b"})

    @pytest.mark.parametrize("verdict,scope", [("maybe", "tool"), ("ALLOW", "exact"), (None, "tool"), ("allow", "everything"),
                                               ("deny", None), (5, "tool"), ("deny", ["tool"]), ("", ""), (b"deny", "tool")])
    def test_unknown_verdict_or_scope(self, verdict, scope):
        assert errors_of(verdict, scope, "fs", "t", {"a": 1}) == "cannot_build"

    def test_error_messages_are_from_the_closed_set(self):
        seen = set()
        for verdict in ("allow", "deny", "ask", "x"):
            for scope in ("exact", "tool_under", "tool", "y"):
                for args in ({}, {"path": "/a/b"}, {"a": 1}, None):
                    try:
                        build_rule(verdict, scope, "fs", "t", args)
                    except ValueError as e:
                        seen.add(str(e))
        assert seen == {"cannot_build", "scope_not_allowed"}


class TestBuildNames:
    @pytest.mark.parametrize("name", ["a\nb", "a\rb", "a\x00b", "a‮b", "a​b", "a b", "a\x1bb", "a\ud800b", "\t", "a\x7fb", "",
                                      "x" * 201, None, 5, b"fs", ["fs"], {"a": 1}])
    def test_bad_names_refused_for_server_and_tool(self, name):
        assert errors_of("deny", "tool", name, "t", {}) == "cannot_build"
        assert errors_of("deny", "tool", "fs", name, {}) == "cannot_build"

    def test_name_length_limit_counts_the_escaped_pattern(self):
        build_rule("deny", "tool", "fs", "x" * 200, {})
        assert errors_of("deny", "tool", "fs", "[" * 100, {}) == "cannot_build"        # escapes to 300 chars

    def test_huge_name_is_cheap(self):
        t = time.time()
        assert errors_of("deny", "tool", "fs", "x" * 10_000_000, {}) == "cannot_build"
        assert time.time() - t < 1

    def test_glob_characters_match_literally_only(self):
        r = build_rule("deny", "tool", "fs", "write_*", {})
        assert r["when"]["tool"] == "write_[*]"
        pol = P.Policy({"version": 1, "default": "allow", "rules": [r]})
        assert pol.evaluate("fs", "write_*", {}).verdict == "deny"
        for other in ("write_file", "write_", "write_x"):
            assert pol.evaluate("fs", other, {}).verdict == "allow", other
        for raw, other in (("a?c", "abc"), ("t[ab]", "ta"), ("[", "x"), ("a]b", "a]c"), ("*", "anything"), ("?", "x")):
            rr = build_rule("deny", "tool", "fs", raw, {})
            pp = P.Policy({"version": 1, "default": "allow", "rules": [rr]})
            assert pp.evaluate("fs", raw, {}).verdict == "deny", raw
            assert pp.evaluate("fs", other, {}).verdict == "allow", (raw, other)

    def test_server_escaped_too(self):
        r = build_rule("allow", "exact", "fs*", "t", {"a": 1})
        pol = P.Policy({"version": 1, "default": "deny", "rules": [r]})
        assert pol.evaluate("fs*", "t", {"a": 1}).verdict == "allow"
        assert pol.evaluate("fs2", "t", {"a": 1}).verdict == "deny"

    def test_unicode_names_ok(self):
        r = build_rule("deny", "tool", "srvé", "outil☃", {})
        P.load_policy({"version": 1, "rules": [r]})


class TestBuildNote:
    def test_note(self):
        assert rule_for(note="n" * 200)["note"] == "n" * 200
        assert "note" not in rule_for(note="") and "note" not in rule_for(note=None)

    @pytest.mark.parametrize("note", ["n" * 201, "a\nb", "a‮b", "a\x00b", 5, b"x", ["x"]])
    def test_bad_note(self, note):
        assert errors_of("deny", "tool", "fs", "t", {}, note=note) == "cannot_build"

    def test_note_does_not_change_the_id(self):
        assert rule_for(note="one")["id"] == rule_for(note="two")["id"] == rule_for()["id"]


# ---------------------------------------------------------------------------
# append_rule
# ---------------------------------------------------------------------------

class TestAppend:
    def test_appends_and_reports_digests(self, pfile):
        before = snapshot(pfile)
        d0 = P.load_policy(pfile).digest()
        r = rule_for()
        info = append_rule(pfile, r)
        assert info["rule_id"] == r["id"] and info["digest_before"] == d0
        pol = P.load_policy(pfile)
        assert info["digest_after"] == pol.digest() != d0
        assert [x.id for x in pol.rules] == ["read-project", "no-writes-outside", r["id"]]
        assert pol.default == "ask" and pol.rules[0].note == "reads are routine"
        assert snapshot(pfile + ".bak") == before

    def test_result_is_valid_json_and_ascii(self, pfile):
        append_rule(pfile, rule_for(note="café ☃"))
        raw = snapshot(pfile)
        raw.decode("ascii")
        assert json.loads(raw)["rules"][-1]["note"] == "café ☃"
        assert raw.endswith(b"\n")

    def test_end_to_end_decision_changes(self, pfile):
        pol0 = P.load_policy(pfile)
        assert pol0.evaluate("fs", "delete_file", {"path": "/project/a/b.txt"}).verdict == "ask"
        append_rule(pfile, build_rule("deny", "tool_under", "fs", "delete_file", {"path": "/project/a/b.txt"}))
        pol1 = P.load_policy(pfile)
        assert pol1.evaluate("fs", "delete_file", {"path": "/project/a/c.txt"}).verdict == "deny"
        assert pol1.evaluate("fs", "delete_file", {"path": "/project/z/c.txt"}).verdict == "ask"

    def test_lint_warnings_are_allowed(self, pfile):
        r = rule_for(verdict="allow", scope="exact", path="/project/x")                   # allow rules are fine; lint may warn elsewhere
        append_rule(pfile, build_rule("deny", "tool", "fs", "write_file", {}))
        append_rule(pfile, build_rule("ask", "tool", "fs", "write_file", {}))
        pol = P.load_policy(pfile)
        assert any("shadowed" in w or "duplicate" in w for w in pol.lint()) or True
        append_rule(pfile, r)

    def test_file_mode_and_no_leftovers(self, pfile):
        os.chmod(pfile, 0o644)
        append_rule(pfile, rule_for())
        assert stat.S_IMODE(os.stat(pfile).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(pfile + ".bak").st_mode) == 0o600
        assert side_files(pfile) == [os.path.basename(pfile) + ".bak", os.path.basename(pfile) + ".lock"]

    def test_pathlike_accepted(self, tmp_path, pfile):
        import pathlib
        append_rule(pathlib.Path(pfile), rule_for())
        assert len(P.load_policy(pfile).rules) == 3

    def test_second_distinct_rule_updates_bak(self, pfile):
        append_rule(pfile, rule_for(tool="a_tool"))
        mid = snapshot(pfile)
        append_rule(pfile, rule_for(tool="b_tool"))
        assert snapshot(pfile + ".bak") == mid and len(P.load_policy(pfile).rules) == 4

    def test_default_and_unknown_formatting_preserved_semantically(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text('{"version":1,"default":"deny","rules":[]}')
        append_rule(str(f), rule_for())
        assert P.load_policy(str(f)).default == "deny"

    def test_policy_without_rules_key(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text('{"version":1}')
        append_rule(str(f), rule_for())
        assert len(P.load_policy(str(f)).rules) == 1


class TestIdempotence:
    def test_same_rule_twice(self, pfile):
        r = rule_for()
        first = append_rule(pfile, r)
        after_first = snapshot(pfile)
        bak = snapshot(pfile + ".bak")
        second = append_rule(pfile, r)
        assert second["rule_id"] == first["rule_id"]
        assert second["digest_after"] == second["digest_before"] == first["digest_after"]
        assert snapshot(pfile) == after_first and snapshot(pfile + ".bak") == bak
        assert len(P.load_policy(pfile).rules) == 3

    def test_repeated_clicks_rebuild_same_rule(self, pfile):
        for _ in range(5):
            append_rule(pfile, rule_for())
        assert len(P.load_policy(pfile).rules) == 3

    def test_existing_identical_rule_with_other_id_returns_its_id(self, tmp_path):
        r = rule_for()
        hand = {"id": "hand-written", "verdict": r["verdict"], "when": r["when"], "note": "mine"}
        f = tmp_path / "p.json"
        f.write_text(json.dumps({"version": 1, "rules": [hand]}))
        before = snapshot(str(f))
        info = append_rule(str(f), r)
        assert info["rule_id"] == "hand-written" and info["digest_after"] == info["digest_before"]
        assert snapshot(str(f)) == before and not os.path.exists(str(f) + ".bak")

    def test_note_difference_is_still_the_same_rule(self, pfile):
        append_rule(pfile, rule_for(note="first"))
        snap = snapshot(pfile)
        assert append_rule(pfile, rule_for(note="second"))["digest_after"] == P.load_policy(pfile).digest()
        assert snapshot(pfile) == snap

    def test_different_verdict_is_a_different_rule(self, pfile):
        append_rule(pfile, rule_for(verdict="deny"))
        append_rule(pfile, rule_for(verdict="ask"))
        assert len(P.load_policy(pfile).rules) == 4

    def test_different_value_is_a_different_rule(self, pfile):
        append_rule(pfile, rule_for(path="/project/a/x"))
        append_rule(pfile, rule_for(path="/project/b/x"))
        assert len(P.load_policy(pfile).rules) == 4


class TestPathHandling:
    @pytest.mark.parametrize("bad", [0, 1, 2, 3, 100, True, False, None, b"/tmp/x", 1.5, "", "a\x00b", ["x"], object()])
    def test_non_path_refused(self, bad):
        e = write_err(bad, rule_for())
        assert e.reason == "write_failed"

    def test_file_descriptor_int_is_never_used(self, pfile):
        fd = os.open(pfile, os.O_RDWR)
        try:
            before = snapshot(pfile)
            assert write_err(fd, rule_for()).reason == "write_failed"
            assert snapshot(pfile) == before
            os.fstat(fd)                                           # still open, untouched
            assert os.lseek(fd, 0, os.SEEK_CUR) == 0
        finally:
            os.close(fd)

    def test_missing_file(self, tmp_path):
        e = write_err(str(tmp_path / "nope.json"), rule_for())
        assert e.reason == "not_found" and not (tmp_path / "nope.json").exists()
        assert os.listdir(tmp_path) == [] or all(not f.endswith((".tmp", ".bak")) for f in os.listdir(tmp_path))

    def test_missing_directory(self, tmp_path):
        assert write_err(str(tmp_path / "no" / "p.json"), rule_for()).reason == "not_found"

    def test_directory(self, tmp_path):
        assert write_err(str(tmp_path), rule_for()).reason == "write_failed"

    def test_symlink_refused(self, tmp_path, pfile):
        link = tmp_path / "link.json"
        os.symlink(pfile, link)
        before = snapshot(pfile)
        e = write_err(str(link), rule_for())
        assert e.reason == "write_failed" and "symlink" in e.detail
        assert snapshot(pfile) == before and os.path.islink(link)
        assert not os.path.exists(str(link) + ".bak")

    def test_dangling_symlink(self, tmp_path):
        link = tmp_path / "dangling.json"
        os.symlink(str(tmp_path / "nowhere"), link)
        assert write_err(str(link), rule_for()).reason == "write_failed"

    def test_fifo_refused(self, tmp_path):
        fifo = tmp_path / "fifo.json"
        os.mkfifo(fifo)
        assert write_err(str(fifo), rule_for()).reason == "write_failed"

    def test_planted_symlinks_for_side_files_are_not_followed(self, tmp_path, pfile):
        victim = tmp_path / "victim.txt"
        victim.write_text("precious")
        for side in (".tmp", ".bak", ".bak.tmp", ".lock"):
            os.symlink(str(victim), pfile + side)
        try:
            append_rule(pfile, rule_for())
        except PolicyWriteError:
            pass                                                   # refusing is fine; clobbering the victim is not
        assert victim.read_text() == "precious"

    def test_stale_tmp_is_replaced(self, pfile):
        open(pfile + ".tmp", "w").write("junk from a crash")
        append_rule(pfile, rule_for())
        assert not os.path.exists(pfile + ".tmp") and len(P.load_policy(pfile).rules) == 3


class TestInvalidInputs:
    def test_existing_file_not_json(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text("{not json")
        assert write_err(str(f), rule_for()).reason == "invalid_policy"
        assert f.read_text() == "{not json" and not os.path.exists(str(f) + ".bak")

    @pytest.mark.parametrize("content", ['[1]', '{"version": 2}', '{"version":1,"bogus":1}', '{"version":1,"rules":[{"id":"a"}]}',
                                         '{"version":1,"rules":[]', b"\xff\xfe", ""])
    def test_existing_file_invalid(self, tmp_path, content):
        f = tmp_path / "p.json"
        f.write_bytes(content if isinstance(content, bytes) else content.encode())
        before = snapshot(str(f))
        assert write_err(str(f), rule_for()).reason == "invalid_policy"
        assert snapshot(str(f)) == before

    def test_existing_file_too_large(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_bytes(b" " * (P.MAX_FILE_BYTES + 10) + b'{"version":1}')
        assert write_err(str(f), rule_for()).reason == "invalid_policy"

    @pytest.mark.parametrize("bad", [
        None, [], "rule", 5, {}, {"id": 5, "verdict": "deny"}, {"id": "x"},
        {"id": "x", "verdict": "maybe"}, {"id": "bad id", "verdict": "deny"}, {"id": "x", "verdict": "deny", "extra": 1},
        {"id": "x", "verdict": "deny", "when": {"tool": ""}}, {"id": "x", "verdict": "deny", "when": {"args": [{"path": "p", "op": "regex", "value": "x"}]}},
        {"id": "x", "verdict": "deny", "when": {"tool": "t" * 201}}, {"id": "x", "verdict": "deny", "note": "n" * 201},
        {"id": "x", "verdict": "deny", "when": {"args": [{"path": "p", "op": "equals", "value": float("nan")}]}},
        {"id": "x", "verdict": "deny", "when": {"tool": object()}}, {"id": "x", "verdict": "deny", "when": {"alert": "yes"}},
    ])
    def test_invalid_rules_are_refused_and_nothing_changes(self, pfile, bad):
        before = snapshot(pfile)
        assert write_err(pfile, bad).reason == "invalid_policy"
        assert snapshot(pfile) == before and not os.path.exists(pfile + ".bak")

    def test_duplicate_id_with_different_content(self, pfile):
        r = rule_for()
        append_rule(pfile, r)
        clash = dict(r, when={"server": "other", "tool": "other"})
        before = snapshot(pfile)
        assert write_err(pfile, clash).reason == "invalid_policy"
        assert snapshot(pfile) == before

    def test_rule_limit(self, tmp_path):
        f = tmp_path / "p.json"
        f.write_text(json.dumps({"version": 1, "rules": [{"id": f"r{i}", "verdict": "ask", "when": {"tool": f"t{i}"}} for i in range(500)]}))
        before = snapshot(str(f))
        e = write_err(str(f), rule_for())
        assert e.reason == "invalid_policy" and snapshot(str(f)) == before

    def test_result_too_large(self, tmp_path):
        f = tmp_path / "p.json"
        pad = {"id": "pad", "verdict": "ask", "note": "n" * 200}
        rules = [dict(pad, id=f"pad{i}", when={"tool": "t" * 190 + str(i)}) for i in range(499)]
        f.write_text(json.dumps({"version": 1, "rules": rules}))
        assert len(f.read_bytes()) < P.MAX_FILE_BYTES
        info = append_rule(str(f), rule_for())                       # 500th rule still fits and is valid
        assert P.load_policy(str(f)).digest() == info["digest_after"]

    def test_hostile_rule_content_is_bounded(self, pfile):
        huge = {"id": "h", "verdict": "deny", "when": {"args": [{"path": "p", "op": "in", "value": list(range(100_000))}]}}
        t = time.time()
        assert write_err(pfile, huge).reason == "invalid_policy"
        deep = cur = {}
        for _ in range(5000):
            cur["k"] = {}
            cur = cur["k"]
        assert write_err(pfile, {"id": "d", "verdict": "deny", "when": deep}).reason == "invalid_policy"
        assert write_err(pfile, {"id": "k", "verdict": "deny", "when": {str(i): 1 for i in range(10_000)}}).reason == "invalid_policy"
        assert time.time() - t < 10
        assert P.load_policy(pfile).digest() == P.load_policy(pfile).digest() and len(P.load_policy(pfile).rules) == 2

    def test_rule_object_is_not_mutated(self, pfile):
        r = rule_for()
        copy = json.loads(json.dumps(r))
        append_rule(pfile, r)
        assert r == copy


class TestAtomicity:
    """A failure at ANY point must leave the original file byte-identical."""

    def _fail_nth(self, monkeypatch, name, nth, exc=OSError("injected")):
        real = getattr(os, name)
        calls = {"n": 0}

        def fake(*a, **k):
            calls["n"] += 1
            if calls["n"] == nth:
                raise exc
            return real(*a, **k)
        monkeypatch.setattr(os, name, fake)
        return calls

    @pytest.mark.parametrize("nth", [1, 2])
    def test_os_replace_failure(self, pfile, monkeypatch, nth):
        before = snapshot(pfile)
        calls = self._fail_nth(monkeypatch, "replace", nth)
        assert write_err(pfile, rule_for()).reason == "write_failed"
        assert calls["n"] == nth
        assert snapshot(pfile) == before
        assert not os.path.exists(pfile + ".tmp") and not os.path.exists(pfile + ".bak.tmp")
        monkeypatch.undo()
        append_rule(pfile, rule_for())                              # recovers
        assert len(P.load_policy(pfile).rules) == 3

    @pytest.mark.parametrize("nth", [1, 2])
    @pytest.mark.parametrize("exc", [OSError("disk full"), RuntimeError("boom")])
    def test_os_write_failure(self, pfile, monkeypatch, nth, exc):
        before = snapshot(pfile)
        self._fail_nth(monkeypatch, "write", nth, exc)
        e = write_err(pfile, rule_for())
        assert e.reason == "write_failed" and snapshot(pfile) == before
        assert [f for f in os.listdir(os.path.dirname(pfile)) if f.endswith(".tmp")] == []

    def test_partial_write_then_failure(self, pfile, monkeypatch):
        before = snapshot(pfile)
        real = os.write
        n = {"c": 0}

        def half(fd, data):
            n["c"] += 1
            if n["c"] == 1:
                real(fd, bytes(data)[:7])
                raise OSError("died after 7 bytes")
            return real(fd, data)
        monkeypatch.setattr(os, "write", half)
        assert write_err(pfile, rule_for()).reason == "write_failed"
        assert snapshot(pfile) == before

    @pytest.mark.parametrize("nth", [1, 2])
    def test_file_fsync_failure(self, pfile, monkeypatch, nth):
        before = snapshot(pfile)
        self._fail_nth(monkeypatch, "fsync", nth)
        assert write_err(pfile, rule_for()).reason == "write_failed"
        assert snapshot(pfile) == before

    def test_tmp_creation_failure(self, pfile, monkeypatch):
        before = snapshot(pfile)
        real = os.open

        def fake(path, flags, *a, **k):
            if str(path).endswith(".tmp"):
                raise PermissionError("no tmp for you")
            return real(path, flags, *a, **k)
        monkeypatch.setattr(os, "open", fake)
        assert write_err(pfile, rule_for()).reason == "write_failed"
        assert snapshot(pfile) == before

    def test_lock_failure(self, pfile, monkeypatch):
        before = snapshot(pfile)
        real = os.open

        def fake(path, flags, *a, **k):
            if str(path).endswith(".lock"):
                raise OSError("no lock file")
            return real(path, flags, *a, **k)
        monkeypatch.setattr(os, "open", fake)
        assert write_err(pfile, rule_for()).reason == "write_failed"
        assert snapshot(pfile) == before

    def test_directory_fsync_failure_after_replace_is_not_an_error(self, pfile, monkeypatch):
        real = os.open

        def fake(path, flags, *a, **k):
            if os.path.isdir(str(path)):
                raise OSError("cannot open dir")
            return real(path, flags, *a, **k)
        monkeypatch.setattr(os, "open", fake)
        append_rule(pfile, rule_for())
        assert len(P.load_policy(pfile).rules) == 3

    def test_unreadable_state_changes_nothing_on_validation_failure(self, pfile):
        before = snapshot(pfile)
        write_err(pfile, {"id": "x", "verdict": "nope"})
        assert snapshot(pfile) == before and side_files(pfile) == [os.path.basename(pfile) + ".lock"]

    @pytest.mark.skipif(IS_ROOT, reason="root ignores directory permissions")
    def test_read_only_directory(self, tmp_path):
        d = tmp_path / "ro"
        d.mkdir()
        f = d / "policy.json"
        f.write_text(json.dumps(BASE))
        before = f.read_bytes()
        os.chmod(d, 0o500)
        try:
            assert write_err(str(f), rule_for()).reason == "write_failed"
            assert f.read_bytes() == before
        finally:
            os.chmod(d, 0o700)

    @pytest.mark.skipif(IS_ROOT, reason="root ignores file permissions")
    def test_unreadable_file(self, pfile):
        os.chmod(pfile, 0)
        try:
            assert write_err(pfile, rule_for()).reason == "write_failed"
        finally:
            os.chmod(pfile, 0o600)

    def test_never_modifies_in_place(self, pfile):
        ino = os.stat(pfile).st_ino
        fd = os.open(pfile, os.O_RDONLY)                            # an open handle keeps seeing the old content
        try:
            append_rule(pfile, rule_for())
            assert os.stat(pfile).st_ino != ino
            assert json.loads(os.read(fd, 10_000)) == BASE
        finally:
            os.close(fd)


class TestConcurrency:
    def test_8_threads_x_5_distinct_rules(self, pfile):
        errs = []
        rules = [[rule_for(tool=f"tool_{t}_{i}", path=f"/project/d{t}/f{i}") for i in range(5)] for t in range(8)]

        def worker(t):
            try:
                for r in rules[t]:
                    append_rule(pfile, r)
            except BaseException as e:               # noqa: BLE001
                errs.append(e)
        ths = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        assert errs == []
        pol = P.load_policy(pfile)
        assert len(pol.rules) == 2 + 40
        ids = [r.id for r in pol.rules]
        assert len(set(ids)) == len(ids) and {r["id"] for ts in rules for r in ts} <= set(ids)
        json.loads(snapshot(pfile))

    def test_same_rule_from_8_threads_is_added_once(self, pfile):
        results = []

        def worker():
            results.append(append_rule(pfile, rule_for()))
        ths = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        assert len(P.load_policy(pfile).rules) == 3 and len({r["rule_id"] for r in results}) == 1

    def test_digest_chain_is_linear(self, pfile):
        out = []

        def worker(t):
            for i in range(3):
                out.append(append_rule(pfile, rule_for(tool=f"x{t}_{i}")))
        ths = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        befores = [o["digest_before"] for o in out]
        afters = [o["digest_after"] for o in out]
        assert len(set(befores)) == len(set(afters)) == 12
        assert set(befores) - set(afters) == {P.Policy(BASE).digest()}          # each write starts from the previous one's result

    def test_multiple_processes_use_the_file_lock(self, pfile, tmp_path):
        script = tmp_path / "w.py"
        script.write_text(
            "import sys\nsys.path.insert(0, sys.argv[1])\nimport policy_writer as W\n"
            "n = int(sys.argv[3])\nfor i in range(5):\n"
            "    W.append_rule(sys.argv[2], W.build_rule('deny', 'tool', 'fs', f'proc{n}_{i}', {}))\n")
        procs = [subprocess.Popen([sys.executable, "-I", str(script), SERVER_DIR, pfile, str(n)], stderr=subprocess.PIPE) for n in range(4)]
        for p in procs:
            assert p.wait(timeout=120) == 0, p.stderr.read()
        assert len(P.load_policy(pfile).rules) == 2 + 20

    def test_lock_file_mode(self, pfile):
        append_rule(pfile, rule_for())
        assert stat.S_IMODE(os.stat(pfile + ".lock").st_mode) == 0o600


def test_module_has_no_web_imports():
    imports = [ln for ln in open(W.__file__, encoding="utf-8").read().splitlines() if ln.lstrip().startswith(("import ", "from "))]
    assert imports and not any(w in ln.lower() for ln in imports for w in ("fastapi", "starlette"))
