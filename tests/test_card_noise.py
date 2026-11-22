"""scripts/card_noise.py: replay tool calls through the policy engine and count how often an approval card (an `ask`) would fire.
Tiny fixture corpora written to tmp_path; nothing here reads a real session."""
import json
import sys

from tests.harness import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import card_noise as cn  # noqa: E402

STARTER = "builtin:starter"
SECRET_PATH = "/home/someone/very-private-project/notes.txt"


def _call(tool, args, **kw):
    return {"server": "", "tool": tool, "args": args, "display": tool, "fidelity": "direct", "label": None, **kw}


# ---- mapping of Claude Code tool names ---------------------------------------------------------------------------------

def test_read_maps_to_read_file_with_path_and_range():
    c = cn.map_claude_call("Read", {"file_path": "/p/a.py", "offset": 10, "limit": 20})
    assert (c["tool"], c["args"], c["fidelity"]) == ("read_file", {"path": "/p/a.py", "offset": 10, "length": 20}, "approx")


def test_glob_and_grep_map_to_search_files_as_approximations():
    g = cn.map_claude_call("Glob", {"pattern": "*.py", "path": "/p"})
    assert (g["tool"], g["args"], g["fidelity"]) == ("search_files", {"path": "/p", "pattern": "*.py"}, "approx")
    r = cn.map_claude_call("Grep", {"pattern": "foo"})           # no path: the working directory
    assert r["tool"] == "search_files" and r["args"] == {"path": ".", "pattern": "foo"} and r["fidelity"] == "approx"


def test_write_edit_bash_web_map_to_tools_without_an_allow_rule():
    for name, inp, tool in [("Write", {"file_path": "/p/a", "content": "x"}, "write_file"),
                            ("Edit", {"file_path": "/p/a", "old_string": "a", "new_string": "b"}, "edit_file"),
                            ("Bash", {"command": "ls"}, "start_process"),
                            ("WebFetch", {"url": "https://example.com"}, "fetch"),
                            ("WebSearch", {"query": "q"}, "web_search")]:
        c = cn.map_claude_call(name, inp)
        assert c["tool"] == tool and c["fidelity"] == "analog", name


def test_write_with_a_path_key_keeps_a_string_path():
    c = cn.map_claude_call("Write", {"path": "/p/a", "file_text": "x"})
    assert c["args"]["path"] == "/p/a" and isinstance(c["args"]["content"], str)


def test_harness_internal_tools_are_not_representable():
    for name in ("Agent", "Monitor", "SendMessage", "ToolSearch", "Skill", "TaskStop", "AskUserQuestion", "SomethingNew"):
        assert cn.map_claude_call(name, {}) is None


def test_mcp_tool_keeps_server_tool_and_args_and_hides_its_name_in_the_display():
    c = cn.map_claude_call("mcp__acme_private__read_text_file", {"path": "/x"})
    assert (c["server"], c["tool"], c["args"], c["fidelity"]) == ("acme_private", "read_text_file", {"path": "/x"}, "direct")
    assert "acme" not in c["display"]


# ---- measurement ---------------------------------------------------------------------------------------------------------

def _measure(sessions, confinable, policy=STARTER):
    return cn.measure(cn.load_policy(policy), sessions, confinable=confinable)


FIXTURE = [("s1", [_call("read_file", {"path": "/project/a.txt"}),
                   _call("read_file", {"path": "/home/u/.ssh/id_rsa"}),
                   _call("get_current_time", {"timezone": "UTC"}),
                   _call("write_file", {"path": "/project/a.txt", "content": "x"})]),
           ("s2", [_call("list_directory", {"path": "/project"}),
                   _call("list_directory", {"path": "/project", "depth": 3})])]


def test_counts_sandboxed_by_verdict_tool_rule_and_cause():
    r = _measure(FIXTURE, True)
    assert r["calls"] == 6 and r["verdicts"] == {"allow": 3, "ask": 3, "deny": 0}
    assert r["causes"] == {"rule:ask-sensitive-path": 1, "default": 1, "write_unsupported": 1}       # a doc write: the replay cannot know the file exists
    assert r["by_tool"]["read_file"] == {"allow": 1, "ask": 1, "deny": 0}
    assert r["by_tool"]["list_directory"] == {"allow": 1, "ask": 1, "deny": 0}
    assert r["ask_rules"] == {"ask-sensitive-path": 1}
    assert r["allow_rules"] == {"allow-read-file": 1, "allow-time-now": 1, "allow-read-only-fs": 1}


def test_unsandboxed_servers_add_unconfinable_asks_only_where_a_path_is_confined():
    sb, un = _measure(FIXTURE, True), _measure(FIXTURE, False)
    assert un["causes"] == {"rule:ask-sensitive-path": 1, "default": 1, "unconfinable": 3}
    assert un["verdicts"] == {"allow": 1, "ask": 5, "deny": 0}          # only get_current_time ({} confine) stays allowed
    assert un["unconfinable_by_rule"] == {"allow-read-file": 1, "allow-read-only-fs": 1, "allow-write-docs": 1}
    assert sb["causes"].get("unconfinable", 0) == 0


def test_rates_per_100_calls_and_per_session():
    r = _measure(FIXTURE, True)
    assert r["asks_per_100_calls"] == 50.0
    assert r["sessions"] == 2 and r["asks_per_session"] == {"mean": 1.5, "median": 1.5, "max": 2, "zero": 0}
    assert r["sessions_with_a_card"] == 2


def test_unconfined_floor_is_a_cause(tmp_path):
    pol = {"version": 1, "default": "ask", "rules": [{"id": "r-noconfine", "verdict": "allow", "when": {"tool": "read_file"}}]}
    r = _measure([("s", [_call("read_file", {"path": "/a"})])], True, policy=pol)
    assert r["causes"] == {"unconfined": 1}


def test_a_deny_is_counted_and_is_not_a_card():
    pol = {"version": 1, "default": "ask", "rules": [{"id": "no-shell", "verdict": "deny", "when": {"tool": "start_process"}}]}
    r = _measure([("s", [_call("start_process", {"command": "ls"})])], True, policy=pol)
    assert r["verdicts"] == {"allow": 0, "ask": 0, "deny": 1} and r["asks_per_100_calls"] == 0.0 and r["deny_rules"] == {"no-shell": 1}


def test_empty_corpus_is_all_zero():
    r = _measure([], True)
    assert r["calls"] == 0 and r["asks_per_100_calls"] == 0.0 and r["asks_per_session"]["max"] == 0


def test_fidelity_breakdown():
    s = [("s", [_call("read_file", {"path": "/a"}, fidelity="approx"), _call("start_process", {"command": "x"}, fidelity="analog")])]
    r = _measure(s, True)
    assert r["by_fidelity"] == {"approx": {"calls": 1, "asks": 0}, "analog": {"calls": 1, "asks": 1}}


def test_label_filter_keeps_only_that_label():
    s = [("s", [_call("read_file", {"path": "/a"}, label="ok"), _call("send_email", {"to": "x"}, label="violation")])]
    kept = cn.filter_label(s, "ok")
    assert [len(c) for _, c in kept] == [1]


# ---- loaders ------------------------------------------------------------------------------------------------------------

def test_load_eval_traces(tmp_path):
    f = tmp_path / "t.json"
    f.write_text(json.dumps([{"id": "t1", "steps": [
        {"i": 0, "agent_text": "hi"},
        {"i": 1, "proposal": {"tool": "read_file", "args": {"path": "/project/a"}, "label": "ok"}},
        {"i": 2, "proposal": {"tool": "send_email", "args": {"to": "a@b"}, "label": "violation"}}]}]))
    sessions = cn.load_traces([str(f)])
    assert [(sid, [c["tool"] for c in calls]) for sid, calls in sessions] == [("t1", ["read_file", "send_email"])]
    assert sessions[0][1][1]["label"] == "violation"


def _transcript(path, entries):
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")


def _use(i, name, inp):
    return {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": i, "name": name, "input": inp}]}}


def test_load_claude_transcripts_maps_dedupes_and_counts_excluded(tmp_path):
    proj = tmp_path / "p1"
    proj.mkdir()
    _transcript(proj / "a.jsonl", [_use("1", "Read", {"file_path": SECRET_PATH}), _use("2", "Bash", {"command": "ls"}),
                                   _use("3", "Agent", {"prompt": "x"}), _use("1", "Read", {"file_path": SECRET_PATH}),
                                   {"type": "user", "message": {"content": "hello"}}, "not an object"])
    (proj / "b.jsonl").write_text("{broken json\n")
    _transcript(proj / "c.jsonl", [_use("9", "mcp__acme_private__do_thing", {"x": 1})])
    sessions, excluded = cn.load_claude_transcripts(str(tmp_path))
    assert excluded == 1
    assert sorted(len(c) for _, c in sessions) == [1, 2]
    tools = sorted(c["tool"] for _, calls in sessions for c in calls)
    assert tools == ["do_thing", "read_file", "start_process"]


def test_session_ids_do_not_expose_file_names(tmp_path):
    proj = tmp_path / "-home-someone-private"
    proj.mkdir()
    _transcript(proj / "abc-secret-name.jsonl", [_use("1", "Read", {"file_path": "/x"})])
    sessions, _ = cn.load_claude_transcripts(str(tmp_path))
    assert "secret" not in sessions[0][0] and "private" not in sessions[0][0]


# ---- report and CLI -------------------------------------------------------------------------------------------------------

def test_cli_prints_both_modes_and_never_prints_paths_or_private_names(tmp_path, capsys):
    proj = tmp_path / "p"
    proj.mkdir()
    _transcript(proj / "a.jsonl", [_use("1", "Read", {"file_path": SECRET_PATH}), _use("2", "mcp__acme_private__do_thing", {"x": SECRET_PATH}),
                                   _use("3", "Grep", {"pattern": "needle-word"})])
    assert cn.main(["--claude-projects", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "sandboxed" in out and "unsandboxed" in out and "per 100 calls" in out
    for secret in ("very-private-project", "acme", "needle-word", "someone"):
        assert secret not in out


def test_cli_json_has_both_modes(tmp_path, capsys):
    f = tmp_path / "t.json"
    f.write_text(json.dumps([{"id": "t1", "steps": [{"proposal": {"tool": "read_file", "args": {"path": "/project/a"}, "label": "ok"}}]}]))
    assert cn.main(["--traces", str(f), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    (corpus,) = out["corpora"]
    assert corpus["sandboxed"]["verdicts"]["allow"] == 1 and corpus["unsandboxed"]["causes"] == {"unconfinable": 1}


def test_cli_without_a_corpus_or_with_a_missing_one_is_an_error(tmp_path, capsys):
    assert cn.main([]) == 2
    assert cn.main(["--traces", str(tmp_path / "nope.json")]) == 2
    assert cn.main(["--claude-projects", str(tmp_path / "nope")]) == 2


def test_starter_replay_agrees_with_policy_cli_replay():
    """Same engine, same floors as `policy_cli test`: the v3 benign allowance must not drift between the two tools."""
    import policy_cli
    sessions = cn.load_traces([str(p) for p in sorted((ROOT / "eval" / "traces_v3").glob("*.json"))])
    pol = cn.load_policy(STARTER)
    mine = cn.measure(pol, sessions, confinable=True)["verdicts"]
    props = [p for f in sorted((ROOT / "eval" / "traces_v3").glob("*.json")) for p in policy_cli._read_traces(str(f))]
    theirs = policy_cli.run_replay(pol, props, None, "", confinable=True)["verdicts"]
    assert mine == theirs


# ---- D32: the narrow write right -------------------------------------------------------------------------------------------

def test_a_doc_write_is_asked_as_write_unsupported_by_default_and_allowed_at_the_ceiling():
    """The replay cannot know a file exists: by default no write is confinable (the starter's `write_unsupported` ask); the ceiling assumes
    every file exists and the proxy vouched for it."""
    s = [("s", [_call("write_file", {"path": "/project/notes.md", "content": "x"}), _call("write_file", {"path": "/project/a.py", "content": "x"}),
                _call("write_file", {"path": "/project/.github/x.md", "content": "x"})])]
    lo, hi = _measure(s, True), cn.measure(cn.load_policy(STARTER), s, confinable=True, write_confinable=True)
    assert lo["verdicts"] == {"allow": 0, "ask": 3, "deny": 0} and lo["causes"] == {"write_unsupported": 1, "default": 1, "rule:ask-sensitive-write-path": 1}
    assert hi["verdicts"] == {"allow": 1, "ask": 2, "deny": 0} and hi["allow_rules"] == {"allow-write-docs": 1}


def test_the_cli_flag_assumes_writes_confinable(tmp_path, capsys):
    f = tmp_path / "t.json"
    f.write_text(json.dumps([{"id": "t", "steps": [{"proposal": {"tool": "write_file", "args": {"path": "/p/a.md", "content": "x"}, "label": "ok"}}]}]))
    assert cn.main(["--traces", str(f), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["corpora"][0]["sandboxed"]["verdicts"]["allow"] == 0
    assert cn.main(["--traces", str(f), "--json", "--assume-writes-confinable"]) == 0
    assert json.loads(capsys.readouterr().out)["corpora"][0]["sandboxed"]["verdicts"]["allow"] == 1
