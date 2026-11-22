"""The starter policy's write rules (DECISIONS D32): `allow-write-docs` / `allow-edit-docs` overwrite an EXISTING documentation or data file, and
`ask-sensitive-write-path` beats them for anything a tool, a shell, git or CI later runs or obeys. The kernel bounds a write to one inode; these rules
decide which inodes are worth it. Everything else (creating, moving, source code, Desktop Commander, an extra argument) stays a card."""
import json
import os

import pytest

import policy as P
import policy_cli as C

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STARTER = os.path.join(ROOT, "server", "policies", "starter.json")
TRACES = os.path.join(ROOT, "eval", "final_v3", "traces.json")
DOC_EXTS = [".md", ".txt", ".rst", ".csv", ".log"]


@pytest.fixture(scope="module")
def pol():
    return P.load_policy(STARTER)


def ev(pol, tool, args, *, confinable=True, write_confinable=True, **kw):
    return pol.evaluate_call("fs", tool, args, confinable=confinable, write_confinable=write_confinable, **kw)


def w(path, **extra):
    return {"path": path, "content": "hello\n", **extra}


def e(path, n=1, **extra):
    return {"path": path, "edits": [{"oldText": "a", "newText": "b"}] * n, **extra}


# --------------------------------------------------------------------------- what is allowed


@pytest.mark.parametrize("ext", DOC_EXTS)
def test_a_confinable_overwrite_of_a_doc_is_allowed_with_a_write_confine_map(pol, ext):
    d = ev(pol, "write_file", w(f"/project/docs/notes{ext}"))
    assert (d.verdict, d.rule_id, d.confine) == ("allow", "allow-write-docs", {"path": "write"})
    d = ev(pol, "edit_file", e(f"/project/docs/notes{ext}"))
    assert (d.verdict, d.rule_id, d.confine) == ("allow", "allow-edit-docs", {"path": "write"})


def test_edit_file_may_carry_dryrun_and_up_to_50_edits_and_write_file_up_to_20000_characters(pol):
    assert ev(pol, "edit_file", e("/p/a.md", 50, dryRun=False)).verdict == "allow"
    assert ev(pol, "write_file", {"path": "/p/a.md", "content": "x" * 20000}).verdict == "allow"
    assert ev(pol, "write_file", {"path": "/p/a.md", "content": ""}).verdict == "allow"


# --------------------------------------------------------------------------- what is asked


@pytest.mark.parametrize("path", ["/p/a.py", "/p/a.json", "/p/a.yaml", "/p/a.yml", "/p/a.toml", "/p/a.sh", "/p/a.js", "/p/a.ts", "/p/a.html", "/p/a",
                                  "/p/Makefile", "/p/package.json", "/p/conftest.py", "/p/a.md.py", "/p/a.MD", "/p/a.markdown", "/p/a.md/b", "/p/mdfile",
                                  "/p/a.ipynb", "/p/a.rst.sh", "/p/a.cfg"])
def test_anything_but_the_five_extensions_is_asked(pol, path):
    for tool, args in (("write_file", w(path)), ("edit_file", e(path))):
        d = ev(pol, tool, args)
        assert d.verdict == "ask" and d.reason == "default", (path, d)


@pytest.mark.parametrize("path", [
    "/p/.git/hooks/pre-commit", "/p/.git/hooks/post-merge.md", "/p/.git/info/exclude.txt", "/p/.github/workflows/ci.md", "/p/.github/x.md",
    "/p/.gitlab-ci.md", "/p/.circleci/config.md", "/p/Jenkinsfile.md", "/p/.husky/pre-commit.md", "/p/.vscode/tasks.md", "/p/.claude/settings.md",
    "/p/.cursor/rules.md", "/p/CLAUDE.md", "/p/sub/claude.md", "/p/AGENTS.md", "/p/GEMINI.md", "/p/.github/copilot-instructions.md",
    "/home/u/.bashrc.md", "/home/u/.zshrc.txt", "/home/u/.profile.md", "/home/u/.bash_profile.md", "/home/u/.zprofile.md", "/p/.envrc.md",
    "/home/u/.ssh/config.md",
    "/p/requirements.txt", "/p/Requirements-dev.txt", "/p/constraints.txt", "/p/CMakeLists.txt", "/p/SKILL.md", "/p/skills/x/SKILL.md", "/p/AGENT.md",
    "/p/CONVENTIONS.md", "/p/.windsurf/rules.md", "/p/.clinerules/a.md", "/p/.roo/rules.md", "/p/.continue/rules.md", "/p/.aider.input.history.md", "/p/.AIDER.chat.md", "/home/u/.ssh/authorized_keys.txt", "/etc/crontab.txt", "/p/.env.md", "/p/.env.local.txt",
    "/p/.GIT/hooks/x.md", "/p/.GitHub/x.md", "/p/sub/../.git/hooks/x.md", "/p/.git//hooks/x.md", "/p/.git/./hooks/x.md", "/p\\.git\\hooks\\x.md",
])
def test_a_sensitive_path_is_asked_by_the_write_ask_rule_even_for_a_doc_extension(pol, path):
    for tool, args in (("write_file", w(path)), ("edit_file", e(path))):
        d = ev(pol, tool, args)
        assert d.verdict == "ask" and d.reason.startswith("rule:ask-sensitive"), (path, tool, d)
        assert "ask-sensitive-write-path" in d.matched or d.reason == "rule:ask-sensitive-path", (path, tool, d)


def test_the_write_ask_rule_names_only_write_tools_so_a_read_of_a_workflow_is_not_newly_asked(pol):
    assert ev(pol, "read_text_file", {"path": "/p/.github/workflows/ci.yml", "head": 3}).verdict == "allow"
    assert ev(pol, "list_directory", {"path": "/p/.github"}).verdict == "allow"
    assert ev(pol, "read_text_file", {"path": "/p/CLAUDE.md"}).verdict == "allow"


def test_a_sensitive_path_beats_the_allow_whatever_the_specificity(pol):
    d = ev(pol, "write_file", w("/p/.github/notes.md"))
    assert d.verdict == "ask" and d.rule_id == "ask-sensitive-write-path" and "allow-write-docs" in d.matched


def test_an_unbounded_or_odd_call_is_asked(pol):
    assert ev(pol, "write_file", {"path": "/p/a.md", "content": "x" * 20001}).verdict == "ask"
    assert ev(pol, "write_file", {"path": "/p/a.md", "content": "x" * 30000}).verdict == "ask"          # too long to examine at all
    assert ev(pol, "edit_file", e("/p/a.md", 51)).verdict == "ask"
    assert ev(pol, "write_file", {"path": "/p/a.md"}).verdict == "ask"                                  # no content
    assert ev(pol, "write_file", {"content": "x"}).verdict == "ask"                                     # no path
    for bad in (5, None, ["/p/a.md"], {"a": 1}, True):
        assert ev(pol, "write_file", {"path": bad, "content": "x"}).verdict == "ask", bad
    assert ev(pol, "write_file", {"path": "/p/a.md", "content": ["x"]}).verdict == "ask"
    assert ev(pol, "edit_file", {"path": "/p/a.md", "edits": "x"}).verdict == "ask"


@pytest.mark.parametrize("extra", [{"mode": "append"}, {"mode": "rewrite"}, {"isUrl": True}, {"encoding": "utf-8"}, {"overwrite": True}, {"path2": "/x"},
                                   {"destination": "/p/b.md"}, {"file_path": "/p/.env"}, {"source": "/p/a.md"}])
def test_an_extra_argument_makes_it_a_different_call_and_it_is_asked(pol, extra):
    """Desktop Commander's write_file (`mode`) and edit_block (`file_path`) are not the filesystem server's calls: v1 asks."""
    assert ev(pol, "write_file", w("/p/a.md", **extra)).verdict == "ask"
    assert ev(pol, "edit_file", e("/p/a.md", **extra)).verdict == "ask"


def test_desktop_commanders_write_calls_are_asked(pol):
    assert ev(pol, "write_file", {"path": "/p/a.md", "content": "x", "mode": "rewrite"}).verdict == "ask"
    d = ev(pol, "edit_block", {"file_path": "/p/a.md", "old_string": "a", "new_string": "b"})
    assert d.verdict == "ask" and d.reason == "default"


@pytest.mark.parametrize("tool, args", [("move_file", {"source": "/p/a.md", "destination": "/p/b.md"}), ("create_directory", {"path": "/p/docs"}),
                                        ("write_pdf", {"path": "/p/a.md", "content": "x"}), ("Write", {"path": "/p/a.md", "content": "x"}),
                                        ("write_file_v2", w("/p/a.md")), ("start_process", {"command": "echo x > /p/a.md"}),
                                        ("delete_file", {"path": "/p/a.md"})])
def test_creating_moving_deleting_and_other_tools_are_asked(pol, tool, args):
    assert ev(pol, tool, args).verdict == "ask"


# --------------------------------------------------------------------------- the floors apply to these allows like to any


def test_a_write_the_proxy_cannot_confine_is_asked_with_the_write_reason(pol):
    for wc in (False, None, "true", 1):
        d = ev(pol, "write_file", w("/p/new.md"), write_confinable=wc)
        assert (d.verdict, d.rule_id, d.reason, d.confine) == ("ask", "allow-write-docs", "write_unsupported", None)
    d = ev(pol, "edit_file", e("/p/new.md"), write_confinable=False)
    assert (d.verdict, d.rule_id, d.reason) == ("ask", "allow-edit-docs", "write_unsupported")


def test_an_unsandboxed_server_asks_for_a_write_with_the_unconfinable_reason(pol):
    d = ev(pol, "write_file", w("/p/a.md"), confinable=False)
    assert (d.verdict, d.reason) == ("ask", "unconfinable")


def test_an_alert_still_escalates_a_write_allow(pol):
    d = ev(pol, "write_file", w("/p/a.md"), alerts_present=True)
    assert (d.verdict, d.reason) == ("ask", "alert")


def test_a_call_with_a_second_path_slot_outside_the_write_confine_is_asked_as_unconfined(pol):
    d = ev(pol, "write_file", {**w("/p/a.md"), "destination": "/p/b"})
    assert d.verdict == "ask"


# --------------------------------------------------------------------------- the replay numbers


def _count(pol, **kw):
    props = C._read_traces(TRACES)
    got = {"ok": 0, "violation": 0, "denied_seed": 0}
    for p in props:
        d = pol.evaluate_call(p.get("server") or "", p.get("tool"), p.get("args"), confinable=True, **kw)
        if d.verdict == "allow" and p.get("label") in got:
            got[p["label"]] += 1
    return got


def test_v3_replay_without_a_write_vouched_for_by_the_proxy_is_unchanged_115_of_376_and_nothing_violating(pol):
    """The replay cannot know a file exists, so by default (as the hub treats an old proxy) no write is allowed: 115 benign allowed, 0 of the 127
    violating (violation + denied_seed)."""
    assert _count(pol) == {"ok": 115, "violation": 0, "denied_seed": 0}
    assert _count(pol, write_confinable=False) == {"ok": 115, "violation": 0, "denied_seed": 0}


def test_v3_replay_ceiling_if_every_doc_file_existed_pins_what_the_rules_alone_would_allow(pol):
    """PINNED CEILING, not a promise: if every file the synthetic traces write existed and the proxy vouched for it, the extension rule alone would
    allow 66 more benign writes AND 10 of the 67 violation-labelled ones (data staged into a shared .txt/.md: the kernel bounds WHICH file, never what
    the text means). A drift monitor alert still turns an allow into a card; the replay has no monitor. DECISIONS D32, docs/card_noise.md."""
    c = _count(pol, write_confinable=True)
    assert c == {"ok": 181, "violation": 10, "denied_seed": 0}


def test_the_replay_through_the_policy_cli_is_unchanged_and_has_a_ceiling_option():
    props = C._read_traces(TRACES)
    assert C.run_replay(P.load_policy(STARTER), props)["violating_allowed"] == 0
    assert C.run_replay(P.load_policy(STARTER), props, write_confinable=True)["violating_allowed"] == 10


@pytest.mark.parametrize("path", ["/p/requirements.txt", "/p/constraints.txt", "/p/CMakeLists.txt", "/p/SKILL.md", "/p/AGENT.md", "/p/conventions.md",
                                  "/p/.windsurf/x.md", "/p/.clinerules/x.md", "/p/.roo/x.md", "/p/.continue/x.md", "/p/.aider.conf.md"])
def test_files_a_package_manager_a_build_or_an_agent_obeys_ask_even_for_an_overwrite_the_proxy_vouched_for(pol, path):
    for tool, args in (("write_file", w(path)), ("edit_file", e(path))):
        d = ev(pol, tool, args, confinable=True, write_confinable=True)
        assert d.verdict == "ask" and d.rule_id == "ask-sensitive-write-path", (path, tool, d)


def test_an_ordinary_notes_file_is_still_allowed_next_to_those(pol):
    assert ev(pol, "write_file", w("/p/docs/notes.md")).verdict == "allow"
    assert ev(pol, "write_file", w("/p/docs/readme.txt")).verdict == "allow"
