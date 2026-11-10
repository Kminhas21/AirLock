"""The built-in starter policy (server/policies/starter.json), selected with SENTINEL_POLICY=builtin:starter."""
import json
import os
import stat
import subprocess
import sys

import pytest

import inbox_hub
import policy as P
import policy_cli as C
import proposal_monitor
from proposal_monitor import SessionMonitor
from test_inbox_hub import FakeMonitor, Rig, call, wait_for

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SERVER_DIR = os.path.join(ROOT, "server")
STARTER = os.path.join(SERVER_DIR, "policies", "starter.json")
TRACES = os.path.join(ROOT, "eval", "final_v3", "traces.json")

READ_PATH_TOOLS = ["read_file", "read_text_file", "list_directory", "list_directory_with_sizes", "directory_tree",
                   "search_files", "get_file_info"]
NO_PATH_TOOLS = ["list_allowed_directories", "read_graph", "search_nodes", "open_nodes", "get_current_time", "convert_time"]
SENSITIVE = [".ssh", ".aws", ".gnupg", ".env", "id_rsa", "id_ed25519", "credentials", "secrets", ".netrc", "/etc/shadow",
             "/etc/passwd", ".kube", ".git/config"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SENTINEL_POLICY", "SENTINEL_POLICY_WRITABLE", "SENTINEL_REGISTRY"):
        monkeypatch.delenv(k, raising=False)
    P._reset_policy_cache()
    inbox_hub._logged_policy_problems.clear()
    proposal_monitor._reset_errors()
    yield
    P._reset_policy_cache()
    proposal_monitor._reset_errors()


@pytest.fixture(scope="module")
def pol():
    return P.load_policy(STARTER)


def ev(pol, tool, args, **kw):
    return pol.evaluate("fs", tool, args, **kw)


def test_starter_lints_clean():
    assert C.main(["lint", STARTER]) == 0
    p = P.load_policy(STARTER)
    assert p.lint() == [] and p.default == "ask"
    assert not any(r.verdict == "deny" for r in p.rules)


@pytest.mark.parametrize("tool", READ_PATH_TOOLS)
def test_reads_of_a_normal_path_are_allowed_with_a_rule_id(pol, tool):
    d = ev(pol, tool, {"path": "/project/src/main.py"})
    assert d.verdict == "allow" and d.rule_id


@pytest.mark.parametrize("tool", NO_PATH_TOOLS)
def test_pathless_read_tools_are_allowed(pol, tool):
    d = ev(pol, tool, {"query": "x"})
    assert d.verdict == "allow" and d.rule_id


def test_read_multiple_files_allowed_when_all_normal(pol):
    assert ev(pol, "read_multiple_files", {"paths": ["/p/a", "/p/b"]}).verdict == "allow"


def spellings(s):
    return [s, s.upper(), s.title(), s.swapcase()]


@pytest.mark.parametrize("tool", READ_PATH_TOOLS)
@pytest.mark.parametrize("sens", SENSITIVE)
def test_sensitive_paths_are_asked_in_any_case(pol, tool, sens):
    for sp in spellings(sens):
        for path in (f"/home/u/{sp}", f"/home/u/{sp}/x", f"/home/u/dir/{sp}/id_x", f"{sp}"):
            d = ev(pol, tool, {"path": path})
            assert d.verdict == "ask", (tool, path, d)


def test_nested_ssh_key_asked(pol):
    d = ev(pol, "read_file", {"path": "/home/u/.ssh/id_rsa"})
    assert d.verdict == "ask" and d.rule_id and d.reason.startswith("rule:")


@pytest.mark.parametrize("sens", SENSITIVE)
def test_read_multiple_files_with_one_sensitive_path_is_asked(pol, sens):
    for i in range(8):
        paths = [f"/p/ok{n}" for n in range(8)]
        paths[i] = f"/home/u/{sens}"
        assert ev(pol, "read_multiple_files", {"paths": paths}).verdict == "ask", (i, sens)


def test_read_multiple_files_with_too_many_paths_is_asked(pol):
    assert ev(pol, "read_multiple_files", {"paths": [f"/p/{n}" for n in range(200)]}).verdict == "ask"


@pytest.mark.parametrize("arg", ["path", "source", "destination", "directory", "file"])
def test_every_path_like_arg_name_is_covered(pol, arg):
    args = {"path": "/p/ok", arg: "/home/u/.aws/credentials"}
    assert ev(pol, "read_file", args).verdict == "ask"


def test_odd_path_types_are_not_allowed(pol):
    assert ev(pol, "read_file", {"path": ["/home/u/.ssh/id_rsa"]}).verdict == "ask"
    assert ev(pol, "read_file", {"path": 5}).verdict == "ask"
    assert ev(pol, "read_file", {}).verdict == "ask"


@pytest.mark.parametrize("tool", ["write_file", "edit_file", "move_file", "create_directory", "delete_file", "send_email",
                                  "post_to_webhook", "run_shell_command", "query_database"])
def test_everything_else_is_asked(pol, tool):
    d = ev(pol, tool, {"path": "/project/x", "content": "c"})
    assert d.verdict == "ask"


def test_an_alert_turns_a_read_into_ask(pol):
    d = ev(pol, "read_file", {"path": "/p/a"}, alerts_present=True)
    assert d.verdict == "ask" and d.escalated


@pytest.mark.parametrize("tool", ["READ_FILE", "Read_File", "read_file\n", "read_file\x00", "read‮_file", "read_file​",
                                  "\nread_file", "read_file ", "read_filex"])
def test_tool_name_tricks_never_get_an_allow(pol, tool):
    assert ev(pol, tool, {"path": "/p/a"}).verdict != "allow"


def test_the_starter_has_no_secrets_and_allows_nothing_with_credentials(pol):
    assert ev(pol, "read_file", {"path": "/p/a"}, secrets_used=True).verdict == "ask"


# ----------------------------------------------------------------------------------------------------------------- selection

def test_resolver_maps_builtin_names_and_passes_paths_through():
    assert os.path.samefile(P.resolve_policy_path("builtin:starter"), STARTER)
    assert P.resolve_policy_path("/x/y.json") == "/x/y.json"
    assert P.resolve_policy_path("builtin:nope") is None
    assert P.resolve_policy_path("builtin:../starter") is None
    assert P.resolve_policy_path("builtin:") is None
    assert P.is_builtin("builtin:starter") and P.is_builtin("builtin:nope") and not P.is_builtin("/x")


def test_load_policy_file_understands_builtin():
    pol, why = P.load_policy_file("builtin:starter")
    assert pol is not None and why == ""
    pol, why = P.load_policy_file("builtin:nope")
    assert pol is None and "nope" in why and "starter" in why


async def test_unknown_builtin_holds_everything_and_logs(monkeypatch, caplog):
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:nope")
    mode, pol, _ = inbox_hub._resolve_policy()
    assert mode is True and pol is None
    assert "builtin:nope" in caplog.text or "nope" in caplog.text
    r = await Rig().start()
    await r.send(call(tool="read_file"))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []


def test_health_says_unknown_builtin_is_unusable(monkeypatch):
    from fastapi.testclient import TestClient
    import main
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:nope")
    h = TestClient(main.app).get("/health").json()
    assert h["policy"]["usable"] is False and h["policy"]["rules"] == 0
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:starter")
    h = TestClient(main.app).get("/health").json()
    assert h["policy"]["usable"] is True and h["policy"]["rules"] > 0


def test_builtin_policy_is_never_writable(monkeypatch, caplog):
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:starter")
    monkeypatch.setenv("SENTINEL_POLICY_WRITABLE", "1")
    hub = inbox_hub.InboxHub(monitor_factory=lambda: FakeMonitor())
    assert hub._capabilities()["policy_writable"] is False
    assert hub._writable_policy() is None
    assert "builtin" in caplog.text and "read-only" in caplog.text


# ------------------------------------------------------------------------------------------------------------------- hub

async def test_hub_auto_allows_a_read_with_a_working_monitor_and_holds_a_write(monkeypatch):
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:starter")
    r = await Rig().start()
    await r.send(call("c1", tool="list_directory", args={"path": "/project"}))
    await wait_for(lambda: r.decisions())
    assert r.decisions()[0]["decision"] == "approve" and r.decisions()[0]["reason"] == "policy"
    assert not r.ui.events("inbox_pending")
    res = r.ui.events("inbox_resolved")[0]
    assert res["rule_id"]
    await r.send(call("c2", tool="write_file", args={"path": "/project/a", "content": "x"}))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    p = r.ui.events("inbox_pending")[0]
    assert p["call_id"] == "c2" and len(r.decisions()) == 1


async def test_hub_holds_a_sensitive_read_with_its_rule(monkeypatch):
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:starter")
    r = await Rig().start()
    await r.send(call("c1", tool="read_file", args={"path": "/home/u/.ssh/id_rsa"}))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.ui.events("inbox_pending")[0]["rule_id"]
    assert r.decisions() == []


async def test_hub_holds_a_read_when_the_monitor_is_degraded(monkeypatch):
    monkeypatch.setenv("SENTINEL_POLICY", "builtin:starter")
    r = await Rig(SessionMonitor("rules")).start()
    await r.send(call("c1", tool="list_directory", args={"path": "/project"}))
    await wait_for(lambda: r.ui.events("inbox_pending"))
    assert r.decisions() == []


# ------------------------------------------------------------------------------------------------------------------- CLI

def run(*argv):
    env = dict(os.environ, PYTHONPATH=SERVER_DIR)
    return subprocess.run([sys.executable, "-m", "policy_cli", *argv], capture_output=True, text=True, env=env, cwd=SERVER_DIR)


def test_init_copies_the_starter_exactly(tmp_path):
    out = tmp_path / "mine.json"
    r = run("init", str(out), "--starter")
    assert r.returncode == 0, r.stderr
    assert out.read_bytes() == open(STARTER, "rb").read()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert C.main(["lint", str(out)]) == 0
    assert P.load_policy_file(str(out))[0] is not None


def test_init_without_the_flag_also_writes_the_starter(tmp_path):
    out = tmp_path / "p.json"
    assert run("init", str(out)).returncode == 0
    assert out.read_bytes() == open(STARTER, "rb").read()


def test_init_refuses_to_overwrite_unless_forced(tmp_path):
    out = tmp_path / "mine.json"
    out.write_text("keep me")
    r = run("init", str(out), "--starter")
    assert r.returncode == 2 and "exists" in r.stderr and "--force" in r.stderr
    assert out.read_text() == "keep me"
    assert run("init", str(out), "--starter", "--force").returncode == 0
    assert out.read_bytes() == open(STARTER, "rb").read()


def test_init_missing_directory_is_an_error_not_a_traceback(tmp_path):
    r = run("init", str(tmp_path / "no" / "such" / "p.json"))
    assert r.returncode == 2 and "Traceback" not in r.stderr


def test_copy_can_be_replayed_over_traces_through_the_cli(tmp_path):
    r = run("test", "builtin:starter", "--traces", TRACES, "--json")
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["violating_allowed"] == 0


def test_a_tenant_may_name_the_builtin_policy():
    import identity
    errs: list = []
    identity._check_tenant("acme", {"policy_file": "builtin:starter"}, errs)
    assert errs == []
    identity._check_tenant("acme", {"policy_file": "starter.json"}, errs)
    assert errs


# ------------------------------------------------------------------------------------------------------- icontains_any op

def _ic(values, args, path="p", verdict="ask"):
    p = P.Policy({"version": 1, "default": "allow", "rules": [
        {"id": "r", "verdict": verdict, "when": {"args": [{"path": path, "op": "icontains_any", "value": values}]}}]})
    return p.evaluate("s", "t", args).verdict == verdict


def test_icontains_any_string_is_case_insensitive():
    assert _ic([".ssh"], {"p": "/home/u/.SSH/id"})
    assert _ic([".SSH"], {"p": "/home/u/.ssh/id"})
    assert _ic(["x", ".ssh"], {"p": "/a/.Ssh"})
    assert not _ic([".ssh"], {"p": "/home/u/ssh"})


def test_icontains_any_list_any_element():
    assert _ic([".ssh"], {"p": ["/a", "/b/.SSH/k", "/c"]})
    assert not _ic([".ssh"], {"p": ["/a", "/b"]})
    assert not _ic([".ssh"], {"p": []})
    assert not _ic([".ssh"], {"p": ["/a", "/b/ok"]})


def test_icontains_any_top_level_dict_or_scalar_is_false_but_odd_list_entries_match():
    assert not _ic([".ssh"], {"p": {"k": "/x/.ssh"}})
    for odd in ([["/x/.ssh"]], [{"path": "/.ssh/x"}], [5], [None], [True], ["/ok", 1.5], ["/ok", ["/ok"]]):
        assert _ic([".ssh"], {"p": odd}), odd              # fail closed: an entry that cannot be examined counts as a match
    assert _ic([".ssh"], {"p": [5, "/x/.ssh"]})


def test_icontains_any_dotted_path_and_missing_or_odd_args_are_false():
    assert _ic([".ssh"], {"a": {"b": "/.SSH"}}, path="a.b")
    assert not _ic([".ssh"], {})
    for odd in (5, None, True, 1.5):
        assert not _ic([".ssh"], {"p": odd})


def test_icontains_any_casefold_sanity():
    assert _ic(["strasse"], {"p": "/a/STRAßE"})          # casefold: ß -> ss
    assert _ic(["I"], {"p": "i"})
    assert _ic(["é"], {"p": "É"})


def test_icontains_any_value_must_be_a_non_empty_list_of_non_empty_strings():
    for bad in ([], "x", [""], [5], [None], ["a", ""], ["x" * 1001], ["a\x00"], list("a" * 65)):
        with pytest.raises(P.PolicyError):
            P.Policy({"version": 1, "rules": [{"id": "r", "verdict": "ask",
                                               "when": {"args": [{"path": "p", "op": "icontains_any", "value": bad}]}}]})
    with pytest.raises(P.PolicyError):
        P.Policy({"version": 1, "rules": [{"id": "r", "verdict": "ask", "when": {"args": [{"path": "p", "op": "icontains_any"}]}}]})


def test_icontains_any_too_big_to_examine_counts_as_a_match():
    """fail closed for the ask rules it is meant for: a padded path or a long list cannot hide a sensitive element"""
    assert _ic([".ssh"], {"p": "a" * 5000 + ".ssh"})
    assert _ic([".ssh"], {"p": "a" * 30000})
    assert _ic([".ssh"], {"p": ["ok"] * 65})
    assert not _ic([".ssh"], {"p": ["ok"] * 64})
    assert not _ic([".ssh"], {"p": "a" * 4096})


def test_icontains_any_lint_warns_when_used_in_an_allow_rule():
    p = P.Policy({"version": 1, "rules": [{"id": "a", "verdict": "allow", "when": {"args": [{"path": "p", "op": "icontains_any", "value": ["x"]}]}}]})
    assert any("icontains_any" in w for w in p.lint())


def test_icontains_any_is_listed_and_explain_prints_it(tmp_path, capsys):
    assert "icontains_any" in P.OPS and "icontains_any" not in P.NEGATIVE_OPS
    assert C.main(["explain", STARTER, "--tool", "read_file", "--args", '{"path": "/h/.SSH/k"}']) == 0
    out = capsys.readouterr().out
    assert "verdict: ask" in out and "sensitive" in out


def test_starter_is_small_and_hand_editable():
    assert os.path.getsize(STARTER) < 4096
    assert len(P.load_policy(STARTER).rules) <= 12


# ---------------------------------------------------------------------------------------------------- path spelling variants

VARIANTS = [("/p/.git/./config", ".git/config"), ("/p/.git//config", ".git/config"), (".git\\config", ".git/config"),
            ("/p/.git\\config", ".git/config"), ("/etc//passwd", "/etc/passwd"), ("//etc///passwd", "/etc/passwd"),
            ("/etc/./shadow", "/etc/shadow"), ("\\etc\\shadow", "/etc/shadow"), ("/etc/./passwd", "/etc/passwd"),
            ("./etc/passwd", "/etc/passwd"), ("/etc/././/./shadow", "/etc/shadow"), ("/ETC/./Passwd", "/etc/passwd"),
            ("/etc/x/../passwd", "/etc/passwd"), ("/p/.git/././/config", ".git/config")]


@pytest.mark.parametrize("path,needle", VARIANTS)
def test_icontains_any_sees_through_path_spelling_variants(path, needle):
    assert _ic([needle], {"p": path})
    assert _ic([needle], {"p": ["/ok", path]})


def test_icontains_any_normal_paths_still_do_not_match():
    for ok in ("/p/.gitignore", "/p/git/config", "/etc/hosts", "/etc/pass", "/p/a/./b//c", "\\p\\a"):
        assert not _ic([".git/config", "/etc/passwd", "/etc/shadow"], {"p": ok}), ok


@pytest.mark.parametrize("path", ["/p/.git/./config", "/p/.git//config", "/etc//passwd", "/etc/./shadow", "\\etc\\shadow",
                                  ".git\\config", "//etc///passwd"])
def test_starter_asks_for_spelling_variants_in_every_slot(pol, path):
    assert ev(pol, "read_file", {"path": path}).verdict == "ask"
    assert ev(pol, "read_multiple_files", {"paths": ["/ok", path]}).verdict == "ask"
    assert ev(pol, "list_directory", {"directory": path, "path": "/ok"}).verdict == "ask"


NEW_FAMILIES = ["/home/u/.ssh/id_ecdsa", "/h/id_dsa", "/h/.pgpass", "/h/.npmrc", "/h/.docker/config.json", "/h/server.pem", "/h/a.P12",
                "/h/a.pfx", "/proc/self/environ", "/etc/sudoers", "/etc/sudoers.d/x", "/h/.bash_history", "/h/.git-credentials"]


@pytest.mark.parametrize("path", NEW_FAMILIES)
def test_starter_asks_for_the_extended_sensitive_families(pol, path):
    assert ev(pol, "read_file", {"path": path}).verdict == "ask"
    assert ev(pol, "read_multiple_files", {"paths": ["/ok", path]}).verdict == "ask"


def test_starter_odd_list_entries_are_asked(pol):
    for paths in ([["/.ssh/x"]], [{"path": "/.ssh/x"}], [5], ["/ok", None]):
        assert ev(pol, "read_multiple_files", {"paths": paths}).verdict == "ask", paths
