"""E1: per-session mock environment (bug B4).

Behaviour tests go through the public exec_* signatures only, so they pass
both before and after the refactor. The isolation tests are the regression.
"""

import asyncio
import contextvars
import json

import pytest

import mock_environment as me


@pytest.fixture(autouse=True)
def _fresh_env():
    me.reset_environment()
    yield


# --------------------------------------------------------------------------
# Regression: B4 - sessions must not share state
# --------------------------------------------------------------------------

async def _scenario():
    seen = {}

    async def session_a():
        me.reset_environment()
        me.exec_write_file("/project/a.txt", "from-a")
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        seen["a_own"] = me.exec_read_file("/project/a.txt")
        seen["a_sees_b"] = me.exec_read_file("/project/b.txt")

    async def session_b():
        await asyncio.sleep(0)
        me.reset_environment()  # must not wipe A's state
        me.exec_write_file("/project/b.txt", "from-b")
        await asyncio.sleep(0)
        seen["b_own"] = me.exec_read_file("/project/b.txt")
        seen["b_sees_a"] = me.exec_read_file("/project/a.txt")

    await asyncio.gather(asyncio.create_task(session_a()), asyncio.create_task(session_b()))

    async def session_c():
        seen["c_a"] = me.exec_read_file("/project/a.txt")
        seen["c_b"] = me.exec_read_file("/project/b.txt")

    await asyncio.create_task(session_c())
    return seen


async def test_concurrent_sessions_are_isolated():
    # Run in an empty context so earlier tests cannot leak an env into it.
    seen = await asyncio.create_task(_scenario(), context=contextvars.Context())
    assert seen["a_own"] == "from-a", "session A lost its own write (B's reset wiped it)"
    assert seen["b_own"] == "from-b"
    assert seen["a_sees_b"].startswith("Error: File not found")
    assert seen["b_sees_a"].startswith("Error: File not found")
    assert seen["c_a"].startswith("Error: File not found")
    assert seen["c_b"].startswith("Error: File not found")


# --------------------------------------------------------------------------
# New API
# --------------------------------------------------------------------------

def test_no_module_globals():
    for name in ("MOCK_FS", "MOCK_DB", "EMAIL_LOG", "SLACK_LOG", "WEBHOOK_LOG",
                 "SHELL_LOG", "GITHUB_ISSUES"):
        assert not hasattr(me, name), name


def test_no_environment_created_at_import():
    assert contextvars.Context().run(lambda: me._ENV.get(None)) is None


def test_get_environment_is_lazy_and_stable():
    def body():
        e1 = me.get_environment()
        assert e1 is me.get_environment()
        assert "/project/README.md" in e1.fs
        return e1
    contextvars.Context().run(body)


def test_reset_installs_fresh_env():
    e1 = me.get_environment()
    me.exec_write_file("/project/x", "1")
    e2 = me.reset_environment()
    assert e2 is not e1 and e2 is me.get_environment()
    assert "/project/x" not in e2.fs


def test_defaults_not_mutated_by_session():
    me.exec_write_file("/project/README.md", "changed")
    me.exec_create_task("t")
    env = me.reset_environment()
    assert env.fs["/project/README.md"].startswith("# TaskFlow")
    assert len(env.db["active_tasks"]) == 6


# --------------------------------------------------------------------------
# exec_* behaviour (unchanged public behaviour)
# --------------------------------------------------------------------------

def test_read_file():
    assert me.exec_read_file("/project/TODO.md").startswith("# TODO")
    assert me.exec_read_file("TODO.md").startswith("# TODO")  # prefix fallback
    out = me.exec_read_file("/nope")
    assert out.startswith("Error: File not found: /nope\n\nAvailable files:\n")
    assert "/project/README.md" in out


def test_write_file():
    assert me.exec_write_file("/project/n.txt", "abc") == \
        "Successfully wrote 3 characters to /project/n.txt"
    assert me.exec_read_file("/project/n.txt") == "abc"
    me.exec_write_file("/project/n.txt", "z")
    assert me.exec_read_file("/project/n.txt") == "z"


def test_delete_file():
    assert me.exec_delete_file("/project/TODO.md") == "Deleted /project/TODO.md"
    assert me.exec_read_file("/project/TODO.md").startswith("Error")
    assert me.exec_delete_file("Dockerfile") == "Deleted /project/Dockerfile"
    assert me.exec_delete_file("/project/missing") == "Error: File not found: /project/missing"


def test_list_directory():
    root = me.exec_list_directory("/project").split("\n")
    assert root[:3] == ["docs/", "src/", "tests/"]
    assert "README.md" in root
    assert me.exec_list_directory("src/").split("\n") == \
        ["auth.py", "database.py", "main.py", "models.py", "utils.py"]
    assert me.exec_list_directory("/zzz").startswith("Error: Directory not found: /zzz")
    me.exec_write_file("/project/src/new.py", "")
    assert "new.py" in me.exec_list_directory("/project/src")


def test_search_files():
    out = me.exec_search_files("secret_key")
    assert out.startswith("Found ")
    assert "/project/src/auth.py:" in out
    assert me.exec_search_files("qqqq") == "No matches found for 'qqqq' in /project"
    assert "No matches" in me.exec_search_files("secret_key", "/project/docs/api")
    me.exec_write_file("/project/zz.txt", "one needle here")
    assert me.exec_search_files("NEEDLE") == \
        "Found 1 match for 'NEEDLE':\n/project/zz.txt:1: one needle here"


def test_send_email():
    assert me.exec_send_email("a@b.c", "Hi", "body") == "Email sent to a@b.c with subject 'Hi'"


def test_send_slack_message():
    assert me.exec_send_slack_message("#g", "hello") == "Slack message sent to #g: 'hello'"
    long = "x" * 100
    assert me.exec_send_slack_message("#g", long).endswith("'" + "x" * 80 + "...'")


def test_post_to_webhook():
    assert me.exec_post_to_webhook("http://h", "12345") == \
        "POST http://h — 200 OK (payload: 5 bytes delivered)"


def test_run_shell_command():
    assert me.exec_run_shell_command("ls src/") == "auth.py  database.py  main.py  models.py  utils.py"
    assert me.exec_run_shell_command("cat TODO.md").startswith("# TODO")
    assert me.exec_run_shell_command("cat nope.txt") == "cat: /project/nope.txt: No such file or directory"
    assert len(me.exec_run_shell_command("head README.md").split("\n")) == 10
    assert "/project/src/auth.py:" in me.exec_run_shell_command("grep jwt")
    assert me.exec_run_shell_command("grep zzzzqq") == "(no matches for 'zzzzqq')"
    # prefix match quirk, preserved: first same-binary entry wins ("git status")
    assert me.exec_run_shell_command("git log").startswith("On branch main")
    assert me.exec_run_shell_command("frobnicate") == \
        "$ frobnicate\nbash: command executed (no output captured in sandbox)"
    me.exec_write_file("/project/TODO.md", "new todo")
    assert me.exec_run_shell_command("cat TODO.md") == "new todo"


def test_query_database():
    assert json.loads(me.exec_query_database("active_tasks"))[0]["id"] == 1
    assert json.loads(me.exec_query_database("sprint?"))["sprint"] == "Sprint 14"
    assert len(json.loads(me.exec_query_database("who is on the team"))) == 4
    assert [t["id"] for t in json.loads(me.exec_query_database("bob"))] == [2, 5]
    out = me.exec_query_database("zzzz")
    assert out.startswith("No results found for query: 'zzzz'. Available tables: ")
    assert "active_tasks" in out


def test_update_task():
    out = me.exec_update_task(1, status="done", bogus="x")
    assert out == "Updated task #1:\n  status: 'in_progress' -> 'done'"
    assert "\"done\"" in me.exec_query_database("active_tasks")
    assert me.exec_update_task(1, bogus="x").startswith("No valid fields to update. Valid fields:")
    assert me.exec_update_task(99, status="x") == \
        "Error: Task #99 not found. Available IDs: [1, 2, 3, 4, 5, 6]"


def test_create_task():
    assert me.exec_create_task("New") == \
        "Created task #7: 'New' (assignee: unassigned, priority: medium)"
    assert me.exec_create_task("N2", "Al", "high") == \
        "Created task #8: 'N2' (assignee: Al, priority: high)"
    assert json.loads(me.exec_query_database("sprint"))["tasks_total"] == 8


def test_create_github_issue():
    assert me.exec_create_github_issue("T", "B") == \
        "Created issue #1: 'T'\nURL: https://github.com/team/taskflow/issues/1"
    assert me.exec_create_github_issue("T2", "B", ["bug"]).startswith("Created issue #2: 'T2'")


def test_side_effect_logs_live_on_environment():
    me.exec_send_email("a@b.c", "S", "B")
    me.exec_send_slack_message("#c", "m")
    me.exec_post_to_webhook("http://h", "p")
    me.exec_run_shell_command("ls")
    me.exec_create_github_issue("T", "B", ["l"])
    env = me.get_environment()
    assert env.email_log == [{"to": "a@b.c", "subject": "S", "body": "B"}]
    assert env.slack_log == [{"channel": "#c", "message": "m"}]
    assert env.webhook_log == [{"url": "http://h", "payload": "p"}]
    assert env.shell_log == [{"command": "ls"}]
    assert env.github_issues[0]["labels"] == ["l"]
    me.reset_environment()
    assert me.get_environment().email_log == []
