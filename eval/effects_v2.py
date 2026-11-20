"""Decomposition of a proposed call into (verb, payload, destination) for the v2 detectors.

Reuses the conventions (and private helpers) of ``eval.effects`` without changing its behaviour: the verb is
exactly the first word of ``describe_effect`` for the same call; payload is the gist of what would be sent /
written / run (``_gist``, ~120 chars, file names kept); destination is where it goes: e-mail address,
channel, URL host+path (the path is kept because relay URLs are internal-looking and the path carries the
clue), file path, external host of a shell command, assignee of a task, issue repo.
All 13 tools are covered; unknown tools give ("Run", "<k=v ...>", "").
"""
from __future__ import annotations

import posixpath
import re

from . import effects as E


def _strip_scheme(url) -> str:
    u = E._s(url)
    u = re.sub(r"^[A-Za-z][A-Za-z0-9+.\-]*://", "", u)
    u = u.rsplit("@", 1)[-1] if "@" in u.split("/", 1)[0] else u
    return u.rstrip("/")


def _read_file(a):
    return "Read", "", E._s(a.get("path"))


def _write_file(a):
    p = E._s(a.get("path"))
    return ("Stage" if E.is_external_path(p) else "Write"), E._gist(a.get("content")), p


def _delete_file(a):
    return "Delete", "", E._s(a.get("path"))


def _list_directory(a):
    return "List", "", E._s(a.get("path"))


def _search_files(a):
    return "Search", E._gist(a.get("pattern")), E._s(a.get("path")) or E.PROJECT_ROOT


def _send_email(a):
    to = E._s(a.get("to"))
    return ("Disclose" if E.is_external_email(to) else "Send"), E._gist(a.get("body")) or E._gist(a.get("subject")), to


def _send_slack(a):
    ch = E._s(a.get("channel"))
    return ("Disclose" if E._is_external_channel(ch) else "Send"), E._gist(a.get("message")), ch


def _webhook(a):
    return ("Disclose" if E.is_external_host(a.get("url")) else "Send"), E._gist(a.get("payload")), _strip_scheme(a.get("url"))


def _query_db(a):
    return "Query", E._gist(a.get("query")), "internal database"


def _update_task(a):
    tid = E._s(a.get("task_id"))
    keys = ["status", "assignee", "title", "priority"] + [k for k in a if k not in ("status", "assignee", "title", "priority", "task_id")]
    ch = [f"{k}={E._gist(a[k], 60)}" for k in keys if k in a and E._s(a[k])]
    dest = f"task {tid}" + (f" assigned to {E._s(a.get('assignee'))}" if E._s(a.get("assignee")) else "")
    return "Update", ", ".join(ch), dest.strip()


def _create_task(a):
    who = E._s(a.get("assignee"))
    return "Create", E._gist(a.get("title")), (f"task assigned to {who}" if who else "internal task tracker")


def _shell(a):
    cmd = E._s(a.get("command"))
    toks = cmd.split()
    hosts = [re.sub(r":\d+$", "", h) for h in E._URL_HOST_RE.findall(cmd) + E._AT_HOST_RE.findall(cmd)]
    hosts = [h for h in hosts if not E._host_internal(h)]
    dest = hosts[0] if hosts else "local shell"
    if not hosts:
        net = [posixpath.basename(t) for t in toks if posixpath.basename(t) in E._NET_TOOLS]
        if net:
            dest = f"network via {net[0]}"
    return "Run", E._gist(cmd), dest


def _github_issue(a):
    title, body = E._gist(a.get("title"), 60), E._gist(a.get("body"))
    g = ": ".join(x for x in (title, body) if x)
    repo = " ".join(E._s(a.get(k)) for k in ("repo", "repository", "url", "owner")).strip()
    internal = bool(repo) and (E.TEAM_DOMAIN in repo.lower() or re.search(r"(^|[\s/])team(/|$)", repo.lower()) is not None)
    return "Publish", g, (f"{repo} " if repo else "") + ("internal issue tracker" if internal else "external issue tracker")


_PARTS = {
    "read_file": _read_file, "write_file": _write_file, "delete_file": _delete_file,
    "list_directory": _list_directory, "search_files": _search_files, "send_email": _send_email,
    "send_slack_message": _send_slack, "post_to_webhook": _webhook, "query_database": _query_db,
    "update_task": _update_task, "create_task": _create_task, "run_shell_command": _shell,
    "create_github_issue": _github_issue,
}


def describe_parts(tool: str, args: dict) -> tuple[str, str, str]:
    """(verb, payload, destination) of a proposed call; strings, never raises on odd args."""
    a = args if isinstance(args, dict) else {}
    fn = _PARTS.get(tool)
    if fn is not None:
        verb, payload, dest = fn(a)
        return verb, payload.strip(), dest.strip()
    return "Run", ", ".join(f"{k}={E._gist(repr(v), 60)}" for k, v in a.items()), ""
