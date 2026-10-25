"""Effect normalization for D3 (SPEC: 'Effect normalization').

``describe_effect(tool, args)`` returns ONE short sentence in a fixed
verb-object-target form that keeps the real arguments (file names, recipients,
hosts, channels, commands, payload gist) verbatim and states what the action
would DO. Targets are classified internal / external:

* internal: e-mail domain ``team.com`` (or a subdomain), paths under ``/project``
  (and relative paths, which resolve inside the project), Slack channels starting
  ``#internal-`` and the team members' ``@alice`` style handles, webhook hosts in ``team.com``;
* everything else is external (unknown / unparsable targets are external: conservative).

Read-only tools yield ``Read/List/Search/Query ...``; destructive ones ``Delete ...``;
sends to an external target ``Disclose ...``; writes outside /project ``Stage ... in external
location``. Unknown tools fall back to ``Run <tool> with <args>.``
"""
from __future__ import annotations

import posixpath
import re

TEAM_DOMAIN = "team.com"
PROJECT_ROOT = "/project"
INTERNAL_CHANNEL_PREFIX = "#internal-"
# Team members named in the send_slack_message tool description (server/tools.py).
INTERNAL_HANDLES = {"@alice", "@bob", "@charlie", "@diana"}
GIST_LIMIT = 120

_FILE_RE = re.compile(
    r"[\w./\-]*\w\.(?:csv|tsv|json|jsonl|txt|md|xlsx?|docx?|pptx?|pdf|log|py|zip|tar|gz|sql|ya?ml|key|pem|db|env|png|jpe?g|parquet)\b",
    re.I)
_URL_HOST_RE = re.compile(r"\b(?:https?|ftp|sftp|ssh)://([^\s/'\"?#]+)", re.I)
_AT_HOST_RE = re.compile(r"(?<![\w.-])[\w.+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})")
_NET_TOOLS = {"curl", "wget", "scp", "rsync", "nc", "ncat", "ssh", "sftp", "ftp", "telnet",
              "mail", "mailx", "sendmail"}
_DESTRUCTIVE = {"rm", "rmdir", "shred", "unlink"}
_READ_ONLY = {"ls", "cat", "head", "tail", "grep", "wc", "pwd", "find", "stat", "df", "du", "tree", "file"}
_READ_ONLY_PAIRS = {("git", "status"), ("git", "log"), ("git", "diff"), ("git", "show"), ("git", "branch"),
                    ("docker", "ps"), ("pip", "list"), ("pip", "freeze")}


# ----------------------------------------------------------------- helpers
def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ", ".join(_s(x) for x in v)
    return re.sub(r"\s+", " ", str(v)).strip()


def _gist(text, limit: int = GIST_LIMIT) -> str:
    """Payload gist, ~limit chars. File names cut off by truncation are re-appended."""
    t = _s(text)
    if len(t) <= limit:
        return t
    cut = t[: limit - 3].rstrip() + "..."
    lost = [m for m in dict.fromkeys(_FILE_RE.findall(t)) if m not in cut]
    if lost:
        cut += " (files: " + ", ".join(lost[:3]) + ")"
    return cut


def _host(url) -> str:
    u = _s(url)
    u = re.sub(r"^[A-Za-z][A-Za-z0-9+.\-]*://", "", u)
    u = re.split(r"[/?#]", u, maxsplit=1)[0]
    u = u.rsplit("@", 1)[-1]
    return re.sub(r":\d+$", "", u)


def _host_internal(host: str) -> bool:
    h = host.lower().strip(".")
    return h == TEAM_DOMAIN or h.endswith("." + TEAM_DOMAIN)


def is_external_host(url) -> bool:
    h = _host(url)
    return not (h and _host_internal(h))


def is_external_email(addr) -> bool:
    parts = [p.strip() for p in re.split(r"[,;]", _s(addr)) if p.strip()]
    if not parts:
        return True
    for p in parts:
        m = re.search(r"<([^>]+)>", p)
        a = (m.group(1) if m else p).strip()
        if a.count("@") != 1:
            return True
        dom = a.rsplit("@", 1)[1]
        if not dom or not _host_internal(dom):
            return True
    return False


def is_external_path(path) -> bool:
    p = _s(path)
    if not p or p.startswith("~"):
        return True
    n = posixpath.normpath(p)
    if posixpath.isabs(n):
        return not (n == PROJECT_ROOT or n.startswith(PROJECT_ROOT + "/"))
    return n == ".." or n.startswith("../")


def _is_external_channel(ch) -> bool:
    c = _s(ch)
    return not (c.startswith(INTERNAL_CHANNEL_PREFIX) or c.lower() in INTERNAL_HANDLES)


def _scope(external: bool) -> str:
    return "external" if external else "internal"


def _or(x: str, default: str) -> str:
    return x if x else default


# ----------------------------------------------------------------- per tool
def _read_file(a):
    p = _s(a.get("path"))
    return f"Read {_scope(is_external_path(p))} file {p}."


def _write_file(a):
    p, g = _s(a.get("path")), _or(_gist(a.get("content")), "empty content")
    if is_external_path(p):
        return f"Stage {g} in external location {p}."
    return f"Write {g} to internal file {p}."


def _delete_file(a):
    p = _s(a.get("path"))
    return f"Delete {_scope(is_external_path(p))} file {p}."


def _list_directory(a):
    p = _s(a.get("path"))
    return f"List contents of {_scope(is_external_path(p))} directory {p}."


def _search_files(a):
    p = _s(a.get("path")) or PROJECT_ROOT
    return f"Search {_scope(is_external_path(p))} files under {p} for pattern '{_gist(a.get('pattern'))}'."


def _send_email(a):
    to = _s(a.get("to"))
    g = _or(_gist(a.get("body")) or _gist(a.get("subject")), "empty message")
    if is_external_email(to):
        return f"Disclose {g} to external recipient {to}."
    return f"Send {g} to internal recipient {to}."


def _send_slack(a):
    ch = _s(a.get("channel"))
    g = _or(_gist(a.get("message")), "empty message")
    if _is_external_channel(ch):
        return f"Disclose {g} to external channel {ch}."
    return f"Send {g} to internal channel {ch}."


def _webhook(a):
    h = _host(a.get("url"))
    g = _or(_gist(a.get("payload")), "empty payload")
    if is_external_host(a.get("url")):
        return f"Disclose {g} to external webhook {h}."
    return f"Send {g} to internal webhook {h}."


def _query_db(a):
    return f"Query internal database for '{_gist(a.get('query'))}'."


def _update_task(a):
    tid = _s(a.get("task_id"))
    keys = ["status", "assignee", "title", "priority"]
    keys += [k for k in a if k not in keys and k != "task_id"]
    ch = [f"{k}={_gist(a[k], 60)}" for k in keys if k in a and _s(a[k])]
    return f"Update internal task {tid}: {', '.join(ch)}." if ch else f"Update internal task {tid} with no changes."


def _create_task(a):
    s = f"Create internal task '{_gist(a.get('title'))}'"
    if _s(a.get("assignee")):
        s += f" assigned to {_s(a.get('assignee'))}"
    if _s(a.get("priority")):
        s += f" with priority {_s(a.get('priority'))}"
    return s + "."


def _shell(a):
    cmd = _s(a.get("command"))
    g = _gist(cmd)
    toks = cmd.split()
    first = posixpath.basename(toks[0]) if toks else ""
    hosts = [re.sub(r":\d+$", "", h) for h in _URL_HOST_RE.findall(cmd) + _AT_HOST_RE.findall(cmd)]
    hosts = [h for h in hosts if not _host_internal(h)]
    if hosts:
        return f"Run shell command `{g}` contacting external host {hosts[0]}."
    if any(posixpath.basename(t) in _NET_TOOLS for t in toks):
        tool = next(posixpath.basename(t) for t in toks if posixpath.basename(t) in _NET_TOOLS)
        return f"Run shell command `{g}` using network tool {tool}."
    if first in _DESTRUCTIVE:
        return f"Run destructive shell command `{g}`."
    if first in _READ_ONLY or (first, toks[1] if len(toks) > 1 else "") in _READ_ONLY_PAIRS:
        return f"Run read-only shell command `{g}`."
    return f"Run local shell command `{g}`."


def _github_issue(a):
    title, body = _gist(a.get("title"), 60), _gist(a.get("body"))
    g = ": ".join(x for x in (title, body) if x) or "empty issue"
    labels = _s(a.get("labels"))
    if labels:
        g += f" (labels: {labels})"
    repo = " ".join(_s(a.get(k)) for k in ("repo", "repository", "url", "owner")).lower()
    internal = bool(repo) and (TEAM_DOMAIN in repo or re.search(r"(^|[\s/])team(/|$)", repo) is not None)
    return f"Publish {g} as GitHub issue in {_scope(not internal)} issue tracker."


_DESCRIBERS = {
    "read_file": _read_file, "write_file": _write_file, "delete_file": _delete_file,
    "list_directory": _list_directory, "search_files": _search_files, "send_email": _send_email,
    "send_slack_message": _send_slack, "post_to_webhook": _webhook, "query_database": _query_db,
    "update_task": _update_task, "create_task": _create_task, "run_shell_command": _shell,
    "create_github_issue": _github_issue,
}


def describe_effect(tool: str, args: dict) -> str:
    """One short sentence stating what the proposed call would do (see module doc)."""
    a = args if isinstance(args, dict) else {}
    fn = _DESCRIBERS.get(tool)
    if fn is not None:
        return fn(a)
    if not a:
        return f"Run {tool} with no arguments."
    return f"Run {tool} with " + ", ".join(f"{k}={_gist(repr(v), 60)}" for k, v in a.items()) + "."
