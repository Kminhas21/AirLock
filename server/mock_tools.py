"""
Mock tools for the SENTINEL agent.

All data lives in Python dicts/lists in memory. Nothing touches real files,
real email, or real databases. This keeps the demo safe and repeatable.
"""

from langchain_core.tools import tool

# ---------------------------------------------------------------------------
# MOCK DATA — the "world" the agent interacts with
# ---------------------------------------------------------------------------

# Fake filesystem: path -> content
MOCK_FS = {
    "/project/README.md": "# Project Alpha\nA distributed task management system.",
    "/project/src/main.py": "import flask\napp = flask.Flask(__name__)\n# ... 200 lines of code",
    "/project/tests/test_main.py": "import pytest\ndef test_health(): assert True",
    "/project/config.json": '{"db_host": "localhost", "db_port": 5432, "debug": true}',
    "/project/docs/architecture.md": (
        "## Architecture\nMicroservice-based. "
        "3 services: API gateway, worker, scheduler."
    ),
}

# Fake database: table_name -> list of row dicts
MOCK_DB = {
    "active_tasks": [
        {"id": 1, "title": "Fix auth bug", "assignee": "Alice", "status": "in_progress"},
        {"id": 2, "title": "Deploy v2.1", "assignee": "Bob", "status": "blocked"},
        {"id": 3, "title": "Write API docs", "assignee": "Charlie", "status": "done"},
    ],
    "team_members": [
        {"name": "Alice", "email": "alice@team.com", "role": "backend"},
        {"name": "Bob", "email": "bob@team.com", "role": "devops"},
        {"name": "Charlie", "email": "charlie@team.com", "role": "docs"},
    ],
}

# Fake email outbox: each send_email call appends here
EMAIL_LOG: list[dict] = []


# ---------------------------------------------------------------------------
# TOOL FUNCTIONS — decorated with @tool so LangChain can use them
# ---------------------------------------------------------------------------

@tool
def read_file(path: str) -> str:
    """Read a file from the project filesystem. Returns the file content or an error if not found."""
    if path in MOCK_FS:
        return MOCK_FS[path]
    return f"Error: File not found: {path}"


@tool
def write_file(path: str, content: str) -> str:
    """Write content to a file in the project filesystem. Creates or overwrites the file."""
    MOCK_FS[path] = content
    return f"Successfully wrote {len(content)} characters to {path}"


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a team member. Use their email address (e.g. alice@team.com)."""
    entry = {"to": to, "subject": subject, "body": body}
    EMAIL_LOG.append(entry)
    return f"Email sent to {to} with subject '{subject}'"


@tool
def query_database(query: str) -> str:
    """Query the project database. Supported queries: 'active_tasks', 'team_members', or a keyword to search tasks."""
    # Direct table lookup
    if query in MOCK_DB:
        rows = MOCK_DB[query]
        return "\n".join(str(row) for row in rows)

    # Keyword search across tasks
    results = []
    for task in MOCK_DB.get("active_tasks", []):
        if query.lower() in str(task).lower():
            results.append(task)

    if results:
        return "\n".join(str(r) for r in results)
    return f"No results found for query: {query}"


# All tools in a list — used by agent.py to register them with LangChain
ALL_TOOLS = [read_file, write_file, send_email, query_database]
