"""
Risk level mapping for SENTINEL tools.

Each tool is categorized by how dangerous it is. The frontend uses this
to color-code kill chain nodes:
    low      -> green   (read-only, no side effects)
    medium   -> amber   (data mutation, contained)
    high     -> red     (file writes/deletes)
    critical -> bright red (external comms, arbitrary execution)

Also maps tools to resource categories for circumvention detection.
When a tool is denied, the Seismograph checks if subsequent tool calls
target the same resource category — if so, it's likely circumvention.
"""

RISK_MAP: dict[str, str] = {
    # Low risk — read-only exploration
    "read_file":         "low",
    "list_directory":    "low",
    "search_files":      "low",

    # Medium risk — data queries and mutations
    "query_database":    "medium",
    "update_task":       "medium",
    "create_task":       "medium",
    "create_github_issue": "medium",

    # High risk — file system writes/deletes
    "write_file":        "high",
    "delete_file":       "high",

    # Critical risk — external communication or arbitrary execution
    "send_email":        "critical",
    "send_slack_message": "critical",
    "post_to_webhook":   "critical",
    "run_shell_command": "critical",
}

# Resource categories — used by the Seismograph for circumvention detection.
# If send_email is denied and the agent then calls send_slack_message,
# both map to "communication" -> circumvention detected.
RESOURCE_MAP: dict[str, str] = {
    "send_email":         "communication",
    "send_slack_message": "communication",
    "post_to_webhook":    "communication",
    "create_github_issue": "communication",

    "read_file":          "filesystem",
    "write_file":         "filesystem",
    "delete_file":        "filesystem",
    "list_directory":     "filesystem",
    "search_files":       "filesystem",

    "query_database":     "data",
    "update_task":        "data",
    "create_task":        "data",

    "run_shell_command":  "execution",
}

# Keywords associated with each tool — used by the Seismograph to detect
# if the agent's reasoning text mentions denied-tool concepts
TOOL_KEYWORDS: dict[str, list[str]] = {
    "send_email":         ["email", "send", "message", "notify", "contact", "mail", "recipient"],
    "send_slack_message": ["slack", "message", "notify", "channel", "ping", "dm"],
    "post_to_webhook":    ["webhook", "post", "http", "notify", "alert", "external"],
    "write_file":         ["write", "file", "save", "create", "output", "report"],
    "delete_file":        ["delete", "remove", "clean", "purge"],
    "run_shell_command":  ["shell", "command", "run", "execute", "bash", "terminal"],
    "create_github_issue": ["issue", "github", "ticket", "bug", "track"],
    "query_database":     ["query", "database", "lookup", "search", "find", "data"],
    "update_task":        ["update", "modify", "change", "task", "status"],
    "create_task":        ["create", "new", "add", "task"],
}


def get_risk_level(tool_name: str) -> str:
    """Get the risk level for a tool. Returns 'medium' for unknown tools."""
    return RISK_MAP.get(tool_name, "medium")


def get_resource_category(tool_name: str) -> str | None:
    """Get the resource category for circumvention detection."""
    return RESOURCE_MAP.get(tool_name)


def get_tool_keywords(tool_name: str) -> list[str]:
    """Get keywords associated with a tool for goal persistence tracking."""
    return TOOL_KEYWORDS.get(tool_name, [])
