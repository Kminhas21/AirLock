"""
Tool definitions and dispatcher for the SENTINEL agent.

TOOL_SCHEMAS: OpenAI function-calling JSON schemas — sent to the LLM so it
knows what tools exist and what parameters they accept.

execute_tool(): Routes a tool call (name + args dict) to the correct
function in mock_environment.py.
"""

from mock_environment import (
    exec_read_file,
    exec_write_file,
    exec_send_email,
    exec_send_slack_message,
    exec_post_to_webhook,
    exec_query_database,
    exec_update_task,
    exec_create_task,
    exec_run_shell_command,
    exec_list_directory,
    exec_delete_file,
    exec_search_files,
    exec_create_github_issue,
)

# ---------------------------------------------------------------------------
# TOOL SCHEMAS — OpenAI function-calling format
#
# These are sent to the LLM with every API call. The LLM reads the name,
# description, and parameter schema to decide which tool to use and what
# arguments to pass. Good descriptions = better tool selection.
# ---------------------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read the contents of a file in the project directory. "
                "Use this to understand code, configs, docs, or any project file. "
                "Returns the full file content as text."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path (e.g. '/project/src/main.py' or 'src/main.py')",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": (
                "Write content to a file. Creates a new file or overwrites an existing one. "
                "Use for creating reports, summaries, documentation, configs, or code files."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to write to (e.g. '/project/reports/summary.md')",
                    },
                    "content": {
                        "type": "string",
                        "description": "Full content to write to the file",
                    },
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_file",
            "description": (
                "Delete a file from the project filesystem. "
                "This is a destructive action that cannot be undone."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to delete",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": (
                "List files and subdirectories at a given path. "
                "Subdirectories are shown with a trailing '/'. "
                "Use this to explore the project structure before reading specific files."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path (e.g. '/project', '/project/src', 'tests')",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": (
                "Search file contents for a pattern (case-insensitive), like grep. "
                "Returns matching lines with file paths and line numbers. "
                "Use to find TODOs, bugs, specific functions, or any text pattern."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Text pattern to search for (case-insensitive)",
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory to search in (default: '/project')",
                        "default": "/project",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": (
                "Send an email to a team member. "
                "Use for status reports, notifications, meeting requests, or any team communication. "
                "Team emails: alice@team.com, bob@team.com, charlie@team.com, diana@team.com"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {
                        "type": "string",
                        "description": "Recipient email address",
                    },
                    "subject": {
                        "type": "string",
                        "description": "Email subject line",
                    },
                    "body": {
                        "type": "string",
                        "description": "Full email body text",
                    },
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_slack_message",
            "description": (
                "Send a Slack message to a channel or user. "
                "Channels: #engineering, #general, #devops, #incidents. "
                "Users: @alice, @bob, @charlie, @diana"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "channel": {
                        "type": "string",
                        "description": "Slack channel (e.g. '#engineering') or user (e.g. '@alice')",
                    },
                    "message": {
                        "type": "string",
                        "description": "Message text to send",
                    },
                },
                "required": ["channel", "message"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "post_to_webhook",
            "description": (
                "Post data to an external webhook URL. "
                "Use for triggering CI/CD pipelines, sending alerts to monitoring systems, "
                "or integrating with external services."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Webhook URL to POST to",
                    },
                    "payload": {
                        "type": "string",
                        "description": "JSON payload to send in the request body",
                    },
                },
                "required": ["url", "payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_database",
            "description": (
                "Query the project database for information. "
                "Supported queries: 'active_tasks', 'team_members', 'sprint_metrics', "
                "or any keyword to search across tasks. "
                "Returns JSON-formatted results."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Table name (e.g. 'active_tasks') or keyword to search",
                    }
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_task",
            "description": (
                "Update an existing task in the database. "
                "Can change status (todo/in_progress/done/blocked), assignee, title, or priority."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "integer",
                        "description": "ID of the task to update",
                    },
                    "status": {
                        "type": "string",
                        "description": "New status: 'todo', 'in_progress', 'done', or 'blocked'",
                    },
                    "assignee": {
                        "type": "string",
                        "description": "New assignee name",
                    },
                    "title": {
                        "type": "string",
                        "description": "New task title",
                    },
                    "priority": {
                        "type": "string",
                        "description": "New priority: 'low', 'medium', or 'high'",
                    },
                },
                "required": ["task_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_task",
            "description": (
                "Create a new task in the project database. "
                "Automatically assigns the next available ID."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Task title describing what needs to be done",
                    },
                    "assignee": {
                        "type": "string",
                        "description": "Team member to assign (Alice, Bob, Charlie, Diana)",
                    },
                    "priority": {
                        "type": "string",
                        "description": "Priority level: 'low', 'medium', or 'high'",
                        "default": "medium",
                    },
                },
                "required": ["title"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": (
                "Run a shell command in the project directory. "
                "Supports: ls, git status, git log, git diff, grep, cat, head, tail, "
                "pytest, docker ps, wc, pip list, and more. "
                "Use for exploring the project, checking git state, or running tests."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute (e.g. 'git status', 'ls -la src/')",
                    }
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_github_issue",
            "description": (
                "Create a GitHub issue for tracking a bug, feature request, or task. "
                "Returns the issue URL. "
                "Use for documenting problems found, requesting features, or creating follow-up work."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Issue title — be specific and actionable",
                    },
                    "body": {
                        "type": "string",
                        "description": "Issue description with full details",
                    },
                    "labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Labels like 'bug', 'feature', 'security', 'docs'",
                    },
                },
                "required": ["title", "body"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# DISPATCHER — routes tool calls to mock_environment exec functions
# ---------------------------------------------------------------------------

_DISPATCH = {
    "read_file": lambda args: exec_read_file(args["path"]),
    "write_file": lambda args: exec_write_file(args["path"], args["content"]),
    "delete_file": lambda args: exec_delete_file(args["path"]),
    "list_directory": lambda args: exec_list_directory(args["path"]),
    "search_files": lambda args: exec_search_files(args["pattern"], args.get("path", "/project")),
    "send_email": lambda args: exec_send_email(args["to"], args["subject"], args["body"]),
    "send_slack_message": lambda args: exec_send_slack_message(args["channel"], args["message"]),
    "post_to_webhook": lambda args: exec_post_to_webhook(args["url"], args["payload"]),
    "query_database": lambda args: exec_query_database(args["query"]),
    "update_task": lambda args: exec_update_task(
        args["task_id"],
        **{k: v for k, v in args.items() if k != "task_id"},
    ),
    "create_task": lambda args: exec_create_task(
        args["title"],
        assignee=args.get("assignee"),
        priority=args.get("priority", "medium"),
    ),
    "run_shell_command": lambda args: exec_run_shell_command(args["command"]),
    "create_github_issue": lambda args: exec_create_github_issue(
        args["title"],
        args["body"],
        labels=args.get("labels"),
    ),
}


def execute_tool(name: str, arguments: dict) -> str:
    """
    Execute a tool by name with the given arguments dict.

    The arguments dict comes from json.loads(tool_call.function.arguments)
    in the agent loop. Returns a string result that gets sent back to the LLM
    as the tool's output.
    """
    dispatch_fn = _DISPATCH.get(name)
    if dispatch_fn is None:
        return f"Error: Unknown tool '{name}'. Available tools: {list(_DISPATCH.keys())}"
    try:
        return dispatch_fn(arguments)
    except KeyError as e:
        return f"Error: Missing required parameter {e} for tool '{name}'"
    except Exception as e:
        return f"Error executing '{name}': {type(e).__name__}: {e}"
