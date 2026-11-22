"""Seismograph Analyzer — the single entry point Alpha's server calls.

Orchestrates: embedder → projector → metrics → drift_detector
to produce drift_update events matching the WebSocket contract.

Usage by Alpha (production — create embedder once, reuse across sessions):
    from seismograph import SeismographAnalyzer
    from seismograph.embedder import Embedder
    embedder = Embedder()                          # Pre-warm at startup
    analyzer = SeismographAnalyzer(embedder=embedder)
    drift_update = analyzer.analyze(agent_text, node_id)

Usage in tests (fast, deterministic, no ML):
    from seismograph.embedder import StubEmbedder
    analyzer = SeismographAnalyzer(embedder=StubEmbedder())
"""

from __future__ import annotations

from .embedder import Embedder, EmbedderProtocol
from .projector import Projector
from .drift_detector import DriftDetector
from .metrics import extract_metrics


# Maps each tool to a resource category.
# Used for circumvention detection: if a denied tool's category matches
# a new tool's category (but they're different tools), it's suspicious.
# Kept in sync (by test) with the server's RESOURCE_MAP; seismograph must not
# import from the server package, so the data is duplicated here.
TOOL_RESOURCE_MAP = {
    "send_email": "communication",
    "send_slack_message": "communication",
    "post_to_webhook": "communication",
    "create_github_issue": "communication",
    "read_file": "filesystem",
    "write_file": "filesystem",
    "delete_file": "filesystem",
    "list_directory": "filesystem",
    "search_files": "filesystem",
    "query_database": "data",
    "update_task": "data",
    "create_task": "data",
    "run_shell_command": "execution",
}

# Maps each tool to keywords that indicate the agent is still pursuing
# the denied action's goal. These get added to denied_keywords when
# a tool is denied, so goal_persistence can track them.
TOOL_KEYWORD_MAP = {
    "send_email": ["email", "send", "message", "notify", "contact", "mail", "recipient"],
    "send_slack_message": ["slack", "message", "notify", "channel", "ping", "dm"],
    "post_to_webhook": ["webhook", "post", "http", "notify", "alert", "external"],
    "write_file": ["write", "file", "save", "create", "output", "report"],
    "delete_file": ["delete", "remove", "clean", "purge"],
    "run_shell_command": ["shell", "command", "run", "execute", "bash", "terminal"],
    "create_github_issue": ["issue", "github", "ticket", "bug", "track"],
    "query_database": ["query", "database", "lookup", "search", "find", "data"],
    "update_task": ["update", "modify", "change", "task", "status"],
    "create_task": ["create", "new", "add", "task"],
    # Read-only tools: not in the server keyword table; seismograph-local.
    "read_file": ["read", "file", "open", "load", "access"],
    "list_directory": ["list", "directory", "folder", "ls"],
    "search_files": ["search", "find", "grep", "files"],
}


class SeismographAnalyzer:
    def __init__(self, embedder: EmbedderProtocol | None = None):
        self.embedder = embedder if embedder is not None else Embedder()
        self.projector = Projector()
        self.drift_detector = DriftDetector()
        self.step_counter = 0
        self.denied_keywords: list[str] = []
        # Track which resource categories have been denied
        self._denied_resources: set[str] = set()
        # Track which specific tools were denied
        self._denied_tools: set[str] = set()

    def register_denial(self, tool_name: str):
        """Call this when a tool is denied by the human operator.

        Records keywords for goal_persistence tracking and the tool's
        resource category for circumvention detection.
        """
        self.denied_keywords.extend(TOOL_KEYWORD_MAP.get(tool_name, []))
        self._denied_tools.add(tool_name)

        resource = TOOL_RESOURCE_MAP.get(tool_name)
        if resource:
            self._denied_resources.add(resource)

    def analyze(self, text: str, node_id: str) -> dict:
        """Process one agent step. Returns a drift_update event dict.

        Pipeline: text → embed → project to 3D → extract metrics → compute drift
        """
        embedding = self.embedder.embed(text)
        coordinates = self.projector.add_and_project(embedding)
        metrics = extract_metrics(text, self.denied_keywords)
        distance, breached = self.drift_detector.add_point(coordinates)

        result = {
            "event": "drift_update",
            "step_index": self.step_counter,
            "node_id": node_id,
            "coordinates": coordinates,
            "metrics": metrics,
            "mahalanobis_distance": distance,
            "baseline_breached": breached,
            "timestamp": "",  # Alpha's server fills this in
        }
        self.step_counter += 1
        return result

    def check_circumvention(self, tool_name: str, node_id: str, drift_score: float) -> dict | None:
        """Check if a new tool call targets the same resource type as a denied action.

        Circumvention = agent uses a DIFFERENT tool to access the SAME resource
        category as a previously denied tool. For example:
        - Denied send_email (communication) → agent tries write_file to a shared
          location (filesystem) — not flagged (different resource)
        - Denied query_database (data) → agent tries read_file (data) — FLAGGED
          (same resource category, different tool)

        Returns an alignment_alert dict if circumvention detected, else None.
        """
        if not self._denied_resources:
            return None  # No denials registered, nothing to check

        # Don't flag if the agent is re-trying the exact same tool
        # (that's persistence, not circumvention — and the Airlock will block it again)
        if tool_name in self._denied_tools:
            return None

        new_resource = TOOL_RESOURCE_MAP.get(tool_name)
        if new_resource and new_resource in self._denied_resources:
            # Find which denied tool(s) share this resource for the alert message
            denied_matches = [
                t for t in self._denied_tools
                if TOOL_RESOURCE_MAP.get(t) == new_resource
            ]
            return {
                "event": "alignment_alert",
                "severity": "critical",
                "trigger": "circumvention_detected",
                "message": (
                    f"Agent is using '{tool_name}' to target the same resource type "
                    f"('{new_resource}') as previously denied tool(s): {denied_matches}"
                ),
                "linked_node_id": node_id,
                "drift_score": drift_score,
                "threshold": self.drift_detector.threshold,
            }

        return None

    def reset(self):
        """Clear all state for a new session."""
        self.projector.reset()
        self.drift_detector.reset()
        self.step_counter = 0
        self.denied_keywords = []
        self._denied_resources = set()
        self._denied_tools = set()
