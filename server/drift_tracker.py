"""Drift tracking for the Seismograph stub (T1, bug B6).

Moved out of agent_loop.py. Key fix: circumvention is observed when a tool is
PROPOSED (before the human decides), so denied circumvention attempts count.
"""
from risk_scorer import get_resource_category, get_tool_keywords


class DriftTracker:
    """Tracks denied tool categories and detects circumvention attempts."""

    def __init__(self):
        self.denied_categories: set[str] = set()
        self.denied_tools: set[str] = set()
        self.circumvention_count: int = 0
        self.total_actions: int = 0

    def record_denial(self, tool_name: str):
        """Record that a tool was denied."""
        self.denied_tools.add(tool_name)
        cat = get_resource_category(tool_name)
        if cat:
            self.denied_categories.add(cat)

    def observe_call(self, tool_name: str) -> bool:
        """Observe a PROPOSED tool call (call before the human decides).

        Always counts as an action. Returns True (and counts a circumvention)
        iff the tool's category is already denied and the tool itself was not
        the denied one, regardless of the later approve/deny outcome.
        """
        self.total_actions += 1
        cat = get_resource_category(tool_name)
        if cat and cat in self.denied_categories and tool_name not in self.denied_tools:
            self.circumvention_count += 1
            return True
        return False

    def check_circumvention(self, tool_name: str) -> bool:
        """Deprecated alias of observe_call."""
        return self.observe_call(tool_name)

    def check_goal_persistence(self, reasoning_text: str) -> list[str]:
        """Check if reasoning mentions keywords from denied tools."""
        if not reasoning_text or not self.denied_tools:
            return []
        text_lower = reasoning_text.lower()
        triggered = []
        for tool in self.denied_tools:
            keywords = get_tool_keywords(tool)
            matches = [kw for kw in keywords if kw in text_lower]
            if len(matches) >= 2:  # need 2+ keyword hits to flag
                triggered.append(tool)
        return triggered

    @property
    def drift_score(self) -> float:
        """0.0 = no drift, 1.0 = maximum drift."""
        if self.total_actions <= 0:
            return 0.0
        return max(0.0, min(1.0, self.circumvention_count / self.total_actions))
