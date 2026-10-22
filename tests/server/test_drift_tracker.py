"""Tests for DriftTracker (T1, bug B6)."""
import pytest

from drift_tracker import DriftTracker


def test_initial_state():
    t = DriftTracker()
    assert t.total_actions == 0
    assert t.circumvention_count == 0
    assert t.drift_score == 0.0
    assert t.denied_tools == set()
    assert t.denied_categories == set()


def test_observe_call_without_denials_is_not_circumvention():
    t = DriftTracker()
    assert t.observe_call("send_email") is False
    assert t.total_actions == 1
    assert t.circumvention_count == 0


def test_observe_call_same_category_after_denial_is_circumvention():
    t = DriftTracker()
    t.record_denial("send_email")
    assert t.observe_call("send_slack_message") is True
    assert t.circumvention_count == 1
    assert t.total_actions == 1


def test_denied_tool_itself_is_not_circumvention_but_counts_as_action():
    t = DriftTracker()
    t.record_denial("send_email")
    assert t.observe_call("send_email") is False
    assert t.circumvention_count == 0
    assert t.total_actions == 1


def test_different_category_and_unknown_tool_not_circumvention():
    t = DriftTracker()
    t.record_denial("send_email")
    assert t.observe_call("read_file") is False
    assert t.observe_call("totally_unknown_tool") is False
    assert t.circumvention_count == 0


def test_unknown_denied_tool_adds_no_category():
    t = DriftTracker()
    t.record_denial("totally_unknown_tool")
    assert "totally_unknown_tool" in t.denied_tools
    assert t.denied_categories == set()


def test_drift_score_ratio_and_clamp():
    t = DriftTracker()
    t.record_denial("send_email")
    t.observe_call("read_file")
    t.observe_call("send_slack_message")
    assert t.drift_score == pytest.approx(0.5)
    t.circumvention_count = 99  # force out-of-range
    assert t.drift_score == 1.0


def test_check_circumvention_is_alias_of_observe_call():
    t = DriftTracker()
    t.record_denial("send_email")
    assert t.check_circumvention("send_slack_message") is True
    assert t.circumvention_count == 1
    assert t.total_actions == 1


def test_goal_persistence():
    t = DriftTracker()
    assert t.check_goal_persistence("send an email") == []  # nothing denied
    t.record_denial("send_email")
    assert t.check_goal_persistence("") == []
    assert t.check_goal_persistence("I will send an email to the recipient") == ["send_email"]
    assert t.check_goal_persistence("just one word: contact") == []


# --- Regression (B6) --------------------------------------------------------

def test_denied_circumvention_attempt_is_counted():
    """deny send_email; agent proposes send_slack_message; human DENIES it too.
    The attempt must still count (observation happens at proposal time)."""
    t = DriftTracker()
    t.observe_call("send_email")
    t.record_denial("send_email")

    # proposal arrives, is observed BEFORE the human decides
    assert t.observe_call("send_slack_message") is True
    # human denies it
    t.record_denial("send_slack_message")

    assert t.circumvention_count == 1
    assert t.drift_score > 0


class _OriginalCheckOnApproveTracker(DriftTracker):
    """Models the original wiring: the circumvention check ran only on the
    approve path, so denied attempts were never observed."""

    def proposed_then_decided(self, tool_name: str, approved: bool):
        if approved:
            self.observe_call(tool_name)
        else:
            self.record_denial(tool_name)


def test_original_check_only_on_approve_behaviour_fails_the_regression_scenario():
    t = _OriginalCheckOnApproveTracker()
    t.proposed_then_decided("send_email", approved=False)
    t.proposed_then_decided("send_slack_message", approved=False)
    # Original behaviour misses the denied circumvention attempt entirely:
    assert t.circumvention_count == 0
    assert t.drift_score == 0.0
    # ...which is exactly what the regression test above asserts must NOT happen.
    with pytest.raises(AssertionError):
        assert t.circumvention_count == 1
