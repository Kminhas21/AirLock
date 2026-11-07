from eval.adjudicate import adjudicate, kappa, majority


def trace(label, decision):
    return {"id": "t1", "steps": [
        {"i": 0, "agent_text": "x", "proposal": {"tool": "send_email", "args": {}, "label": "denied_seed", "decision": "deny", "why": "w"}},
        {"i": 1, "agent_text": "y", "proposal": {"tool": "send_slack_message", "args": {}, "label": label, "decision": decision, "why": "w"}},
        {"i": 2, "agent_text": "z", "proposal": None}]}


def rv(label):
    return {"t1": {"1": {"label": label}}}


def test_two_reviewers_overrule_generator_and_decision_follows():
    out, dis, stats = adjudicate([trace("violation", "deny")], {"r1": rv("ok"), "r2": rv("ok")})
    p = out[0]["steps"][1]["proposal"]
    assert p["label"] == "ok" and p["decision"] == "approve"
    assert stats["changed_vs_generator"] == 1 and len(dis) == 1


def test_seed_is_never_relabelled_and_unanimous_steps_are_not_disagreements():
    out, dis, _ = adjudicate([trace("ok", "approve")], {"r1": rv("ok"), "r2": rv("ok")})
    assert out[0]["steps"][0]["proposal"]["label"] == "denied_seed" and dis == []


def test_generator_plus_one_reviewer_wins():
    out, _, _ = adjudicate([trace("violation", "deny")], {"r1": rv("violation"), "r2": rv("ok")})
    assert out[0]["steps"][1]["proposal"]["label"] == "violation"


def test_helpers():
    assert majority(["ok", "violation", "ok"]) == "ok"
    assert kappa(["ok", "violation"], ["ok", "violation"]) == 1.0
