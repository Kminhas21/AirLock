"""Pre-registered survivor rule (SPEC_V2), on hand-built metric dicts."""
import math

import pytest

from eval import run_eval_v2 as R2


def det(on_time=0.8, fa=0.03, fa_c=0.05, fa_e=0.05, ms=10.0, v1=0.8, gain=None):
    d = {"on_time": on_time, "fa_overall": fa, "fa_c": fa_c, "fa_e": fa_e, "warm_median_ms": ms, "v1_on_time": v1}
    if gain is not None:
        d["gain_vs_D5"] = {"diff": gain[0], "ci": list(gain[1])}
    return d


def base(**over):
    """D1 weak, D5 qualifying at 0.75, ML detectors weak unless overridden."""
    m = {"D1": det(on_time=0.3, v1=0.3), "D5": det(on_time=0.75, v1=0.8)}
    for k in ("D3", "D4", "D6", "D7"):
        m[k] = det(on_time=0.78, gain=(0.03, (-0.05, 0.10)))
    m.update(over)
    return m


def test_picks_d5_when_ml_gain_below_10pp():
    r = R2.select_survivor(base(D7=det(on_time=0.84, gain=(0.09, (0.01, 0.17)))))
    assert r["survivor"] == "D5" and r["label"] == "policy_check"
    assert r["message"].startswith("D5 (policy check): embeddings did not earn their place")
    assert r["embeddings_earned"] is False


def test_picks_d5_when_ci_includes_zero():
    r = R2.select_survivor(base(D7=det(on_time=0.95, gain=(0.20, (-0.01, 0.35)))))
    assert r["survivor"] == "D5" and r["label"] == "policy_check"


def test_picks_ml_when_gain_and_ci_pass():
    r = R2.select_survivor(base(D7=det(on_time=0.90, gain=(0.15, (0.04, 0.26)))))
    assert r["survivor"] == "D7" and r["label"] == "survivor" and r["embeddings_earned"] is True
    assert "D7" in r["message"]


def test_boundary_gain_exactly_10pp_passes():
    r = R2.select_survivor(base(D6=det(on_time=0.85, gain=(0.10, (0.001, 0.2)))))
    assert r["survivor"] == "D6"


def test_highest_on_time_among_qualifying_ml():
    r = R2.select_survivor(base(D6=det(on_time=0.86, gain=(0.11, (0.02, 0.2))),
                                D7=det(on_time=0.90, gain=(0.15, (0.04, 0.26)))))
    assert r["survivor"] == "D7"


def test_ml_that_fails_other_criteria_is_not_chosen():
    bad = det(on_time=0.95, fa=0.08, gain=(0.2, (0.1, 0.3)))
    r = R2.select_survivor(base(D7=bad))
    assert r["survivor"] == "D5" and r["qualifies"]["D7"] is False
    assert r["criteria"]["D7"]["fa_overall<=5%"]["ok"] is False


@pytest.mark.parametrize("field,val,crit", [
    ("on_time", 0.69, "on_time>=70%"), ("fa", 0.051, "fa_overall<=5%"), ("fa_c", 0.101, "fa_c<=10%"),
    ("fa_e", 0.101, "fa_e<=10%"), ("ms", 100.5, "warm_median<=100ms"), ("v1", 0.69, "v1_on_time_drop<=10pp")])
def test_each_criterion_disqualifies(field, val, crit):
    kw = dict(on_time=0.9, gain=(0.15, (0.05, 0.25)), v1=0.9)
    kw[field] = val
    r = R2.select_survivor(base(D7=det(**kw)))
    assert r["qualifies"]["D7"] is False and r["criteria"]["D7"][crit]["ok"] is False
    assert r["criteria"]["D7"][crit]["value"] == val


def test_v1_drop_is_relative_to_d5_and_exactly_10_points_ok():
    r = R2.select_survivor(base(D7=det(on_time=0.9, v1=0.70, gain=(0.15, (0.05, 0.25)))))      # D5 v1 = 0.80
    assert r["criteria"]["D7"]["v1_on_time_drop<=10pp"]["ok"] is True and r["survivor"] == "D7"
    r = R2.select_survivor(base(D7=det(on_time=0.9, v1=0.699, gain=(0.15, (0.05, 0.25)))))
    assert r["survivor"] == "D5"


def test_nan_fails():
    r = R2.select_survivor(base(D7=det(on_time=0.9, fa_c=math.nan, gain=(0.15, (0.05, 0.25)))))
    assert r["qualifies"]["D7"] is False
    r = R2.select_survivor(base(D7=det(on_time=0.9, gain=(0.15, (math.nan, math.nan)))))
    assert r["survivor"] == "D5"


def test_partial_when_nobody_qualifies():
    m = {"D1": det(on_time=0.2, fa_c=0.0), "D5": det(on_time=0.6, fa_c=0.08, fa=0.02),
         "D3": det(on_time=0.65, fa_c=0.09, gain=(0.05, (0.0, 0.1))),
         "D4": det(on_time=0.9, fa_c=0.30, fa=0.2, gain=(0.3, (0.2, 0.4))),      # best on-time but bucket (c) fails
         "D6": det(on_time=0.55, fa_c=0.05, gain=(-0.05, (-0.1, 0.0))),
         "D7": det(on_time=0.4, fa_c=0.05, gain=(-0.2, (-0.3, -0.1)))}
    r = R2.select_survivor(m)
    assert r["label"] == "partial" and r["survivor"] == "D3"
    assert all(not q for q in r["qualifies"].values())
    assert "shortfall" in r["message"].lower() or "partial" in r["message"].lower()
    assert r["criteria"]["D3"]["on_time>=70%"]["ok"] is False     # every criterion value is reported


def test_none_when_nobody_has_bucket_c_ok():
    m = {k: det(on_time=0.5, fa_c=0.4, gain=(0.0, (-0.1, 0.1))) for k in ("D1", "D3", "D4", "D5", "D6", "D7")}
    r = R2.select_survivor(m)
    assert r["survivor"] is None and r["label"] == "none"


def test_non_ml_d1_can_win_by_highest_on_time():
    r = R2.select_survivor(base(D1=det(on_time=0.9, v1=0.9)))
    assert r["survivor"] == "D1" and r["label"] == "survivor"
    assert r["embeddings_earned"] is False


def test_ml_wins_even_if_d5_itself_does_not_qualify():
    m = base(D5=det(on_time=0.5, v1=0.8), D7=det(on_time=0.8, gain=(0.30, (0.1, 0.5))))
    r = R2.select_survivor(m)
    assert r["survivor"] == "D7"


def test_d5_fallback_reports_d5_own_qualification():
    m = base(D5=det(on_time=0.5), D7=det(on_time=0.8, gain=(0.05, (0.0, 0.1))))
    r = R2.select_survivor(m)
    assert r["survivor"] == "D5" and r["label"] == "policy_check" and r["qualifies"]["D5"] is False
    assert "does not itself qualify" in r["message"].lower() or "does not qualify" in r["message"].lower()
