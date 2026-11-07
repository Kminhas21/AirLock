"""S1 / B11: DriftDetector must survive degenerate (rank-deficient) baselines."""
import math

import numpy as np
import pytest

import seismograph.drift_detector as dd
from seismograph.drift_detector import DriftDetector

COPLANAR = [(0, 0, 0), (1, 0, 0), (0, 1, 0)]
NEAR_POINT = (0.3, 0.3, 0.05)  # tiny off-plane offset, well inside the baseline spread


def _run(points, scale=1.0, **kw):
    d = DriftDetector(**kw)
    out = None
    for p in points:
        out = d.add_point({"x": p[0] * scale, "y": p[1] * scale, "z": p[2] * scale})
    return out, d


def test_near_point_on_coplanar_baseline_is_not_absurd():
    # Old code (+1e-4*I): distance 5.0 here (z^2 / 1e-4 blow-up) and breached=True.
    (dist, breached), _ = _run(COPLANAR + [NEAR_POINT])
    assert dist < 1.0
    assert breached is False


def test_scale_invariance():
    # Old code: distance 5.0 at scale 1 and 50.0 at scale 10.
    (d1, _), _ = _run(COPLANAR + [NEAR_POINT], scale=1.0)
    (d10, _), _ = _run(COPLANAR + [NEAR_POINT], scale=10.0)
    assert d1 == pytest.approx(d10, rel=1e-2, abs=2e-3)


def test_threshold_constant_and_override():
    assert dd.CHI2_99_DF3 == 3.368
    assert DriftDetector().threshold == dd.CHI2_99_DF3
    assert DriftDetector(threshold=1.0).threshold == 1.0


def test_near_below_and_far_above_threshold():
    base = [(0, 0, 0), (1, 0, 0), (0, 1, 0)]
    (near, nb), _ = _run(base + [(0.33, 0.33, 0.0)])
    (far, fb), _ = _run(base + [(50, 50, 50)])
    assert near < 3.368 and nb is False
    assert far > 3.368 and fb is True


def test_pre_baseline_returns_zero():
    d = DriftDetector()
    assert d.add_point({"x": 1, "y": 2, "z": 3}) == (0.0, False)


@pytest.mark.parametrize("kind", ["identical", "collinear", "coplanar", "random"])
def test_never_raises_and_finite(kind):
    for seed in range(200):
        rng = np.random.default_rng(seed)
        if kind == "identical":
            p = rng.normal(size=3)
            base = [p, p, p]
        elif kind == "collinear":
            a, v = rng.normal(size=3), rng.normal(size=3)
            base = [a + t * v for t in (0.0, 1.0, 2.5)]
        elif kind == "coplanar":
            a, u, v = rng.normal(size=(3, 3))
            base = [a, a + u, a + v]
        else:
            base = list(rng.normal(size=(3, 3)))
        pts = base + list(rng.normal(size=(3, 3)) * 3)
        d = DriftDetector()
        for p in pts:
            dist, breached = d.add_point({"x": p[0], "y": p[1], "z": p[2]})
            assert math.isfinite(dist) and dist >= 0.0
            assert isinstance(breached, bool)


def test_identical_baseline_other_point_far():
    (dist, breached), _ = _run([(1, 1, 1)] * 3 + [(2, 2, 2)])
    assert math.isfinite(dist)
    assert breached is True


def test_shrinkage_param_and_reset():
    (_, _), d = _run(COPLANAR + [NEAR_POINT], shrinkage=0.5)
    assert d.shrinkage == 0.5
    d.reset()
    assert d.baseline_cov_inv is None
