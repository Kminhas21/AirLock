"""Drift detection via Mahalanobis distance from a behavioral baseline.

Mahalanobis distance is a "shape-aware" distance metric. Unlike Euclidean
distance which treats all directions equally, Mahalanobis accounts for the
covariance (spread/shape) of the baseline data.

Example: if baseline points cluster tightly on the x-axis but spread on y,
a small move on x is significant while the same move on y is not.

The baseline is established from the first N points. All subsequent points
are measured against this baseline. When the distance exceeds a threshold,
we flag a "breach" — the agent has moved significantly from its initial
behavioral pattern.
"""

import numpy as np

# sqrt(chi2.ppf(0.99, df=3)) ~= 3.368: for a 3D Gaussian, a squared Mahalanobis
# distance follows chi-square with 3 degrees of freedom, so 99% of in-distribution
# points fall within this distance. Replaces the old magic 2.5.
CHI2_99_DF3 = 3.368

# Floor on the shrinkage target scale so identical baseline points (zero
# covariance) still give a non-zero, invertible matrix.
_SCALE_FLOOR = 1e-9


class DriftDetector:
    def __init__(self, baseline_size: int = 3, threshold: float = CHI2_99_DF3,
                 shrinkage: float = 0.1):
        self.baseline_size = baseline_size
        self.threshold = threshold
        self.shrinkage = shrinkage
        self.points: list[np.ndarray] = []
        self.baseline_mean: np.ndarray | None = None
        self.baseline_cov_inv: np.ndarray | None = None

    def add_point(self, coordinates: dict) -> tuple[float, bool]:
        """Add a 3D point and return (mahalanobis_distance, baseline_breached).

        For the first `baseline_size` points, returns (0.0, False) since
        we're still building the baseline. Once the baseline is established,
        every new point gets a distance score.
        """
        point = np.array([coordinates["x"], coordinates["y"], coordinates["z"]])
        self.points.append(point)

        if len(self.points) < self.baseline_size:
            return 0.0, False

        if len(self.points) == self.baseline_size:
            self._fit_baseline()

        if self.baseline_mean is not None and self.baseline_cov_inv is not None:
            diff = point - self.baseline_mean
            # Mahalanobis: sqrt(diff^T @ cov_inv @ diff)
            distance = float(np.sqrt(max(diff @ self.baseline_cov_inv @ diff, 0.0)))
            breached = distance > self.threshold
            return round(distance, 3), breached

        return 0.0, False

    def _fit_baseline(self):
        """Compute baseline mean and inverse covariance from accumulated points.

        The covariance matrix describes the "shape" of the baseline cluster.
        A 3-point baseline has rank-2 covariance (nearly coplanar in 3D), so
        the raw matrix is singular. We apply scale-aware shrinkage toward a
        spherical target instead of a fixed epsilon:

            cov_s = (1 - a) * cov + a * (trace(cov) / d) * I

        The target scales with the data, so the distance is invariant to
        uniform scaling of the coordinates. pinv means no LinAlgError.
        """
        baseline = np.array(self.points[:self.baseline_size], dtype=float)
        self.baseline_mean = baseline.mean(axis=0)

        d = baseline.shape[1]
        cov = np.atleast_2d(np.cov(baseline.T))
        cov = np.nan_to_num(cov)
        a = self.shrinkage
        scale = max(float(np.trace(cov)) / d, _SCALE_FLOOR)
        cov_s = (1.0 - a) * cov + a * scale * np.eye(d)
        self.baseline_cov_inv = np.linalg.pinv(cov_s)

    def reset(self):
        """Clear all state for a new session."""
        self.points = []
        self.baseline_mean = None
        self.baseline_cov_inv = None
