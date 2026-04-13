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


class DriftDetector:
    def __init__(self, baseline_size: int = 3, threshold: float = 2.5):
        self.baseline_size = baseline_size
        self.threshold = threshold
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
            distance = float(np.sqrt(diff @ self.baseline_cov_inv @ diff))
            breached = distance > self.threshold
            return round(distance, 3), breached

        return 0.0, False

    def _fit_baseline(self):
        """Compute baseline mean and inverse covariance from accumulated points.

        The covariance matrix describes the "shape" of the baseline cluster.
        We add a small regularization term (1e-4 * I) to prevent the matrix
        from being singular (non-invertible), which happens when points are
        nearly coplanar — common with only 3 points in 3D.
        """
        baseline = np.array(self.points[:self.baseline_size])
        self.baseline_mean = baseline.mean(axis=0)

        # np.cov expects each row to be a variable, each column an observation
        # With baseline.T, we get a 3x3 covariance matrix
        cov = np.cov(baseline.T)

        # Regularize: add small identity to prevent singular matrix.
        # 1e-4 is large enough to stabilize but small enough not to distort.
        # (The plan used 1e-6 which is too small for 3-point baselines.)
        cov += np.eye(3) * 1e-4
        self.baseline_cov_inv = np.linalg.inv(cov)

    def reset(self):
        """Clear all state for a new session."""
        self.points = []
        self.baseline_mean = None
        self.baseline_cov_inv = None
