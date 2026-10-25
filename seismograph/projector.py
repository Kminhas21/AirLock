from sklearn.decomposition import PCA
import numpy as np


class Projector:
    """Projects high-dimensional embeddings (384-dim) into 3D coordinates.

    Uses PCA (Principal Component Analysis) to find the 3 most informative
    directions in the embedding space. The PCA model is fit once on the
    first `baseline_size` embeddings — these define the coordinate system.
    All subsequent embeddings are projected into that same 3D space, so we
    can visually track how the agent's behavior drifts from its baseline.
    """

    def __init__(self, n_components: int = 3, baseline_size: int = 3):
        self.n_components = n_components
        self.baseline_size = baseline_size
        self.pca = PCA(n_components=n_components)
        self.embeddings: list[list[float]] = []
        self.is_fitted = False

    def add_and_project(self, embedding: list[float]) -> dict:
        """Add a new embedding and return its 3D coordinates.

        Returns {"x": 0, "y": 0, "z": 0} for the first few points
        (before PCA is fitted). Once we have enough baseline points,
        PCA is fitted and all points get real coordinates.
        """
        self.embeddings.append(embedding)

        if len(self.embeddings) < self.baseline_size:
            # Not enough data to fit PCA yet — return origin
            return {"x": 0.0, "y": 0.0, "z": 0.0}

        if len(self.embeddings) == self.baseline_size:
            # We just got enough points — fit PCA on the baseline.
            # n_components can't exceed n_samples - 1, so we cap it.
            # With 3 samples, max useful components = 2 (the 3rd is noise).
            # We still request 3 but PCA will handle the math gracefully.
            n_usable = min(self.n_components, len(self.embeddings))
            self.pca = PCA(n_components=n_usable)
            self.pca.fit(np.array(self.embeddings))
            self.is_fitted = True

            # Re-project all baseline points so they get real coordinates
            all_coords = self.pca.transform(np.array(self.embeddings))
            # Return coords for the latest (last) point
            coords = all_coords[-1]
            return self._to_dict(coords)

        # Post-baseline: transform the new embedding using fitted PCA
        coords = self.pca.transform(np.array([embedding]))[0]
        return self._to_dict(coords)

    def get_all_coordinates(self) -> list[dict]:
        """Re-project all stored embeddings. Useful after PCA is fitted
        to get corrected coordinates for baseline points."""
        if not self.is_fitted:
            return [{"x": 0.0, "y": 0.0, "z": 0.0}] * len(self.embeddings)
        all_coords = self.pca.transform(np.array(self.embeddings))
        return [self._to_dict(c) for c in all_coords]

    def _to_dict(self, coords: np.ndarray) -> dict:
        """Convert a numpy coordinate array to {"x", "y", "z"} dict.
        Pads with 0.0 if fewer than 3 components (can happen with small baselines)."""
        x = float(coords[0]) if len(coords) > 0 else 0.0
        y = float(coords[1]) if len(coords) > 1 else 0.0
        z = float(coords[2]) if len(coords) > 2 else 0.0
        return {"x": x, "y": y, "z": z}

    def reset(self):
        """Clear all state for a new session."""
        self.embeddings = []
        self.is_fitted = False
        self.pca = PCA(n_components=self.n_components)
