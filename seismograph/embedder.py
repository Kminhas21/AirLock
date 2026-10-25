"""Embedding providers for the Seismograph pipeline.

Uses dependency injection: SeismographAnalyzer accepts any object with an
embed(text) -> list[float] method. This module provides:

- Embedder:      Real ML model (sentence-transformers). Lazy-loaded, offline-safe.
- StubEmbedder:  Deterministic hash-based vectors. No ML, no network, instant.
                 Use for unit tests and CI.

Alpha's server should create ONE Embedder at startup and pass it into
SeismographAnalyzer to avoid re-loading the model per session.
"""

from __future__ import annotations

import hashlib
from typing import Protocol


class EmbedderProtocol(Protocol):
    """Any object with this method can be used as an embedder."""
    def embed(self, text: str) -> list[float]: ...


class Embedder:
    """Real embedding provider using sentence-transformers.

    The model is lazy-loaded on the first call to embed(), not in __init__.
    This keeps construction cheap and lets Alpha pre-warm it once at startup.
    Uses local_files_only=True to prevent network calls during demo —
    the model must be pre-downloaded to ~/.cache/.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self._model_name = model_name
        self._model = None  # Lazy-loaded

    def embed(self, text: str) -> list[float]:
        """Return a 384-dimensional embedding for the input text."""
        if self._model is None:
            self._load_model()
        return self._model.encode(text).tolist()

    def _load_model(self):
        """Load the model from local cache. Fails clearly if not cached."""
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(
                self._model_name,
                local_files_only=True,
            )
        except OSError:
            raise RuntimeError(
                f"Model '{self._model_name}' not found in local cache. "
                f"Pre-download it by running:\n"
                f"  python -c \"from sentence_transformers import SentenceTransformer; "
                f"SentenceTransformer('{self._model_name}')\""
            )


class StubEmbedder:
    """Deterministic hash-based embedder for tests. No ML dependencies.

    Produces 384-dim vectors derived from a SHA-256 hash of the input text.
    Semantically similar texts will NOT produce similar vectors (unlike the
    real model), but the output is deterministic and instant — perfect for
    testing pipeline logic without ML flakiness.
    """

    def __init__(self, dim: int = 384):
        self._dim = dim

    def embed(self, text: str) -> list[float]:
        """Return a deterministic 384-dim vector based on text hash."""
        # Use SHA-256 to get enough bytes, then expand to fill dim
        h = hashlib.sha256(text.encode()).digest()
        # Repeat hash bytes to cover dim, convert to floats in [-1, 1]
        values = []
        for i in range(self._dim):
            byte_val = h[i % len(h)]
            values.append((byte_val / 127.5) - 1.0)  # map 0-255 to [-1, 1]
        return values
