"""Shared embedders for the evaluation harness.

* ``MiniLMEmbedder``: all-MiniLM-L6-v2 on CPU, batch size 1, unit-normalised output,
  small LRU cache. ONE warm instance is shared by every detector (``get_shared_embedder``).
* ``StubEmbedder``: deterministic hashed bag-of-words for fast unit tests (shared words =>
  higher cosine; no model, no network).

Both expose ``embed(text) -> np.ndarray`` (1-D, float32/64, L2 norm 1, read-only),
``model_calls`` (number of real encodes, cache hits excluded), ``clear_cache()``.
"""
from __future__ import annotations

import hashlib
import os
import re
from collections import OrderedDict

os.environ.setdefault("HF_HUB_OFFLINE", "1")   # never touch the network

import numpy as np

DEFAULT_MODEL = "all-MiniLM-L6-v2"
DEFAULT_CACHE = 256


class _CachedEmbedder:
    name = "base"

    def __init__(self, cache_size: int = DEFAULT_CACHE):
        self.cache_size = int(cache_size)
        self._cache: OrderedDict[str, np.ndarray] = OrderedDict()
        self.model_calls = 0

    def _encode(self, text: str) -> np.ndarray:   # pragma: no cover - abstract
        raise NotImplementedError

    def embed(self, text: str) -> np.ndarray:
        hit = self._cache.get(text)
        if hit is not None:
            self._cache.move_to_end(text)
            return hit
        v = np.asarray(self._encode(text), dtype=np.float64).reshape(-1)
        n = float(np.linalg.norm(v))
        v = v / n if n > 0 else v
        v.flags.writeable = False
        self.model_calls += 1
        if self.cache_size > 0:
            self._cache[text] = v
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)
        return v

    def clear_cache(self) -> None:
        self._cache.clear()

    def warm(self) -> None:
        """Make sure the model is loaded (no-op for the stub)."""


class MiniLMEmbedder(_CachedEmbedder):
    name = DEFAULT_MODEL

    def __init__(self, model_name: str = DEFAULT_MODEL, cache_size: int = DEFAULT_CACHE, device: str = "cpu"):
        super().__init__(cache_size)
        self.model_name = model_name
        self.device = device
        self._model = None

    def warm(self) -> None:
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name, device=self.device, local_files_only=True)
            self._model.encode("warm up", batch_size=1, show_progress_bar=False)   # first-call overheads
            self.model_calls = 0

    def _encode(self, text: str) -> np.ndarray:
        self.warm()
        return self._model.encode(text, batch_size=1, convert_to_numpy=True, show_progress_bar=False)


class StubEmbedder(_CachedEmbedder):
    """Hashed bag of lower-cased alphanumeric tokens in 384-d, signed. Deterministic across runs."""
    name = "stub"

    def __init__(self, dim: int = 384, cache_size: int = DEFAULT_CACHE):
        super().__init__(cache_size)
        self.dim = dim

    def _encode(self, text: str) -> np.ndarray:
        v = np.zeros(self.dim)
        toks = re.findall(r"[a-z0-9_.@\-]+", text.lower()) or [""]
        for t in toks:
            h = hashlib.md5(t.encode()).digest()
            idx = int.from_bytes(h[:4], "big") % self.dim
            v[idx] += 1.0 if h[4] & 1 else -1.0
        if not v.any():
            v[0] = 1.0
        return v


_SHARED: MiniLMEmbedder | None = None


def get_shared_embedder() -> MiniLMEmbedder:
    """The process-wide warm MiniLM embedder (lazy: model loads on first embed()/warm())."""
    global _SHARED
    if _SHARED is None:
        _SHARED = MiniLMEmbedder()
    return _SHARED
