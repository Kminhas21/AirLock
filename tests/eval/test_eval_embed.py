"""Shared embedder: batch-1, unit-normalised, LRU cache; deterministic stub."""
import numpy as np
import pytest

from eval.embed import MiniLMEmbedder, StubEmbedder, get_shared_embedder


def cos(a, b):
    return float(np.dot(a, b))


def test_stub_deterministic_unit_384():
    e1, e2 = StubEmbedder(), StubEmbedder()
    v = e1.embed("send the report to alice")
    assert v.shape == (384,) and v.dtype.kind == "f"
    assert abs(np.linalg.norm(v) - 1.0) < 1e-6
    assert np.array_equal(v, e2.embed("send the report to alice"))
    assert np.array_equal(StubEmbedder().embed(""), StubEmbedder().embed(""))
    assert abs(np.linalg.norm(StubEmbedder().embed("")) - 1.0) < 1e-6


def test_stub_overlap_means_similarity():
    e = StubEmbedder()
    a = e.embed("disclose report.csv to external recipient alice")
    b = e.embed("disclose report.csv to external recipient bob")
    c = e.embed("rename the logo graphics folder")
    assert cos(a, b) > cos(a, c) + 0.3


def test_stub_counts_calls_and_cache_clear():
    e = StubEmbedder()
    e.embed("x"); e.embed("y")
    assert e.model_calls == 2
    e.embed("x")            # cached
    assert e.model_calls == 2
    e.clear_cache(); e.embed("x")
    assert e.model_calls == 3


def test_lru_eviction_and_returned_vectors_are_readonly():
    e = StubEmbedder(cache_size=2)
    e.embed("a"); e.embed("b"); e.embed("a"); e.embed("c")   # evicts b (a was refreshed)
    n = e.model_calls
    e.embed("a"); assert e.model_calls == n
    e.embed("b"); assert e.model_calls == n + 1
    v = e.embed("a")
    with pytest.raises(ValueError):
        v[0] = 5.0


@pytest.mark.real_model
def test_minilm_unit_norm_batch1_cache(real_embedder):
    e = real_embedder
    e.clear_cache()
    n0 = e.model_calls
    v = e.embed("Please send the quarterly report to the client.")
    assert v.shape == (384,) and abs(np.linalg.norm(v) - 1.0) < 1e-5
    assert e.model_calls == n0 + 1
    v2 = e.embed("Please send the quarterly report to the client.")
    assert e.model_calls == n0 + 1 and np.array_equal(v, v2)


@pytest.mark.real_model
def test_shared_is_singleton_and_semantic(real_embedder):
    assert get_shared_embedder() is real_embedder
    a = real_embedder.embed("Email the sales numbers to our customer.")
    b = real_embedder.embed("Send the revenue figures to the client by mail.")
    c = real_embedder.embed("Rename the folder with holiday photos.")
    assert cos(a, b) > cos(a, c) + 0.2


@pytest.mark.real_model
def test_matches_shipped_embedder_vector(real_embedder):
    """D0 fidelity: our vector equals what seismograph.Embedder would produce."""
    from seismograph.embedder import Embedder

    shipped = Embedder()
    shipped._model = real_embedder._model   # same weights; exercises the shipped code path
    txt = "I'll start by reading the Q3 report."
    ref = np.array(shipped.embed(txt))
    assert cos(real_embedder.embed(txt), ref / np.linalg.norm(ref)) > 0.99999


def test_minilm_class_lazy_no_load_at_construction():
    e = MiniLMEmbedder()
    assert e._model is None and e.model_calls == 0
