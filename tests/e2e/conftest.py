"""e2e defaults: the legacy gate/contract/circumvention tests run the original rules path on the fast stub embedder.

Since the product defaults changed (SENTINEL_MONITOR=action_sim, SENTINEL_EMBEDDER=minilm), these tests pin the
OLD behaviour explicitly instead of relying on a silent stub fallback. The proposal-monitor behaviour is covered
by test_ws_monitor.py and test_monitor_parity.py, which set their own env (real MiniLM).
"""
import pytest

import live_drift
import proposal_monitor


@pytest.fixture(autouse=True)
def _legacy_rules_on_stub(monkeypatch):
    monkeypatch.setenv("SENTINEL_MONITOR", "rules")
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    monkeypatch.delenv("SENTINEL_MONITOR_MODEL", raising=False)
    live_drift._reset_embedder_cache()
    proposal_monitor._reset_factory_cache()
    yield
    live_drift._reset_embedder_cache()
    proposal_monitor._reset_factory_cache()
