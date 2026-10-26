import httpx

import live_drift
import proposal_monitor
from main import app


async def test_health_reports_status_monitor_and_embedder(monkeypatch):
    monkeypatch.delenv("SENTINEL_MONITOR", raising=False)
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    live_drift._reset_embedder_cache()
    proposal_monitor._reset_factory_cache()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/health")
    live_drift._reset_embedder_cache()
    assert r.status_code == 200
    # SENTINEL_MONITOR unset -> product default action_sim; the stub embedder cannot support it, so it must
    # fall back to rules AND say so here (never claim a monitor that is not running)
    assert r.json() == {"status": "ok", "monitor": "rules", "requested_monitor": "action_sim", "registry": None, "embedder": "stub", "monitor_errors": 0}
