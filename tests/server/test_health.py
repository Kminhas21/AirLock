import httpx

import live_drift
from main import app


async def test_health_reports_status_monitor_and_embedder(monkeypatch):
    monkeypatch.delenv("SENTINEL_MONITOR", raising=False)
    monkeypatch.setenv("SENTINEL_EMBEDDER", "stub")
    live_drift._reset_embedder_cache()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/health")
    live_drift._reset_embedder_cache()
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "monitor": "rules", "embedder": "stub"}
