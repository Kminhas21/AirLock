"""D1 live drift: per-session adapter over SeismographAnalyzer + DriftTracker.

Methods are sync and CPU-bound; callers wrap them in asyncio.to_thread.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Mapping

# `seismograph/` is a sibling of `server/`, and the server is started from inside `server/`
# (`uvicorn main:app`), so the repo root is not on sys.path by default.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.append(_REPO_ROOT)

import events
from drift_tracker import DriftTracker
from seismograph.analyzer import SeismographAnalyzer
from seismograph.embedder import Embedder, EmbedderProtocol, StubEmbedder

log = logging.getLogger(__name__)

ENV_VAR = "SENTINEL_EMBEDDER"


def make_embedder(env: Mapping[str, str] = os.environ) -> EmbedderProtocol:
    """Build an embedder from SENTINEL_EMBEDDER ('minilm' default | 'stub').

    The proposal monitors need real embeddings, hence the default. Never raises: any failure of the real
    embedder falls back to the stub with a WARNING (and the monitor then falls back to rules, see /health).
    """
    choice = (env.get(ENV_VAR) or "minilm").strip().lower()
    if choice == "stub":
        return StubEmbedder()
    if choice != "minilm":
        log.warning("Unknown %s=%r; falling back to StubEmbedder", ENV_VAR, choice)
        return StubEmbedder()
    try:
        emb = Embedder()
        emb.embed("warmup")  # Embedder loads lazily; surface failures now
        return emb
    except Exception as exc:  # missing package, model cache, anything
        log.warning("MiniLM embedder unavailable (%s); falling back to StubEmbedder "
                    "(proposal monitors that need embeddings will fall back to rules)", exc)
        return StubEmbedder()


_cached: EmbedderProtocol | None = None
_lock = threading.Lock()


def get_embedder() -> EmbedderProtocol:
    """Process-wide embedder, built once from os.environ."""
    global _cached
    with _lock:
        if _cached is None:
            _cached = make_embedder(os.environ)
        return _cached


def _reset_embedder_cache() -> None:
    """Test hook."""
    global _cached
    with _lock:
        _cached = None
    pm = sys.modules.get("proposal_monitor")      # the monitor factory depends on the embedder choice
    if pm is not None:                            # (outside _lock: the factory takes its own lock, then ours)
        pm._reset_factory_cache()


MONITOR_ENV_VAR = "SENTINEL_MONITOR"


def monitor_info() -> dict:
    """What is ACTUALLY monitoring proposals (reported by /health):
    {"monitor": "action_sim"|"learned"|"rules", "embedder": "minilm"|"stub"|"none", "monitor_errors": int}.

    ``monitor`` is the ACTIVE mode, not the requested one: a fallback to rules (stub embedder, missing or corrupt
    frozen file, unknown mode) shows up as "rules". ``embedder`` is the active embedder. ``monitor_errors`` counts
    runtime monitor exceptions (each one was logged and the proposal went to the human without an alert).
    """
    import proposal_monitor    # lazy: proposal_monitor imports this module
    try:
        monitor = proposal_monitor.get_monitor_factory().mode
    except Exception:  # pragma: no cover - the factory degrades instead of raising; belt and braces
        log.exception("monitor factory failed")
        monitor = "rules"
    errors = proposal_monitor.error_count()
    try:
        emb = get_embedder()
    except Exception:  # pragma: no cover - make_embedder never raises, belt and braces
        return {"monitor": monitor, "embedder": "none", "monitor_errors": errors}
    if isinstance(emb, StubEmbedder):
        kind = "stub"
    elif isinstance(emb, Embedder):
        kind = "minilm"
    else:
        kind = "none"
    return {"monitor": monitor, "embedder": kind, "monitor_errors": errors}


class SessionDrift:
    """Drift state for ONE session. Not shared between sessions."""

    def __init__(self, embedder: EmbedderProtocol | None = None):
        self.analyzer = SeismographAnalyzer(embedder=embedder or get_embedder())
        self.tracker = DriftTracker()

    @property
    def threshold(self) -> float:
        return self.analyzer.drift_detector.threshold

    def observe_reasoning(self, text: str, node_id: str) -> list[dict]:
        raw = self.analyzer.analyze(text, node_id)
        out = [events.drift_update(
            raw["step_index"], raw["node_id"], raw["coordinates"], raw["metrics"],
            raw["mahalanobis_distance"], raw["baseline_breached"],
        )]
        hits = self.tracker.check_goal_persistence(text)
        if hits:
            out.append(events.alignment_alert(
                "warning", "goal_persistence",
                f"Reasoning keeps pursuing the goal of denied tool(s): {sorted(hits)}",
                node_id, self.tracker.drift_score, self.threshold,
            ))
        return out

    def observe_tool_call(self, tool_name: str, node_id: str) -> list[dict]:
        """Call at proposal time, before the human decides. At most one alert."""
        # Evaluate both unconditionally so each keeps consistent counters.
        tracker_flag = self.tracker.observe_call(tool_name)
        score = self.tracker.drift_score
        analyzer_alert = self.analyzer.check_circumvention(tool_name, node_id, score)
        if not (tracker_flag or analyzer_alert):
            return []
        message = (analyzer_alert or {}).get("message") or (
            f"Agent is using '{tool_name}' to reach a resource category of a denied tool"
        )
        return [events.alignment_alert(
            "critical", "circumvention_detected", message, node_id, score, self.threshold,
        )]

    def observe_denial(self, tool_name: str) -> None:
        self.tracker.record_denial(tool_name)
        self.analyzer.register_denial(tool_name)
