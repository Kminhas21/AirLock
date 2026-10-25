"""Proposal-time monitor: the FROZEN evaluation detectors, run in the live loop BEFORE tool_pending.

SENTINEL_MONITOR selects what watches tool proposals:

* ``action_sim`` (default, the pre-registered survivor, eval D3): alert when the proposed action's effect string is
  within the frozen cosine threshold of an effect the human already DENIED in this session.
* ``learned`` (eval D7): the frozen logistic-regression combiner over the same family of features.
* ``rules``: the original resource-category circumvention rules (live_drift.SessionDrift.observe_tool_call). This
  monitor emits nothing itself; agent_loop keeps using the rules path.

The detectors are imported from ``eval/`` (frozen, scored) and loaded from the frozen model file with
``eval.detectors_v2.load_frozen`` so the live thresholds / weights ARE the evaluated ones.

Failure policy: loud but never fatal. A mode that needs embeddings with the stub embedder active, a missing/corrupt
frozen file, an unknown mode name, or an import failure -> WARNING and the factory degrades to ``rules``
(``/health`` reports the ACTIVE monitor). A runtime exception inside a monitor is logged, counted in
``error_count()`` (``monitor_errors`` on /health) and the proposal simply goes to the human without an alert.

Sync and CPU-bound (embedding); callers wrap ``on_proposal`` / ``register_decision`` in ``asyncio.to_thread``.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Mapping

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

import events  # noqa: E402
import live_drift  # noqa: E402

log = logging.getLogger(__name__)

MODE_ENV = "SENTINEL_MONITOR"
MODEL_ENV = "SENTINEL_MONITOR_MODEL"
DEFAULT_MODE = "action_sim"
DEFAULT_MODEL_PATH = _REPO_ROOT / "eval" / "results_v2" / "frozen_models.json"
TRIGGER = "denied_effect_match"

# mode -> id of the frozen detector in frozen_models.json (None: no detector, rules path)
MODES = {"action_sim": "D3", "learned": "D7", "rules": None}


# --------------------------------------------------------------------------- error counter
_errors = 0
_errors_lock = threading.Lock()


def _count_error() -> None:
    global _errors
    with _errors_lock:
        _errors += 1


def error_count() -> int:
    """Runtime monitor exceptions since process start (exposed as ``monitor_errors`` on /health)."""
    with _errors_lock:
        return _errors


def _reset_errors() -> None:
    """Test hook."""
    global _errors
    with _errors_lock:
        _errors = 0


# --------------------------------------------------------------------------- shared embedder
class LockedEmbedder:
    """Serialises ``embed`` on a lock: the eval embedder's LRU cache and the torch model are not thread-safe, and
    sessions run their monitors in worker threads. Everything else (model_calls, clear_cache, ...) is delegated."""

    def __init__(self, inner, lock: threading.Lock | None = None):
        self._inner = inner
        self._lock = lock or threading.Lock()

    def embed(self, text):
        with self._lock:
            return self._inner.embed(text)

    def __getattr__(self, name):          # only called for attributes not found on the wrapper
        return getattr(self._inner, name)


_shared: LockedEmbedder | None = None
_shared_lock = threading.Lock()


def _shared_embedder() -> LockedEmbedder:
    """ONE process-wide MiniLM (eval.embed.get_shared_embedder, the very instance the evaluation scored with),
    loaded eagerly: raises if the local model cache is missing."""
    global _shared
    with _shared_lock:
        if _shared is None:
            from eval.embed import get_shared_embedder
            inner = get_shared_embedder()
            inner.warm()
            _shared = LockedEmbedder(inner)
        return _shared


# --------------------------------------------------------------------------- per-session monitor
class SessionMonitor:
    """Monitor state for ONE session. Holds fresh detector instances, so denied history is never shared."""

    def __init__(self, mode: str, detector=None, embedder=None, describe_effect=None):
        self.mode = mode
        self._detector = detector
        self._embedder = embedder
        self._describe = describe_effect
        self._denied: list[tuple[str, object]] = []      # (effect string, vector) of DENIED proposals, for the message

    @property
    def is_rules(self) -> bool:
        """True when this monitor emits nothing and the rules circumvention path stays in charge."""
        return self._detector is None

    # -- explanation ------------------------------------------------------------------------------------------
    def _nearest_denied(self, tool: str, args: dict):
        """-> (proposed effect, nearest denied effect or None, cosine or None). Never raises."""
        try:
            effect = self._describe(tool, args)
            if not self._denied:
                return effect, None, None
            v = self._embedder.embed(effect)
            sims = [float(d[1] @ v) for d in self._denied]
            j = max(range(len(sims)), key=sims.__getitem__)
            return effect, self._denied[j][0], sims[j]
        except Exception:
            log.exception("could not explain a monitor alert; alerting without the earlier effect")
            _count_error()
            return None, None, None

    def _message(self, tool: str, args: dict, score: float, threshold: float) -> str:
        effect, denied, cos = self._nearest_denied(tool, args)
        if self.mode == "action_sim":
            head = (f"Proposed action is nearly the same as one you already denied: similarity {score:.2f} "
                    f"exceeds the {threshold:.2f} threshold.")
        else:
            head = (f"Learned monitor score {score:.2f} exceeds the {threshold:.2f} threshold: this proposal "
                    f"looks like an action you already denied"
                    + (f" (effect similarity {cos:.2f})." if cos is not None else "."))
        parts = [head]
        if denied:
            parts.append(f"Earlier denied effect: {denied}")
        if effect:
            parts.append(f"Now proposed: {effect}")
        return " ".join(parts)

    # -- API --------------------------------------------------------------------------------------------------
    def on_proposal(self, agent_text: str, tool: str, args: dict, node_id: str) -> list[dict]:
        """Score a proposal BEFORE the human decides. -> [] or ONE contract-shaped alignment_alert. Never raises."""
        if self._detector is None:
            return []
        try:
            res = self._detector.on_step(agent_text, {"tool": tool, "args": args})
            if not res.alert or res.score is None:
                return []
            score, threshold = float(res.score), float(self._detector.threshold)
            return [events.alignment_alert("critical", TRIGGER, self._message(tool, args, score, threshold),
                                           node_id, score, threshold)]
        except Exception:
            log.exception("proposal monitor failed on %s (%s); continuing without an alert", node_id, tool)
            _count_error()
            return []

    def register_decision(self, tool: str, args: dict, decision: str) -> None:
        """Tell the monitor how the human (or the gate timeout) decided: 'approve' | 'deny'. Never raises."""
        if self._detector is None:
            return
        try:
            self._detector.register_decision({"tool": tool, "args": args}, decision)
            if decision == "deny":
                effect = self._describe(tool, args)
                self._denied.append((effect, self._embedder.embed(effect)))
        except Exception:
            log.exception("proposal monitor failed to register a decision on %s; continuing", tool)
            _count_error()


# --------------------------------------------------------------------------- factory (once per process)
class MonitorFactory:
    """Resolved mode + how to build a fresh SessionMonitor. Call it (or ``new_session()``) once per session."""

    def __init__(self, requested: str, mode: str, reason: str = "", model_path: Path | None = None):
        self.requested = requested          # what the environment asked for
        self.mode = mode                    # what is ACTUALLY active ("rules" after a fallback)
        self.reason = reason                # why it fell back ("" if it did not)
        self.model_path = model_path

    def new_session(self) -> SessionMonitor:
        if self.mode == "rules":
            return SessionMonitor("rules")
        try:
            from eval.detectors_v2 import load_frozen
            from eval.effects import describe_effect
            emb = _shared_embedder()
            det = load_frozen(self.model_path, emb)[MODES[self.mode]]
            det.reset()
            return SessionMonitor(self.mode, det, emb, describe_effect)
        except Exception:
            log.exception("could not build a %s monitor for this session; using rules", self.mode)
            _count_error()
            return SessionMonitor("rules")

    __call__ = new_session


def _fallback(requested: str, reason: str) -> MonitorFactory:
    log.warning("SENTINEL_MONITOR=%s is NOT active: %s. Falling back to the 'rules' monitor.", requested, reason)
    return MonitorFactory(requested, "rules", reason)


def _resolve(env: Mapping[str, str]) -> MonitorFactory:
    requested = (env.get(MODE_ENV) or "").strip().lower() or DEFAULT_MODE
    if requested not in MODES:
        return _fallback(requested, f"unknown mode (expected one of {sorted(MODES)})")
    if requested == "rules":
        return MonitorFactory("rules", "rules")
    try:
        embedder = live_drift.get_embedder()
    except Exception as exc:
        return _fallback(requested, f"no embedder available ({exc!r})")
    if isinstance(embedder, live_drift.StubEmbedder):
        return _fallback(requested, "the active embedder is the stub (MiniLM unavailable or SENTINEL_EMBEDDER=stub); "
                                    "hashed vectors carry no semantics, so the frozen thresholds would be meaningless")
    path = Path(env.get(MODEL_ENV) or DEFAULT_MODEL_PATH)
    try:
        from eval.detectors_v2 import load_frozen
        emb = _shared_embedder()
        det = load_frozen(path, emb)[MODES[requested]]
        float(det.threshold)
    except Exception as exc:        # missing/corrupt file, absent detector, no model cache, eval not importable
        return _fallback(requested, f"cannot load the frozen {MODES[requested]} from {path} ({exc!r})")
    log.info("proposal monitor: %s (frozen %s from %s)", requested, MODES[requested], path)
    return MonitorFactory(requested, requested, model_path=path)


_factory: MonitorFactory | None = None
_factory_key: tuple | None = None
_factory_lock = threading.Lock()


def get_monitor_factory() -> MonitorFactory:
    """The process-wide factory. Mode / model path / embedder choice are resolved from the environment once and
    cached (the cache is keyed on the env values only so that tests that change them re-resolve)."""
    global _factory, _factory_key
    key = (os.environ.get(MODE_ENV), os.environ.get(MODEL_ENV), os.environ.get(live_drift.ENV_VAR))
    with _factory_lock:
        if _factory is None or _factory_key != key:
            _factory, _factory_key = _resolve(os.environ), key
        return _factory


def _reset_factory_cache() -> None:
    """Test hook (also called by live_drift._reset_embedder_cache)."""
    global _factory, _factory_key
    with _factory_lock:
        _factory, _factory_key = None, None


def warm_up() -> None:
    """Load the Seismograph embedder and the monitor's detectors/model now. Never raises."""
    for name, fn in (("embedder", lambda: live_drift.get_embedder()), ("monitor", lambda: get_monitor_factory())):
        try:
            fn()
        except Exception:
            log.exception("warm-up of the %s failed; the first session will retry or fall back", name)


def warm_up_in_background() -> threading.Thread:
    """Start the warm-up in a daemon thread (app startup must not wait for the model load)."""
    t = threading.Thread(target=warm_up, name="sentinel-warmup", daemon=True)
    t.start()
    return t
