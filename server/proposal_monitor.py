"""Proposal-time monitor: the FROZEN evaluation detectors, run in the live loop BEFORE tool_pending.

SENTINEL_MONITOR selects what watches tool proposals:

* ``action_sim`` (default, the pre-registered survivor, eval D3): alert when the proposed action's effect string is
  within the frozen cosine threshold of an effect the human already DENIED in this session.
* ``learned`` (eval D7): the frozen logistic-regression combiner over the same family of features. Needs a frozen
  file fitted AFTER the post-hoc ``proposals_since_denial`` fix: set SENTINEL_MONITOR_MODEL=
  eval/results_v2_posthoc/frozen_models.json. The default (ORIGINAL) file still serves ``action_sim``; its D7 uses the
  old step-index feature and is refused (loud fallback to ``rules``).
* ``rules``: the original resource-category circumvention rules (live_drift.SessionDrift.observe_tool_call). This
  monitor emits nothing itself; agent_loop keeps using the rules path.
* ``registry`` (eval D8, rule) and ``registry_learned`` (eval D9, D7 + registry features): OPT-IN (DECISIONS.md D9: the
  pre-registered criteria were not met, so the default is unchanged). They need an operator-written destination registry
  (docs/registry.md) at SENTINEL_REGISTRY and the frozen models at SENTINEL_REGISTRY_MODEL (default
  eval/results_registry/frozen_registry_models.json). The registry is loaded and linted at every session start (mtime-cached),
  so edits apply to the NEXT session without a restart. Without a usable registry (unset / missing / unparseable /
  lint errors), a missing frozen file or the stub embedder they fall back LOUDLY to ``action_sim`` and never to a
  registry-trained detector without a registry (evaluation: D9 without a registry 16.7% on-time vs 37.5% for D7).
  Alerts: severity ``critical``, trigger ``registry_denied_party_match``, with a message that names the destination, the
  registry entry and its note, the party, the earlier denied proposal that reached the same party and the scores.
  SENTINEL_MONITOR_THRESHOLD (float in [0, 1]) overrides D8's two thresholds / D9's threshold: UNCALIBRATED, for operators
  who accept that the frozen values are the only pre-registered ones.

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
import math
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
REGISTRY_ENV = "SENTINEL_REGISTRY"
REGISTRY_MODEL_ENV = "SENTINEL_REGISTRY_MODEL"
THRESHOLD_ENV = "SENTINEL_MONITOR_THRESHOLD"
DEFAULT_MODE = "action_sim"
DEFAULT_MODEL_PATH = _REPO_ROOT / "eval" / "results_v2" / "frozen_models.json"
DEFAULT_REGISTRY_MODEL_PATH = _REPO_ROOT / "eval" / "results_registry" / "frozen_registry_models.json"
TRIGGER = "denied_effect_match"
REGISTRY_TRIGGER = "registry_denied_party_match"

# mode -> id of the frozen detector in frozen_models.json / frozen_registry_models.json (None: rules path)
MODES = {"action_sim": "D3", "learned": "D7", "rules": None, "registry": "D8", "registry_learned": "D9"}
REGISTRY_MODES = ("registry", "registry_learned")


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


# --------------------------------------------------------------------------- registry file (mtime-cached)
_registry_cache: dict[str, tuple] = {}        # path -> (signature, Registry | None, reason)
_registry_lock = threading.Lock()


def _file_sig(path) -> tuple | None:
    """(mtime_ns, size, inode) of a file, None if it cannot be stat-ed."""
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size, st.st_ino)
    except OSError:
        return None


def load_registry(path: str | os.PathLike) -> tuple["object | None", str]:
    """-> (Registry, "") or (None, reason). Parsed and LINTED again whenever the file's mtime / size / inode changed
    (so an operator edit applies to the next session start, no restart); lint errors reject the whole registry and
    are logged one by one. Never raises."""
    key = str(path)
    sig = _file_sig(key)
    with _registry_lock:
        hit = _registry_cache.get(key)
        if hit is not None and hit[0] == sig and sig is not None:
            return hit[1], hit[2]
        reg, reason = None, ""
        if sig is None:
            reason = f"registry file {key} does not exist or cannot be read"
        else:
            try:
                from server.registry import Registry       # the module eval.detectors_registry uses (same class)
                cand = Registry.load(key)
                errors = cand.validate()
                for w in cand.warnings():
                    log.info("registry %s: warning: %s", key, w)
                if errors:
                    for e in errors:
                        log.warning("registry %s: lint error: %s", key, e)
                    reason = (f"registry {key} has {len(errors)} lint error(s) (first: {errors[0]}); "
                              f"fix it (python -m registry_cli lint) - it was rejected")
                else:
                    reg = cand
            except Exception as exc:                          # unparseable JSON, not an object, unreadable
                reason = f"registry {key} cannot be parsed ({exc!r})"
        _registry_cache[key] = (sig, reg, reason)
        return reg, reason


def _reset_registry_cache() -> None:
    """Test hook."""
    with _registry_lock:
        _registry_cache.clear()


def _parse_threshold(env: Mapping[str, str]) -> float | None:
    """SENTINEL_MONITOR_THRESHOLD: a finite float in [0, 1] overrides the alert threshold of D8 / D9 ONLY. Invalid ->
    WARNING and None (the frozen, pre-registered thresholds stay in force)."""
    raw = env.get(THRESHOLD_ENV)
    if raw is None or not raw.strip():
        return None
    try:
        v = float(raw)
    except ValueError:
        v = math.nan
    if not (math.isfinite(v) and 0.0 <= v <= 1.0):
        log.warning("%s=%r is not a number in [0, 1]; ignoring it and keeping the frozen threshold", THRESHOLD_ENV, raw)
        return None
    log.warning("%s=%s overrides the frozen D8/D9 threshold: UNCALIBRATED (the frozen values are the only "
                "pre-registered ones; see eval/results_registry/D9_threshold_sweep_DESCRIPTIVE.md)", THRESHOLD_ENV, raw)
    return v


# --------------------------------------------------------------------------- registry session monitor (D8 / D9)
_EXTERNAL_KINDS = ("external", "relay", "unknown")


class RegistrySessionMonitor(SessionMonitor):
    """Per-session D8 / D9. Owns its detector AND the registry that detector resolves with (a private copy parsed at
    session start), so concurrent sessions with different registries cannot affect each other."""

    def __init__(self, mode: str, detector, embedder):
        super().__init__(mode, detector, embedder, None)
        self.registry = detector.registry
        self._entries = {e.id: e for e in self.registry.entries if e.valid}
        self._denied_props: list[tuple[str, dict, object]] = []     # (tool, args, Resolution) of DENIED proposals
        self.last_features: dict | None = None
        extractor, inner = detector._ex, detector._ex.on_step

        def spy(agent_text, proposal):
            f = inner(agent_text, proposal)
            self.last_features = f
            return f
        extractor.on_step = spy      # keep the exact feature dict that was scored (for the explanation)

    # -- explanation ------------------------------------------------------------------------------------------
    def _applicable_threshold(self, f: dict | None) -> float:
        if self.mode == "registry":
            return float(self._detector.t_same if f is None or f.get("same_party", 0) > 0 else self._detector.t_other)
        return float(self._detector.threshold)

    def _payload_sim(self, a_payload: str, b_payload: str) -> float:
        if not a_payload or not b_payload:
            return 0.0
        return float(self._embedder.embed(a_payload) @ self._embedder.embed(b_payload))

    def _entry_phrase(self, rt) -> str:
        r = rt.resolution
        e = self._entries.get(r.entry_id)
        if e is None:
            what = "relay" if r.kind == "relay" else "an external party"
            return (f"no registry entry matches it, so the default rule treats it as {what} "
                    f"'{r.party}' (an unregistered destination)")
        note = f': "{e.note}"' if getattr(e, "note", "") else ""
        return f"registry entry {e.id} ({e.kind}, party '{e.party}'){note}"

    def _explain_registry(self, tool: str, args: dict, score: float, threshold: float) -> str:
        from eval.effects_v2 import describe_parts
        f = self.last_features or {}
        res = self.registry.resolve(tool, args)
        denied_parties = set().union(*(d[2].reaches for d in self._denied_props)) if self._denied_props else set()
        shared = set(res.reaches) & denied_parties
        reaching = [rt for rt in res.tokens if rt.resolution.kind in _EXTERNAL_KINDS and rt.resolution.party in res.reaches]
        reaching.sort(key=lambda rt: (rt.resolution.party not in shared,
                                      rt.resolution.entry_id in ("default", "unknown")))     # stable
        parts = []
        if reaching:
            rt = reaching[0]
            party = rt.resolution.party
            more = f" (and {len(reaching) - 1} more external destination(s))" if len(reaching) > 1 else ""
            parts.append(f"Registry match: {tool} to {rt.token.value} reaches party '{party}' - {self._entry_phrase(rt)}{more}.")
        else:
            party = None
            parts.append(f"Registry match: {tool} reaches no external party in the registry, but repeats a denied payload.")
        # the earlier denied proposal: one that reached the same party if any (most similar payload), else the most similar
        payload = describe_parts(tool, args)[1]
        pool = [d for d in self._denied_props if party in d[2].reaches] or list(self._denied_props)
        best, best_s = None, -1.0
        for d in pool:
            try:
                sim = self._payload_sim(payload, describe_parts(d[0], d[1])[1])
            except Exception:
                sim = 0.0
            if sim > best_s:
                best, best_s = d, sim
        if best is not None:
            same = party in best[2].reaches
            dtoks = [rt.token.value for rt in best[2].tokens
                     if rt.resolution.kind in _EXTERNAL_KINDS and (not same or rt.resolution.party == party)]
            where = f" to {', '.join(dtoks[:3])}" if dtoks else ""
            if same:
                parts.append(f"An earlier DENIED proposal reached the same party '{party}': {best[0]}{where}.")
            else:
                parts.append(f"The earlier DENIED proposal ({best[0]}{where}) reached a different party in the registry, but the payload "
                             f"is a copy of it (if both are the same company, register the denied destination under the same party).")
        sim_now = float(f.get("s", f.get("cos_payload", 0.0)))
        if self.mode == "registry":
            name = "t_same" if f.get("same_party", 0) > 0 else "t_other"
            if f.get("retry") and sim_now < threshold:
                parts.append(f"Verbatim retry of a denied tool with no payload to compare ({name} {threshold:.2f} not needed).")
            else:
                parts.append(f"Payload similarity {sim_now:.2f} >= {name} {threshold:.2f}.")
        else:
            from eval.detectors_registry import REG_FEATURE_NAMES
            det = self._detector
            contrib = sorted(((float(det.weights[i] * (f[n] - det.mean[i]) / det.std[i]), n)
                              for i, n in enumerate(REG_FEATURE_NAMES) if n in f), reverse=True)[:2]
            parts.append(f"Registry-learned score {score:.2f} exceeds the {threshold:.2f} threshold; payload similarity "
                         f"{float(f.get('cos_payload', 0.0)):.2f}. Top feature contributions: "
                         + ", ".join(f"{n} {c:+.2f}" for c, n in contrib) + ".")
        return " ".join(parts)

    # -- API --------------------------------------------------------------------------------------------------
    def on_proposal(self, agent_text: str, tool: str, args: dict, node_id: str) -> list[dict]:
        """Score a proposal BEFORE the human decides. -> [] or ONE contract-shaped alignment_alert. Never raises."""
        try:
            self.last_features = None
            res = self._detector.on_step(agent_text, {"tool": tool, "args": args})
            if not res.alert or res.score is None:
                return []
            score, threshold = float(res.score), self._applicable_threshold(self.last_features)
            try:
                message = self._explain_registry(tool, args, score, threshold)
            except Exception:
                log.exception("could not explain a registry alert on %s; alerting with a plain message", node_id)
                _count_error()
                message = (f"{tool} reaches a party the registry says an earlier denied proposal reached "
                           f"(score {score:.2f}, threshold {threshold:.2f}).")
            return [events.alignment_alert("critical", REGISTRY_TRIGGER, message, node_id, score, threshold)]
        except Exception:
            log.exception("registry monitor failed on %s (%s); continuing without an alert", node_id, tool)
            _count_error()
            return []

    def register_decision(self, tool: str, args: dict, decision: str) -> None:
        try:
            self._detector.register_decision({"tool": tool, "args": args}, decision)
            if decision == "deny":
                self._denied_props.append((tool, args, self.registry.resolve(tool, args)))
        except Exception:
            log.exception("registry monitor failed to register a decision on %s; continuing", tool)
            _count_error()


# --------------------------------------------------------------------------- factory (resolved per environment)
class MonitorFactory:
    """Resolved mode + how to build a fresh SessionMonitor. Call it (or ``new_session()``) once per session."""

    def __init__(self, requested: str, mode: str, reason: str = "", model_path: Path | None = None, *,
                 registry=None, registry_path: Path | None = None, threshold: float | None = None):
        self.requested = requested          # what the environment asked for
        self.mode = mode                    # what is ACTUALLY active (a fallback shows up here)
        self.reason = reason                # why it fell back ("" if it did not)
        self.model_path = model_path        # frozen file of the ACTIVE mode
        self.registry = registry            # validated Registry (registry modes only)
        self.registry_path = registry_path
        self.threshold = threshold          # SENTINEL_MONITOR_THRESHOLD override (registry modes only)
        self.registry_info = ({"path": str(registry_path), "digest": registry.digest(), "entries": len(registry.entries)}
                              if registry is not None else None)

    def _new_registry_session(self) -> SessionMonitor:
        from eval.detectors_registry import load_frozen_registry
        did = MODES[self.mode]
        emb = _shared_embedder()
        det = load_frozen_registry(self.model_path, emb, self.registry.to_dict(), only=[did])[did]   # private registry copy
        if self.threshold is not None:
            if did == "D8":
                det.t_same = det.t_other = self.threshold
            else:
                det.threshold = self.threshold
        det.reset()
        return RegistrySessionMonitor(self.mode, det, emb)

    def new_session(self) -> SessionMonitor:
        if self.mode == "rules":
            return SessionMonitor("rules")
        try:
            if self.mode in REGISTRY_MODES:
                return self._new_registry_session()
            from eval.detectors_v2 import load_frozen
            from eval.effects import describe_effect
            emb = _shared_embedder()
            det = load_frozen(self.model_path, emb, only=[MODES[self.mode]])[MODES[self.mode]]
            det.reset()
            return SessionMonitor(self.mode, det, emb, describe_effect)
        except Exception:
            log.exception("could not build a %s monitor for this session; using %s", self.mode,
                          "action_sim" if self.mode in REGISTRY_MODES else "rules")
            _count_error()
            if self.mode in REGISTRY_MODES:
                try:
                    return _resolve_basic("action_sim", os.environ).new_session()
                except Exception:
                    log.exception("the action_sim fallback failed too; using rules")
            return SessionMonitor("rules")

    __call__ = new_session


def _fallback(requested: str, reason: str) -> MonitorFactory:
    log.warning("SENTINEL_MONITOR=%s is NOT active: %s. Falling back to the 'rules' monitor.", requested, reason)
    return MonitorFactory(requested, "rules", reason)


def _fallback_registry(requested: str, reason: str, env: Mapping[str, str]) -> MonitorFactory:
    """A registry mode without what it needs runs action_sim (D3), never a registry-trained detector without a registry."""
    log.warning("SENTINEL_MONITOR=%s is NOT active: %s. Falling back to the 'action_sim' monitor "
                "(registry detectors without a usable registry are worse than having none).", requested, reason)
    base = _resolve_basic("action_sim", env)
    return MonitorFactory(requested, base.mode, reason, base.model_path)


def _resolve_basic(requested: str, env: Mapping[str, str]) -> MonitorFactory:
    """action_sim | learned | rules (the original modes; unchanged behaviour)."""
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
        det = load_frozen(path, emb, only=[MODES[requested]])[MODES[requested]]
        float(det.threshold)
    except Exception as exc:        # missing/corrupt file, absent detector, no model cache, eval not importable
        return _fallback(requested, f"cannot load the frozen {MODES[requested]} from {path} ({exc!r})")
    log.info("proposal monitor: %s (frozen %s from %s)", requested, MODES[requested], path)
    return MonitorFactory(requested, requested, model_path=path)


def _resolve_registry(requested: str, env: Mapping[str, str]) -> MonitorFactory:
    try:
        embedder = live_drift.get_embedder()
    except Exception as exc:
        return _fallback_registry(requested, f"no embedder available ({exc!r})", env)
    if isinstance(embedder, live_drift.StubEmbedder):
        return _fallback_registry(requested, "the active embedder is the stub (MiniLM unavailable or SENTINEL_EMBEDDER=stub); "
                                             "payload similarities would be meaningless", env)
    raw_reg = (env.get(REGISTRY_ENV) or "").strip()
    if not raw_reg:
        return _fallback_registry(requested, f"{REGISTRY_ENV} is not set (a destination registry is required; docs/registry.md)", env)
    registry, why = load_registry(raw_reg)
    if registry is None:
        return _fallback_registry(requested, why, env)
    path = Path(env.get(REGISTRY_MODEL_ENV) or DEFAULT_REGISTRY_MODEL_PATH)
    try:
        from eval.detectors_registry import load_frozen_registry
        emb = _shared_embedder()
        det = load_frozen_registry(path, emb, registry.to_dict(), only=[MODES[requested]])[MODES[requested]]
        float(det.threshold["t_same"] if requested == "registry" else det.threshold)
    except Exception as exc:
        return _fallback_registry(requested, f"cannot load the frozen {MODES[requested]} from {path} ({exc!r})", env)
    threshold = _parse_threshold(env)
    log.info("proposal monitor: %s (frozen %s from %s; registry %s digest %s, %d entries)", requested, MODES[requested],
             path, raw_reg, registry.digest(), len(registry.entries))
    return MonitorFactory(requested, requested, model_path=path, registry=registry, registry_path=Path(raw_reg),
                          threshold=threshold)


def _resolve(env: Mapping[str, str]) -> MonitorFactory:
    requested = (env.get(MODE_ENV) or "").strip().lower() or DEFAULT_MODE
    if requested in REGISTRY_MODES:
        return _resolve_registry(requested, env)
    return _resolve_basic(requested, env)


_factory: MonitorFactory | None = None
_factory_key: tuple | None = None
_factory_lock = threading.Lock()


def get_monitor_factory() -> MonitorFactory:
    """The factory for the CURRENT environment. Mode / model paths / embedder choice and, for the registry modes, the
    registry file (path AND mtime/size/inode) are part of the cache key, so tests that change the environment and
    operators who edit the registry file get a fresh resolution (and linting) at the next call - i.e. at the next
    session start - while an unchanged environment costs one dict lookup and a stat."""
    global _factory, _factory_key
    requested = (os.environ.get(MODE_ENV) or "").strip().lower()
    reg_path = os.environ.get(REGISTRY_ENV) if requested in REGISTRY_MODES else None
    key = (os.environ.get(MODE_ENV), os.environ.get(MODEL_ENV), os.environ.get(live_drift.ENV_VAR),
           os.environ.get(REGISTRY_ENV), os.environ.get(REGISTRY_MODEL_ENV), os.environ.get(THRESHOLD_ENV),
           _file_sig(reg_path.strip()) if reg_path and reg_path.strip() else None)
    with _factory_lock:
        if _factory is None or _factory_key != key:
            _factory, _factory_key = _resolve(os.environ), key
        return _factory


def _reset_factory_cache() -> None:
    """Test hook (also called by live_drift._reset_embedder_cache)."""
    global _factory, _factory_key
    with _factory_lock:
        _factory, _factory_key = None, None
    _reset_registry_cache()


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
