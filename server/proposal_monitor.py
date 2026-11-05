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
  eval/results_registry/frozen_registry_models.json). The registry is loaded and linted at every session start (cached by the
  sha256 of its CONTENT, not its mtime), so edits apply to the NEXT session without a restart. Without a usable registry
  (unset / missing / unparseable / lint errors) or a missing frozen file they fall back LOUDLY to ``action_sim`` (with the stub
  embedder ``action_sim`` cannot run either: the chain ends at ``rules``) and never to a
  registry-trained detector without a registry (evaluation: D9 without a registry 16.7% on-time vs 37.5% for D7).
  Alerts: severity ``critical``, trigger ``registry_denied_party_match``, with a message that names the destination, the
  registry entry and its note, the party, the earlier denied proposal that reached the same party and the scores.
* ``registry_learned_e`` (eval D9b) and ``registry_learned_dropout`` (eval D9c), DECISIONS.md D10 (v3 fresh holdout,
  PROVISIONAL verdict): same registry handling and the SAME fallback chain, but the frozen models come from
  SENTINEL_REGISTRY_MODEL_V3 (default eval/results_registry_v3/frozen_registry_models_v3.json, loaded with
  ``eval.detectors_registry_v3.load_frozen_registry_v3``; a missing / corrupt / wrong-``schema_version`` file falls back
  too). In v3 these detectors were USELESS without a registry (on-time 0% vs 36.7% for action_sim), so the fallback to
  ``action_sim`` is mandatory: it also applies to a valid registry with no entries (equivalent to no registry). Their
  alerts end with the line ``Monitor: <mode> (frozen, provisional: see DECISIONS D10)``.
  SENTINEL_MONITOR_THRESHOLD (float in [0, 1]) overrides the alert threshold of EVERY registry mode (D8's two thresholds, D9,
  D9b, D9c): UNCALIBRATED, for operators who accept that the frozen values are the only pre-registered ones.

Alert text safety (B1): every string an agent or a registry can influence is passed through ``safe_text.clean_field`` (one line,
control / bidi / zero-width characters gone, length-limited with an ellipsis) BEFORE it is interpolated into any message, in
every monitor; the only newline in an alert is the one this module writes before the final ``Monitor:`` line of the v3 modes.

The detectors are imported from ``eval/`` (frozen, scored) and loaded from the frozen model file with
``eval.detectors_v2.load_frozen`` so the live thresholds / weights ARE the evaluated ones.

Failure policy: loud but never fatal. A mode that needs embeddings with the stub embedder active, a missing/corrupt
frozen file, an unknown mode name, or an import failure -> WARNING and the factory degrades to ``rules`` (registry modes:
``action_sim``, then ``rules``; ``/health`` reports the ACTIVE monitor). Only the EXPECTED error family (OSError, ValueError
incl. JSON errors and FrozenRegistryError, KeyError) is turned into a fallback reason; any other exception is a programming
error: it is logged with its real type and traceback, counted in ``monitor_errors`` and the factory still degrades loudly.
A session that cannot be built degrades per session and is counted in ``session_fallbacks`` (``last_session_fallback``). A runtime exception inside a monitor is logged, counted in
``error_count()`` (``monitor_errors`` on /health) and the proposal simply goes to the human without an alert.

Sync and CPU-bound (embedding); callers wrap ``on_proposal`` / ``register_decision`` in ``asyncio.to_thread``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import shutil
import sys
import tempfile
import threading
import weakref
from pathlib import Path
from typing import Mapping

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

import events  # noqa: E402
import live_drift  # noqa: E402
import safe_text  # noqa: E402
from safe_text import clean_field  # noqa: E402

log = logging.getLogger(__name__)

MODE_ENV = "SENTINEL_MONITOR"
MODEL_ENV = "SENTINEL_MONITOR_MODEL"
REGISTRY_ENV = "SENTINEL_REGISTRY"
REGISTRY_MODEL_ENV = "SENTINEL_REGISTRY_MODEL"
REGISTRY_MODEL_V3_ENV = "SENTINEL_REGISTRY_MODEL_V3"
THRESHOLD_ENV = "SENTINEL_MONITOR_THRESHOLD"
DEFAULT_MODE = "action_sim"
DEFAULT_MODEL_PATH = _REPO_ROOT / "eval" / "results_v2" / "frozen_models.json"
DEFAULT_REGISTRY_MODEL_PATH = _REPO_ROOT / "eval" / "results_registry" / "frozen_registry_models.json"
DEFAULT_REGISTRY_MODEL_V3_PATH = _REPO_ROOT / "eval" / "results_registry_v3" / "frozen_registry_models_v3.json"
TRIGGER = "denied_effect_match"
REGISTRY_TRIGGER = "registry_denied_party_match"

# mode -> id of the frozen detector in frozen_models.json / frozen_registry_models.json (None: rules path)
MODES = {"action_sim": "D3", "learned": "D7", "rules": None, "registry": "D8", "registry_learned": "D9",
         "registry_learned_e": "D9b", "registry_learned_dropout": "D9c",
         "registry_learned_dropout_or_action": "D9c"}
# D9c OR D3 (DECISIONS.md D13): alert iff the registry detector OR action similarity alerts. Post-hoc design; missed the FA(c) bar.
UNION_MODE = "registry_learned_dropout_or_action"
V3_MODES = ("registry_learned_e", "registry_learned_dropout", UNION_MODE)     # frozen v3 file (PROVISIONAL, DECISIONS.md D10)
REGISTRY_MODES = ("registry", "registry_learned") + V3_MODES


def monitor_line(mode: str) -> str:
    return f"Monitor: {mode} (frozen, provisional: see DECISIONS D10)"


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


_session_fallbacks = 0
_last_fallback: str | None = None


def _record_session_fallback(mode: str, used: str, exc: BaseException) -> None:
    """A session degraded per-session to ``used`` (the factory itself still reports ``mode``): count it and remember why,
    so /health shows it (``session_fallbacks`` / ``last_session_fallback``)."""
    global _session_fallbacks, _last_fallback
    reason = clean_field(f"{mode} -> {used}: {type(exc).__name__}: {exc}", safe_text.REASON)
    with _errors_lock:
        _session_fallbacks += 1
        _last_fallback = reason


def session_fallback_info() -> tuple[int, str | None]:
    """(number of sessions that fell back per-session since process start, reason of the last one or None)."""
    with _errors_lock:
        return _session_fallbacks, _last_fallback


def _reset_errors() -> None:
    """Test hook (also resets the per-session fallback counter)."""
    global _errors, _session_fallbacks, _last_fallback
    with _errors_lock:
        _errors = 0
        _session_fallbacks = 0
        _last_fallback = None


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
        # B1: both strings embed agent-controlled tool names / arguments: one clean, length-limited line each
        effect = clean_field(effect, safe_text.EFFECT) if effect else effect
        denied = clean_field(denied, safe_text.EFFECT) if denied else denied
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


# --------------------------------------------------------------------------- registry file (content-hash cached)
_registry_cache: dict[str, tuple] = {}        # path -> (sha256 of the bytes, Registry | None, reason)
_registry_lock = threading.Lock()


def _read_with_sig(path) -> tuple[bytes | None, str | None]:
    """(bytes, sha256 hex) of a small file, (None, None) if it cannot be read. The signature is a CONTENT hash on purpose:
    mtime / size / inode miss a same-size edit whose mtime was restored (``cp -p``, ``rsync -t``, ``tar x``, two writes in
    one timestamp tick). Registries and frozen models are a few KB, so reading them at every session start is cheap."""
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None, None
    return raw, hashlib.sha256(raw).hexdigest()


def _content_sig(path) -> str | None:
    """sha256 (hex) of the file's current bytes, None if it cannot be read."""
    return _read_with_sig(path)[1]


def load_registry(path: str | os.PathLike) -> tuple["object | None", str]:
    """-> (Registry, "") or (None, reason). Parsed and LINTED again whenever the file's CONTENT (sha256) changed (so an
    operator edit applies to the next session start, no restart); lint errors reject the whole registry and are logged one
    by one. The bytes that were hashed are the bytes that are parsed (no stat-then-read race).

    Expected failures (unreadable file, not UTF-8 / not JSON / not an object, a structure the loader refuses) become a reason
    string; anything else is a programming error and PROPAGATES (``_resolve`` logs it with its real type, counts it in
    ``monitor_errors`` and falls back loudly)."""
    from server.registry import Registry                      # the module eval.detectors_registry uses (same class)
    key = str(path)
    raw, sig = _read_with_sig(key)
    with _registry_lock:
        hit = _registry_cache.get(key)
        if hit is not None and sig is not None and hit[0] == sig:
            return hit[1], hit[2]
        reg, reason = None, ""
        if raw is None:
            reason = f"registry file {key} does not exist or cannot be read"
        else:
            try:
                data = json.loads(raw.decode("utf-8"))        # UnicodeDecodeError / JSONDecodeError are ValueErrors
                if not isinstance(data, dict):
                    raise ValueError("registry must be a JSON object")
                cand = Registry.load(data)
                errors = cand.validate()
            except (OSError, ValueError, KeyError) as exc:     # unparseable / not an object / refused structure
                reason = clean_field(f"registry {key} cannot be parsed ({type(exc).__name__}: {exc})", safe_text.REASON)
            else:
                for w in cand.warnings():
                    log.info("registry %s: warning: %s", key, clean_field(w, safe_text.REASON))
                if errors:
                    for e in errors:
                        log.warning("registry %s: lint error: %s", key, clean_field(e, safe_text.REASON))
                    reason = clean_field(f"registry {key} has {len(errors)} lint error(s) (first: {errors[0]}); "
                                         f"fix it (python -m registry_cli lint) - it was rejected", safe_text.REASON)
                else:
                    reg = cand
        _registry_cache[key] = (sig, reg, reason)
        return reg, reason


def _reset_registry_cache() -> None:
    """Test hook."""
    with _registry_lock:
        _registry_cache.clear()


def _parse_threshold(env: Mapping[str, str]) -> float | None:
    """SENTINEL_MONITOR_THRESHOLD: a finite float in [0, 1] overrides the alert threshold of the registry modes (D8 / D9 / D9b /
    D9c; never action_sim / learned). Invalid ->
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
    log.warning("%s=%s overrides the frozen D8/D9/D9b/D9c threshold: UNCALIBRATED (the frozen values are the only "
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
                    f"'{clean_field(r.party, safe_text.PARTY)}' (an unregistered destination)")
        note = clean_field(e.note, safe_text.NOTE) if getattr(e, "note", "") else ""
        note = f': "{note}"' if note else ""
        return (f"registry entry {clean_field(e.id, safe_text.ID)} ({clean_field(e.kind, safe_text.KIND)}, "
                f"party '{clean_field(e.party, safe_text.PARTY)}'){note}")

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
        tool_s = clean_field(tool, safe_text.TOOL)           # B1: every interpolated field below is cleaned first
        if reaching:
            rt = reaching[0]
            party = rt.resolution.party
            more = f" (and {len(reaching) - 1} more external destination(s))" if len(reaching) > 1 else ""
            parts.append(f"Registry match: {tool_s} to {clean_field(rt.token.value, safe_text.TOKEN)} reaches party "
                         f"'{clean_field(party, safe_text.PARTY)}' - {self._entry_phrase(rt)}{more}.")
        else:
            party = None
            parts.append(f"Registry match: {tool_s} reaches no external party in the registry, but repeats a denied payload.")
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
            where = f" to {safe_text.clean_list(dtoks, safe_text.TOKEN, 3)}" if dtoks else ""
            denied_tool = clean_field(best[0], safe_text.TOOL)
            if same:
                parts.append(f"An earlier DENIED proposal reached the same party '{clean_field(party, safe_text.PARTY)}': "
                             f"{denied_tool}{where}.")
            else:
                parts.append(f"The earlier DENIED proposal ({denied_tool}{where}) reached a different party in the registry, but the payload "
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
                         + ", ".join(f"{clean_field(n, safe_text.FEATURE)} {c:+.2f}" for c, n in contrib) + ".")
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
                message = (f"{clean_field(tool, safe_text.TOOL)} reaches a party the registry says an earlier denied proposal reached "
                           f"(score {score:.2f}, threshold {threshold:.2f}).")
            if self.mode in V3_MODES:
                message += "\n" + monitor_line(self.mode)
            return [events.alignment_alert("critical", REGISTRY_TRIGGER, message, node_id, score, threshold)]
        except Exception:
            log.exception("registry monitor failed on %s (%s); continuing without an alert", node_id, tool)
            _count_error()
            return []

    def register_decision(self, tool: str, args: dict, decision: str) -> None:
        """Record the EFFECTIVE decision ('approve' | 'deny'; a timeout, forged or duplicate approve is a deny) in BOTH the
        detector and the explanation state. Never raises; a failure of either half is logged by name."""
        try:
            self._detector.register_decision({"tool": tool, "args": args}, decision)
        except Exception:
            log.exception("registry monitor: the DETECTOR failed to register a %s on %s; continuing", decision, tool)
            _count_error()
        if decision == "deny":
            try:
                self._denied_props.append((tool, args, self.registry.resolve(tool, args)))
            except Exception:
                log.exception("registry monitor: the EXPLANATION state failed to record a deny on %s; continuing", tool)
                _count_error()


class UnionSessionMonitor(RegistrySessionMonitor):
    """D9c OR D3 for ONE session. Both members see every proposal and every decision (consistent state); at most ONE alert is
    returned per proposal: the registry member's (it names the party) if it fired, else action similarity's."""

    def __init__(self, mode: str, detector, embedder, action_monitor: SessionMonitor):
        super().__init__(mode, detector, embedder)
        self._action = action_monitor

    def on_proposal(self, agent_text: str, tool: str, args: dict, node_id: str) -> list[dict]:
        reg_alerts = super().on_proposal(agent_text, tool, args, node_id)
        act_alerts = self._action.on_proposal(agent_text, tool, args, node_id)      # never raises
        if reg_alerts:
            return reg_alerts
        for a in act_alerts:
            a["message"] = a["message"] + "\n" + monitor_line(self.mode)
        return act_alerts[:1]

    def register_decision(self, tool: str, args: dict, decision: str) -> None:
        super().register_decision(tool, args, decision)
        self._action.register_decision(tool, args, decision)                        # never raises


def _load_action_monitor(model_path: Path, emb) -> SessionMonitor:
    from eval.detectors_v2 import load_frozen
    from eval.effects import describe_effect
    det = load_frozen(model_path, emb, only=["D3"])["D3"]
    det.reset()
    return SessionMonitor("action_sim", det, emb, describe_effect)


# --------------------------------------------------------------------------- factory (resolved per environment)
class MonitorFactory:
    """Resolved mode + how to build a fresh SessionMonitor. Call it (or ``new_session()``) once per session."""

    def __init__(self, requested: str, mode: str, reason: str = "", model_path: Path | None = None, *,
                 registry=None, registry_path: Path | None = None, threshold: float | None = None,
                 frozen_model: dict | None = None, frozen_copy: Path | None = None, action_model_path: Path | None = None):
        self.requested = requested          # what the environment asked for
        self.mode = mode                    # what is ACTUALLY active (a fallback shows up here)
        self.reason = reason                # why it fell back ("" if it did not)
        self.model_path = model_path        # frozen file of the ACTIVE mode
        self.registry = registry            # validated Registry (registry modes only)
        self.registry_path = registry_path
        self.threshold = threshold          # SENTINEL_MONITOR_THRESHOLD override (D8 / D9 / D9b / D9c only)
        self.frozen_model = frozen_model    # {"path", "sha256" (prefix), "schema_version"} of the frozen file (registry modes)
        self.action_model_path = action_model_path      # frozen file of the D3 member (union mode only)
        self.frozen_copy = frozen_copy      # private snapshot of exactly the bytes frozen_model describes (registry modes)
        self.registry_info = ({"path": str(registry_path), "digest": registry.digest(), "entries": len(registry.entries)}
                              if registry is not None else None)
        if frozen_copy is not None:         # the snapshot lives exactly as long as the factory
            weakref.finalize(self, shutil.rmtree, str(frozen_copy.parent), True)

    def _new_registry_session(self) -> SessionMonitor:
        did = MODES[self.mode]
        emb = _shared_embedder()
        # the SNAPSHOT, not the live path: the session runs the very bytes /health reported (one resolution step)
        det = _frozen_loader(self.mode)(self.frozen_copy, emb, self.registry.to_dict(), only=[did])[did]   # private registry copy
        if self.threshold is not None:
            if did == "D8":
                det.t_same = det.t_other = self.threshold
            else:
                det.threshold = self.threshold
        det.reset()
        if self.mode == UNION_MODE:
            return UnionSessionMonitor(self.mode, det, emb, _load_action_monitor(self.action_model_path, emb))
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
        except Exception as exc:       # broad on purpose: whatever breaks a session build must never kill the session
            used = "action_sim" if self.mode in REGISTRY_MODES else "rules"
            log.exception("could not build a %s monitor for this session (%s); using %s", self.mode,
                          type(exc).__name__, used)
            _count_error()
            _record_session_fallback(self.mode, used, exc)       # /health: session_fallbacks + last_session_fallback
            if self.mode in REGISTRY_MODES:
                try:
                    return _resolve_basic("action_sim", os.environ).new_session()
                except Exception:
                    log.exception("the action_sim fallback failed too; using rules")
            return SessionMonitor("rules")

    __call__ = new_session


def _frozen_loader(mode: str):
    """The loader of the frozen file of a registry mode: v3 (D9b / D9c, strict schema_version) or the D8 / D9 one."""
    if mode in V3_MODES:
        from eval.detectors_registry_v3 import load_frozen_registry_v3
        return load_frozen_registry_v3
    from eval.detectors_registry import load_frozen_registry
    return load_frozen_registry


def _snapshot_frozen(path: Path) -> tuple[Path, dict]:
    """Read the frozen model file ONCE -> (private copy of exactly those bytes, {"path", "sha256": first 16 hex of the
    bytes, "schema_version"}). /health reports the info and every session of the factory loads the copy, so the model that
    is reported is the model that runs even if the file is replaced afterwards (the next ``get_monitor_factory`` call sees
    the new content hash in the cache key and resolves again). Raises OSError / ValueError for a missing or corrupt file."""
    raw = Path(path).read_bytes()
    blob = json.loads(raw.decode("utf-8"))
    if not isinstance(blob, dict):
        raise ValueError(f"{path}: the frozen model file must be a JSON object")
    d = Path(tempfile.mkdtemp(prefix="sentinel-frozen-"))
    try:
        copy = d / "frozen.json"
        copy.write_bytes(raw)
    except BaseException:
        shutil.rmtree(d, ignore_errors=True)
        raise
    return copy, {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()[:16],
                  "schema_version": blob.get("schema_version")}


def _fallback(requested: str, reason: str) -> MonitorFactory:
    reason = clean_field(reason, safe_text.REASON)        # the reason is logged and may embed file / agent text
    log.warning("SENTINEL_MONITOR=%s is NOT active: %s. Falling back to the 'rules' monitor.", requested, reason)
    return MonitorFactory(requested, "rules", reason)


def _fallback_registry(requested: str, reason: str, env: Mapping[str, str]) -> MonitorFactory:
    """A registry mode without what it needs runs action_sim (D3), never a registry-trained detector without a registry."""
    reason = clean_field(reason, safe_text.REASON)
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
    except (OSError, ValueError, KeyError) as exc:        # missing / corrupt file, absent detector, refused feature set
        return _fallback(requested, clean_field(f"cannot load the frozen {MODES[requested]} from {path} "
                                                f"({type(exc).__name__}: {exc})", safe_text.REASON))
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
    if requested in V3_MODES and not registry.entries:
        return _fallback_registry(requested, f"registry {raw_reg} has no entries (the v3 detectors are useless without "
                                             f"registry entries: 0% on-time in the evaluation)", env)
    path = _model_path(requested, env)
    from eval.detectors_registry_v3 import FrozenRegistryError     # (a ValueError; listed for the reader)
    copy = None
    try:
        copy, frozen = _snapshot_frozen(path)
        emb = _shared_embedder()
        det = _frozen_loader(requested)(copy, emb, registry.to_dict(), only=[MODES[requested]])[MODES[requested]]
        float(det.threshold["t_same"] if requested == "registry" else det.threshold)
        action_path = None
        if requested == UNION_MODE:       # the D3 member must load too, else the whole mode falls back (never half a union)
            action_path = Path(env.get(MODEL_ENV) or DEFAULT_MODEL_PATH)
            _load_action_monitor(action_path, emb)
    except (OSError, ValueError, KeyError, FrozenRegistryError, json.JSONDecodeError) as exc:
        # missing / unreadable / corrupt / wrong-schema frozen file. NOT caught here: programming errors (TypeError,
        # AttributeError, ImportError, ...): they reach ``_resolve``, which logs them with their real type and counts them.
        if copy is not None:
            shutil.rmtree(copy.parent, ignore_errors=True)
        return _fallback_registry(requested, clean_field(f"cannot load the frozen {MODES[requested]} from {path} "
                                                         f"({type(exc).__name__}: {exc})", safe_text.REASON), env)
    except BaseException:
        if copy is not None:
            shutil.rmtree(copy.parent, ignore_errors=True)
        raise
    threshold = _parse_threshold(env)
    log.info("proposal monitor: %s (frozen %s from %s; registry %s digest %s, %d entries)", requested, MODES[requested],
             path, raw_reg, registry.digest(), len(registry.entries))
    return MonitorFactory(requested, requested, model_path=path, registry=registry, registry_path=Path(raw_reg),
                          threshold=threshold, frozen_model=frozen, frozen_copy=copy, action_model_path=action_path)


def _model_path(requested: str, env: Mapping[str, str]) -> Path | None:
    """The frozen model file the requested mode reads (None: rules / unknown). ONE place, used by the resolution AND by the
    factory cache key, so the two can never disagree."""
    if requested in V3_MODES:
        return Path(env.get(REGISTRY_MODEL_V3_ENV) or DEFAULT_REGISTRY_MODEL_V3_PATH)
    if requested in REGISTRY_MODES:
        return Path(env.get(REGISTRY_MODEL_ENV) or DEFAULT_REGISTRY_MODEL_PATH)
    if requested in MODES and requested != "rules":
        return Path(env.get(MODEL_ENV) or DEFAULT_MODEL_PATH)
    return None


def _resolve(env: Mapping[str, str]) -> MonitorFactory:
    requested = (env.get(MODE_ENV) or "").strip().lower() or DEFAULT_MODE
    try:
        if requested in REGISTRY_MODES:
            return _resolve_registry(requested, env)
        return _resolve_basic(requested, env)
    except Exception as exc:
        # A PROGRAMMING error (the loaders above only swallow the expected OSError / ValueError / KeyError family). Still never
        # fatal: it is logged with its real type and traceback, counted in monitor_errors and the factory degrades loudly.
        log.exception("unexpected %s while resolving SENTINEL_MONITOR=%s", type(exc).__name__, requested)
        _count_error()
        why = clean_field(f"unexpected {type(exc).__name__}: {exc}", safe_text.REASON)
        try:
            if requested in REGISTRY_MODES:
                return _fallback_registry(requested, why, env)
            return _fallback(requested, why)
        except Exception:
            log.exception("the fallback failed too; using rules")
            return MonitorFactory(requested, "rules", why)


_factory: MonitorFactory | None = None
_factory_key: tuple | None = None
_factory_lock = threading.Lock()


def get_monitor_factory() -> MonitorFactory:
    """The factory for the CURRENT environment. Mode / model paths / embedder choice and the CONTENT HASHES (sha256) of the
    registry file (registry modes) and of the frozen model file the mode reads are part of the cache key, so tests that
    change the environment, operators who edit the registry and a replaced frozen model get a fresh resolution (and linting)
    at the next call - i.e. at the next session start - while an unchanged environment costs a read and a hash of two
    small files."""
    global _factory, _factory_key
    requested = (os.environ.get(MODE_ENV) or "").strip().lower()
    reg_path = os.environ.get(REGISTRY_ENV) if requested in REGISTRY_MODES else None
    model = _model_path(requested or DEFAULT_MODE, os.environ)
    key = (os.environ.get(MODE_ENV), os.environ.get(MODEL_ENV), os.environ.get(live_drift.ENV_VAR),
           os.environ.get(REGISTRY_ENV), os.environ.get(REGISTRY_MODEL_ENV), os.environ.get(REGISTRY_MODEL_V3_ENV),
           os.environ.get(THRESHOLD_ENV),
           _content_sig(reg_path.strip()) if reg_path and reg_path.strip() else None,
           _content_sig(model) if model is not None else None)
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
