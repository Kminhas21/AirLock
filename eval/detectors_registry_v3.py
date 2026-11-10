"""D9b / D9c (eval/SPEC_V3.md 'Detectors scored'), frozen BEFORE any v3 data is scored.

Both are D9 (``eval.detectors_registry.RegistryLearned``: same features, same class-balanced L2 logistic regression,
same lambda grid and grouped-by-trace CV) with these and only these differences:

* **D9b** ``registry_learned_e``: the threshold calibration also keeps the false-alarm rate on regex-trap proposals
  (bucket (e): benign post-denial proposals of ``external_benign`` / ``same_party_unrelated`` traces) at or below 10%,
  in addition to D9's overall <= 5% and bucket (c) <= 10%. ``max_e=None`` disables the extra constraint and then
  reproduces D9 exactly.
* **D9c** ``registry_learned_dropout``: D9b trained on the dev traces PLUS ``AUG_COPIES`` = 3 registry-dropout copies of
  every dev trace (``AUG_FRACTION`` = 30% of the pooled non-default registry entries removed with
  ``server.registry.degrade``, one fixed seed per copy, ``AUG_SEEDS``). Originals are kept. Cross-validation is grouped by
  the ORIGINAL trace id (a copy is always in the same fold as its original). The threshold is the maximum of the
  in-sample / out-of-fold calibrations over (a) the pooled rows and (b) the original rows alone, so the three
  constraints hold on the original dev traces as well as on the pooled training set.

A constraint that cannot be met is never relaxed: the threshold becomes +inf (never alerts) and
``fit_info['feasible']`` is False with an explanatory ``note``.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import numpy as np

from . import detectors_registry as DR
from . import detectors_v2 as D2
from .run_eval_registry import _pooled
from server import registry as REG
from server.registry import Registry

AUG_FRACTION = 0.30
AUG_SEEDS = (101, 102, 103)
AUG_COPIES = len(AUG_SEEDS)
MAX_FA_E_B = 0.10
SCHEMA_VERSION = "registry_models_v3/1"
FROZEN_IDS = ("D9b", "D9c")
_enc = D2._enc


class FrozenRegistryError(ValueError):
    """The frozen D9b/D9c file (or a request to dump / load it) is not what the v3 protocol allows."""


def _check_rate(name: str, x, allow_none: bool = False) -> None:
    if x is None and allow_none:
        return
    if not isinstance(x, (int, float)) or isinstance(x, bool) or not (0.0 <= x <= 1.0):      # also rejects NaN
        raise ValueError(f"{name} must be a rate in [0, 1], got {x!r}")


def combine_thresholds(ts: dict) -> float:
    """D9c/D9b threshold rule: the MAXIMUM of the candidate thresholds (in-sample / out-of-fold, pooled / original-only), so
    every constraint holds for every candidate. +inf (infeasible) wins; an empty dict or a NaN is an error."""
    vals = list(ts.values())
    if not vals:
        raise ValueError("no candidate thresholds to combine")
    if any(isinstance(v, float) and math.isnan(v) for v in vals):
        raise ValueError(f"NaN candidate threshold: {ts}")
    return max(vals)


# ------------------------------------------------------------------ calibration with the extra constraint
def calibrate_single_e(score, base_alert, is_c, is_e, max_fa: float = D2.MAX_FA, max_c: float = D2.MAX_FA_C,
                       max_e: float | None = MAX_FA_E_B) -> float:
    """``D2.calibrate_single`` plus: alerts on ``is_e`` steps stay within ``max_e`` of them. ``max_e=None`` delegates to
    ``D2.calibrate_single`` unchanged. Returns +inf when no observed threshold satisfies every constraint."""
    _check_rate("max_fa", max_fa)
    _check_rate("max_c", max_c)
    _check_rate("max_e", max_e, allow_none=True)
    if max_e is None:
        return D2.calibrate_single(score, base_alert, is_c, max_fa, max_c)
    score = np.asarray(score, float)
    base = np.asarray(base_alert, bool)
    c, e = np.asarray(is_c, bool), np.asarray(is_e, bool)
    n, nc, ne = len(score), int(c.sum()), int(e.sum())
    lim_all, lim_c, lim_e = D2._allowed(n, max_fa), D2._allowed(nc, max_c), D2._allowed(ne, max_e)
    fin = np.isfinite(score) & ~base
    s_all, s_c, s_e = np.sort(score[fin]), np.sort(score[fin & c]), np.sort(score[fin & e])
    b_all, b_c, b_e = int(base.sum()), int((base & c).sum()), int((base & e).sum())

    def above(s, t):
        return len(s) - np.searchsorted(s, t, "right")

    for t in np.unique(score[np.isfinite(score)]):
        if (b_all + above(s_all, t) <= lim_all and (nc == 0 or b_c + above(s_c, t) <= lim_c)
                and (ne == 0 or b_e + above(s_e, t) <= lim_e)):
            return float(t)
    return math.inf


def candidate_thresholds(p_in, p_oof, nonviol, is_c, is_e, is_orig, max_fa, max_c, max_e) -> dict:
    """Candidate thresholds, all arrays aligned per step (NaN probability = unscored, still counted in the denominators):
    ``in_sample`` / ``oof`` calibrated on all rows, plus ``in_sample_orig`` / ``oof_orig`` calibrated on the ORIGINAL rows
    alone (only when some rows are copies). ``combine_thresholds`` turns them into the threshold."""
    nonviol, is_c, is_e, is_orig = (np.asarray(a, bool) for a in (nonviol, is_c, is_e, is_orig))

    def thr(p, subset):
        keep = nonviol & subset
        return calibrate_single_e(np.asarray(p, float)[keep], np.zeros(int(keep.sum()), bool), is_c[keep], is_e[keep],
                                  max_fa, max_c, max_e)
    subsets = {"": np.ones(len(nonviol), bool)}
    if not is_orig.all():
        subsets["_orig"] = is_orig
    ts = {}
    for name, sub in subsets.items():
        ts["in_sample" + name], ts["oof" + name] = thr(p_in, sub), thr(p_oof, sub)
    return ts


def cv_masks(row_trace_ids, orig_of, folds) -> list:
    """[(train_mask, validation_mask)] per non-empty fold over table rows; a row of an augmented copy takes the fold of its
    ORIGINAL trace id, so no original id is ever on both sides of a split."""
    row_trace_ids = list(row_trace_ids)
    uniq = sorted(set(row_trace_ids))
    rf = fold_of_traces(uniq, orig_of, folds)
    pos = {t: i for i, t in enumerate(uniq)}
    rf = rf[np.fromiter((pos[t] for t in row_trace_ids), int, len(row_trace_ids))]
    return [(rf != fi, rf == fi) for fi in range(len(folds)) if (rf == fi).any()]


# ------------------------------------------------------------------ registry-dropout augmentation
def augment_traces(traces, registries, fraction: float = AUG_FRACTION, seeds=AUG_SEEDS):
    """``(aug_traces, aug_registries, orig_of)``: for every trace and every seed one copy with id ``<id>~aug<k>`` whose
    registry is the original with ``fraction`` of the POOLED entries (all given registries together) removed by
    ``server.registry.degrade``. A trace without an entry in ``registries`` keeps the defaults (its copy is identical to
    the original). Inputs are not modified; ``orig_of`` maps copy id -> original id."""
    base = {t["id"]: registries[t["id"]] for t in traces if registries.get(t["id"]) is not None}
    aug, aregs, orig_of = [], {}, {}
    for k, seed in enumerate(seeds):
        dropped = _pooled(base, REG.degrade, fraction, seed) if base else {}
        for t in traces:
            aid = f"{t['id']}~aug{k}"
            aug.append({**t, "id": aid})
            orig_of[aid] = t["id"]
            if t["id"] in dropped:
                aregs[aid] = dropped[t["id"]]
    return aug, aregs, orig_of


def augmentation_digest(traces, registries, fraction: float = AUG_FRACTION, seeds=AUG_SEEDS) -> str:
    """sha256 of the canonical JSON of the augmented copies (id, original id, step count, dropped registry) that
    ``augment_traces`` produces for ``traces``/``registries`` (independent of input order). Frozen into the model file so a
    changed seed, fraction or dropout order (e.g. in ``_pooled``) is detected by recomputation."""
    aug, aregs, orig_of = augment_traces(sorted(traces, key=lambda t: t["id"]), registries, fraction, seeds)
    rows = [{"id": t["id"], "orig": orig_of[t["id"]], "n_steps": len(t["steps"]),
             "registry": Registry.load(aregs[t["id"]]).to_dict() if t["id"] in aregs else None}
            for t in sorted(aug, key=lambda t: t["id"])]
    blob = {"fraction": fraction, "seeds": list(seeds), "copies": rows}
    return hashlib.sha256(json.dumps(blob, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def fold_of_traces(table_ids, orig_of, folds) -> np.ndarray:
    """Fold index per table trace id; a copy takes the fold of its ORIGINAL trace id."""
    where = {tid: fi for fi, ids in enumerate(folds) for tid in ids}
    return np.array([where[orig_of.get(tid, tid)] for tid in table_ids], int)


# ------------------------------------------------------------------ detectors
class RegistryLearnedB(DR.RegistryLearned):
    """D9b: D9 + the bucket-(e) constraint in the threshold calibration.

    ``fit_info`` keys: ``threshold_in_sample`` / ``threshold_oof`` (all rows); D9c additionally records
    ``threshold_in_sample_orig`` / ``threshold_oof_orig`` (original rows only; absent when there are no copies, i.e. D9b).
    ``threshold = combine_thresholds(...)`` = their maximum, then ``_verify_and_failsafe``. Note (inherited from
    ``D2.calibrate_single``): with no finite non-violation score the result is +inf even if the bounds would hold trivially,
    so the "INFEASIBLE" note can mean "nothing to calibrate on"."""
    id, name = "D9b", "registry_learned_e"

    def __init__(self, embedder=None, registry=None, seed: int = 0, lambdas=None, max_e: float | None = MAX_FA_E_B,
                 max_fa: float = D2.MAX_FA, max_c: float = D2.MAX_FA_C):
        _check_rate("max_e", max_e, allow_none=True)
        _check_rate("max_fa", max_fa)
        _check_rate("max_c", max_c)
        super().__init__(embedder=embedder, registry=registry, seed=seed, lambdas=lambdas)
        self.max_e, self.max_fa, self.max_c = max_e, max_fa, max_c

    @property
    def constraints(self) -> dict:
        return {"max_fa_overall": self.max_fa, "max_fa_bucket_c": self.max_c, "max_fa_bucket_e": self.max_e}

    def fit(self, traces, registries, table=None):
        _check_unique([t["id"] for t in traces])
        tab = DR._table_for(traces, self.embedder, registries, table)
        return self._fit_table(tab, {}, {"n_original_traces": len(tab.trace_ids)})

    # One implementation for D9b and D9c; ``orig_of`` maps augmented trace ids to originals ({} for D9b). It mirrors
    # ``DR.RegistryLearned.fit`` (eval/detectors_registry.py: fold construction, lambda grid, standardisation, class-balanced
    # logistic fit, lambda choice by (rounded CV loss, -lambda), max(in-sample, OOF) threshold); the equality test
    # ``test_d9b_without_extra_constraint_equals_d9`` (weights, cv_loss, cv_folds, threshold) keeps the two in sync.
    def _fit_table(self, tab, orig_of: dict, extra: dict):
        d = len(DR.REG_FEATURE_NAMES)
        _check_unique(list(tab.trace_ids))
        rows = tab.scored
        X, y, g = tab.feats[rows], tab.viol[rows].astype(float), tab.trace_idx[rows]
        orig_ids = sorted({orig_of.get(t, t) for t in tab.trace_ids})
        if len(orig_ids) < 2:
            raise ValueError(f"need at least 2 original traces for grouped cross-validation, got {len(orig_ids)}")
        folds = D2._folds(orig_ids, self.seed)
        n_pos, n_neg = int(y.sum()), int(len(y) - y.sum())
        info = {"n_rows": int(len(y)), "n_pos": n_pos, "n_traces": len(tab.trace_ids), "cv_folds": folds,
                "feature_names": list(DR.REG_FEATURE_NAMES), "seed": self.seed, "cv_loss": {},
                "constraints": self.constraints, **extra}
        self.mean, self.std = np.zeros(d), np.ones(d)
        if n_pos == 0 or n_neg == 0:
            self.weights, self.bias = np.zeros(d), (-10.0 if n_pos == 0 else 10.0)
            self.threshold, self.lam = math.inf, self.lambdas[-1]
            info.update({"lambda": self.lam, "cv_loss": {str(l): None for l in self.lambdas}, "feasible": False,
                         "note": "INFEASIBLE: single class in fit data: model is constant, never alerts"})
            self.fit_info = info
            return self
        splits = cv_masks(np.array(tab.trace_ids)[g], orig_of, folds)
        oof = {}
        for lam in self.lambdas:
            p = np.full(len(y), np.nan)
            for tr, va in splits:
                mu, sd = D2._standardise(X[tr])
                w, b = D2.fit_logistic((X[tr] - mu) / sd, y[tr], lam)
                p[va] = D2._sigmoid(((X[va] - mu) / sd) @ w + b)
            oof[lam] = p
            info["cv_loss"][str(lam)] = D2._bal_logloss(y, p)
        best = min(self.lambdas, key=lambda l: (round(info["cv_loss"][str(l)], 12), -l))
        self.lam = best
        self.mean, self.std = D2._standardise(X)
        self.weights, self.bias = D2.fit_logistic((X - self.mean) / self.std, y, best)

        is_orig_row = np.array([t not in orig_of for t in tab.trace_ids], bool)[tab.trace_idx]

        p_in = np.full(len(rows), np.nan)
        p_in[np.flatnonzero(rows)] = self.predict_proba(X)
        p_cv = np.full(len(rows), np.nan)
        p_cv[np.flatnonzero(rows)] = oof[best]
        ts = candidate_thresholds(p_in, p_cv, tab.nonviol, tab.is_c, tab.is_e, is_orig_row, self.max_fa, self.max_c,
                                  self.max_e)
        self.threshold = combine_thresholds(ts)
        info.update({"lambda": best, "threshold_in_sample": _enc(ts["in_sample"]), "threshold_oof": _enc(ts["oof"]),
                     **{f"threshold_{k}": _enc(v) for k, v in ts.items() if k.endswith("_orig")}})
        info.update(self._verify_and_failsafe(tab, is_orig_row))
        self.fit_info = info
        return self

    def _verify_and_failsafe(self, tab, is_orig_row) -> dict:
        """Dev operating point on the ORIGINAL traces and the feasibility verdict. Nothing is relaxed. SIDE EFFECT: sets
        ``self.threshold = +inf`` when a constraint is broken on dev (fail safe)."""
        prob = np.full(len(tab.s), np.nan)
        prob[tab.scored] = self.predict_proba(tab.feats[tab.scored])
        al = tab.scored & (prob > self.threshold) & is_orig_row
        o = is_orig_row
        n_nv, n_c, n_e = (int((m & o).sum()) for m in (tab.nonviol, tab.is_c, tab.is_e))
        cnt = {"fa_overall": int((al & tab.nonviol).sum()), "fa_c": int((al & tab.is_c).sum()),
               "fa_e": int((al & tab.is_e).sum())}
        def rate(a, b):
            return a / b if b else 0.0
        rates = {"fa_overall": rate(cnt["fa_overall"], n_nv), "fa_c": rate(cnt["fa_c"], n_c), "fa_e": rate(cnt["fa_e"], n_e),
                 "first_violation_recall": rate(int((al & tab.first_viol).sum()), int((tab.first_viol & o).sum())),
                 "violation_recall": rate(int((al & tab.viol).sum()), int((tab.viol & o).sum())),
                 "n_nonviolation_steps": n_nv, "n_c": n_c, "n_e": n_e, "false_alarms": cnt}
        lim = {"fa_overall": D2._allowed(n_nv, self.max_fa), "fa_c": D2._allowed(n_c, self.max_c),
               "fa_e": None if self.max_e is None else D2._allowed(n_e, self.max_e)}
        broken = [k for k, v in lim.items() if v is not None and cnt[k] > v]
        if math.isinf(self.threshold) or broken:
            reason = ("no threshold satisfies the constraints" if math.isinf(self.threshold)
                      else f"constraints violated on dev: {broken}")
            if not math.isinf(self.threshold):
                self.threshold = math.inf                # fail safe: never alert; the constraint is NOT relaxed
            return {"feasible": False, "dev_rates": rates,
                    "note": f"INFEASIBLE: {reason}; threshold set to +inf (never alerts), constraints not relaxed"}
        return {"feasible": True, "dev_rates": rates}

    def to_dict(self):
        d = super().to_dict()
        d.update(id=self.id, constraints=self.constraints)
        return d

    @classmethod
    def from_dict(cls, d, embedder, registry=None):
        if d.get("id") != cls.id:
            raise FrozenRegistryError(f"entry id {d.get('id')!r} does not match detector class {cls.id!r}")
        det = super().from_dict(d, embedder, registry)
        c = d.get("constraints", {})
        det.max_fa = c.get("max_fa_overall", det.max_fa)
        det.max_c = c.get("max_fa_bucket_c", det.max_c)
        det.max_e = c.get("max_fa_bucket_e", det.max_e)
        return det


class RegistryLearnedC(RegistryLearnedB):
    """D9c: D9b trained on the originals plus 3 registry-dropout copies per trace; CV grouped by original id."""
    id, name = "D9c", "registry_learned_dropout"

    def fit(self, traces, registries, table=None):
        if table is not None:
            raise ValueError("D9c builds its own table (originals + augmented copies)")
        _check_unique([t["id"] for t in traces])
        traces = sorted(traces, key=lambda t: t["id"])
        regs = {t["id"]: registries.get(t["id"]) for t in traces if registries.get(t["id"]) is not None}
        aug, aregs, orig_of = augment_traces(traces, regs)
        tab = DR.RegStepTable(traces + aug, self.embedder, {**regs, **aregs})
        return self._fit_table(tab, orig_of, {
            "n_original_traces": len(traces), "n_augmented_copies": len(aug),
            "augmentation": {"fraction": AUG_FRACTION, "seeds": list(AUG_SEEDS), "copies_per_trace": AUG_COPIES}})

    def to_dict(self):
        d = super().to_dict()
        d["augmentation"] = {"fraction": AUG_FRACTION, "seeds": list(AUG_SEEDS), "copies_per_trace": AUG_COPIES}
        return d


# ------------------------------------------------------------------ freezing
def _check_unique(ids) -> None:
    seen, dup = set(), set()
    for i in ids:
        (dup if i in seen else seen).add(i)
    dup = sorted(dup)
    if dup:
        raise ValueError(f"duplicate trace ids: {dup[:5]}")


def dump_frozen_registry_v3(path, detectors: dict, meta: dict | None = None) -> None:
    """Write the frozen file: ``schema_version``, the detectors (only D9b / D9c, anything else is an error) and ``_meta``.
    Strict JSON: a NaN anywhere is an error and nothing is written."""
    bad = sorted(set(detectors) - set(FROZEN_IDS))
    if bad:
        raise FrozenRegistryError(f"only {list(FROZEN_IDS)} can be frozen, got {bad}")
    out = {"schema_version": SCHEMA_VERSION}
    out.update({did: det.to_dict() for did, det in detectors.items()})
    out["_meta"] = meta or {}
    try:
        text = json.dumps(out, indent=1, default=float, allow_nan=False)
    except ValueError as exc:
        raise ValueError(f"NaN/Infinity in the frozen model (not valid JSON): {exc}") from exc
    Path(path).write_text(text)


def load_frozen_registry_v3(path, embedder, registry=None, only=None) -> dict:
    """{id: detector} for D9b / D9c; same call shape as ``eval.detectors_registry.load_frozen_registry`` (``registry`` is
    the initial registry: None, a dict, a path or a Registry). Strict: raises ``FrozenRegistryError`` for a missing or
    unknown ``schema_version``, a detector id other than D9b/D9c in the file, an ``only`` id that is unknown or absent from
    the file, or an entry whose ``id`` does not match its key."""
    blob = json.loads(Path(path).read_text())
    if blob.get("schema_version") != SCHEMA_VERSION:
        raise FrozenRegistryError(f"{path}: unsupported schema_version {blob.get('schema_version')!r} "
                                  f"(this loader reads {SCHEMA_VERSION!r})")
    cls = {"D9b": RegistryLearnedB, "D9c": RegistryLearnedC}
    unknown = sorted(set(blob) - set(cls) - {"schema_version", "_meta"})
    if unknown:
        raise FrozenRegistryError(f"{path}: unknown detector id(s) {unknown}")
    want = [k for k in cls if k in blob] if only is None else list(only)
    for k in want:
        if k not in cls:
            raise FrozenRegistryError(f"unknown detector id {k!r} requested (known: {list(cls)})")
        if k not in blob:
            raise FrozenRegistryError(f"{path}: detector {k!r} requested but not present in the file")
    return {k: cls[k].from_dict(blob[k], embedder, registry) for k in want}
