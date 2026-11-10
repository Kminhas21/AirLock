"""Fit and freeze D9b / D9c (SPEC_V3 'Detectors scored') on v1 dev + v2 dev with the extractor-1 registries.

    python -m eval.fit_registry_v3 --v1 eval/final/traces.json --v2 eval/final_v2/traces.json \\
        --reg1 eval/registries_v2/ex1.json --out eval/results_registry_v3

Only DEV traces (``eval.run_eval.split_for``) are ever looked at after loading; TEST traces of v1 / v2 are dropped before
any feature, label or registry is read, so perturbing them cannot change ``frozen_registry_models_v3.json``. The frozen
file records sha256 of the canonical JSON of the DEV subsets that were used (so it stays byte-identical when TEST traces
change) and a golden digest of the dropout copies (``_meta.augmentation_digest``); provenance is verified by recomputing
``dev_subset_digests(v1, v2, reg1)`` from the allowed input files. ``FIT_REPORT_V3.md`` additionally records sha256 of the
whole input files (informational). Paths containing "v3" are refused. D9 is re-fitted for the side-by-side
report only (it is not written to the frozen file). Constraints are never relaxed: an infeasible fit is reported and the
exit status is 3.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
from pathlib import Path

import numpy as np

from . import detectors_registry as DR
from . import detectors_registry_v3 as V3
from . import detectors_v2 as D2
from . import metrics as M
from .embed import StubEmbedder, get_shared_embedder
from .run_eval import TraceLoadError, load_traces, split_for
from .run_eval_registry import _load_registries

DEFAULT_SEED = M.DEFAULT_SEED          # the seed of the frozen D9 (folds), so D9 is reproduced exactly
D9_FROZEN = str(Path(__file__).resolve().parent / "results_registry" / "frozen_registry_models.json")
DETS = ["D9", "D9b", "D9c"]


def make_embedder(kind: str):
    emb = get_shared_embedder() if kind == "minilm" else StubEmbedder()
    emb.warm()
    emb.cache_size = max(emb.cache_size, 200000)
    return emb


def refuse_v3_paths(flag: str, patterns) -> None:
    """The fit must be blind to v3 data: refuse any input path (pattern, glob expansion or resolved symlink) with 'v3'."""
    for pat in patterns:
        cands = [pat, *glob.glob(pat)]
        cands += [os.path.realpath(c) for c in list(cands)]
        bad = [c for c in cands if "v3" in c.lower()]
        if bad:
            raise ValueError(f"{flag}: refusing path containing 'v3' (the D9b/D9c fit must not see v3 data): {bad[0]}")


def _canon_sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _content(traces):
    """Traces without the loader's ``_file`` path annotation (the hash must not depend on where the file lives)."""
    return [{k: v for k, v in t.items() if k != "_file"} for t in traces]


def _file_sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def operating_point(det, tab) -> dict:
    """Dev operating point of a fitted detector on the table of the ORIGINAL dev traces."""
    prob = np.full(len(tab.s), np.nan)
    prob[tab.scored] = det.predict_proba(tab.feats[tab.scored])
    al = tab.scored & (prob > det.threshold)
    def n(m):
        return int(m.sum())

    def r(a, b):
        return a / b if b else 0.0
    return {"threshold": det.threshold, "lambda": det.lam,
            "fa_overall": r(n(al & tab.nonviol), n(tab.nonviol)), "fa_c": r(n(al & tab.is_c), n(tab.is_c)),
            "fa_e": r(n(al & tab.is_e), n(tab.is_e)),
            "first_violation_recall": r(n(al & tab.first_viol), n(tab.first_viol)),
            "violation_recall": r(n(al & tab.viol), n(tab.viol)),
            "counts": {"nonviolation_steps": n(tab.nonviol), "c": n(tab.is_c), "e": n(tab.is_e),
                       "first_violations": n(tab.first_viol), "violations": n(tab.viol),
                       "false_alarms": n(al & tab.nonviol), "fa_c": n(al & tab.is_c), "fa_e": n(al & tab.is_e),
                       "first_violation_hits": n(al & tab.first_viol), "violation_hits": n(al & tab.viol)}}


def dev_inputs(v1, v2, reg1):
    """(v1 dev, v2 dev, dev, registries of the dev v2 traces): the ONLY data a fit may see. Duplicate ids are an error."""
    v1d = sorted((t for t in v1 if split_for(t["id"]) == "dev"), key=lambda t: t["id"])
    v2d = sorted((t for t in v2 if split_for(t["id"]) == "dev"), key=lambda t: t["id"])
    dev = sorted(v1d + v2d, key=lambda t: t["id"])
    ids = [t["id"] for t in dev]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise ValueError(f"duplicate dev trace ids: {dup[:5]}")
    v2_ids = {t["id"] for t in v2d}
    regs = {k: r for k, r in reg1.items() if k in v2_ids}          # dev v2 traces only; the rest use the defaults
    return v1d, v2d, dev, regs


def _digests(v1d, v2d, dev, regs) -> dict:
    return {"v1_dev_traces": _canon_sha(_content(v1d)), "v2_dev_traces": _canon_sha(_content(v2d)),
            "reg1_dev_registries": _canon_sha({k: regs[k] if isinstance(regs[k], dict) else regs[k].to_dict()
                                               for k in sorted(regs)}),
            "augmentation_digest": V3.augmentation_digest(dev, regs)}


def dev_subset_digests(v1_path, v2_path, reg1_path) -> dict:
    """Recompute, from the input files, the provenance digests written to the frozen file: the three keys of
    ``_meta.inputs_dev_sha256`` (canonical-JSON sha256 of the v1 dev traces, v2 dev traces and the dev-v2 extractor-1
    registries) and ``augmentation_digest`` (``_meta.augmentation_digest``). Same code path as ``fit_all``. Each path is a
    file / glob or a list of them (v1 / v2)."""
    def as_list(p):
        return [str(x) for x in p] if isinstance(p, (list, tuple)) else [str(p)]
    v1, v2 = load_traces(as_list(v1_path)), load_traces(as_list(v2_path))
    reg1 = _load_registries(str(reg1_path), "extractor 1")
    return _digests(*dev_inputs(v1, v2, reg1))


def fit_all(v1, v2, reg1, embedder, seed: int = DEFAULT_SEED, max_e=V3.MAX_FA_E_B) -> dict:
    """Fit D9 (reference), D9b, D9c on v1 dev + v2 dev. Returns detectors, operating points and the frozen meta."""
    v1d, v2d, dev, regs = dev_inputs(v1, v2, reg1)
    tab = DR.RegStepTable(dev, embedder, regs)
    d9 = DR.RegistryLearned(embedder=embedder, seed=seed).fit(dev, regs, table=tab)
    d9b = V3.RegistryLearnedB(embedder=embedder, seed=seed, max_e=max_e).fit(dev, regs, table=tab)
    d9c = V3.RegistryLearnedC(embedder=embedder, seed=seed, max_e=max_e).fit(dev, regs)
    dets = {"D9": d9, "D9b": d9b, "D9c": d9c}
    ops = {k: operating_point(d, tab) for k, d in dets.items()}
    dg = _digests(v1d, v2d, dev, regs)
    n_entries = sum(len(r.get("entries") or []) if isinstance(r, dict) else len(r.entries) for r in regs.values())
    meta = {"fit_on": "v1 dev + v2 dev", "fit_registry": "extractor 1 (full), dev v2 traces only; others use defaults",
            "seed": seed, "aug_seeds": list(V3.AUG_SEEDS), "aug_fraction": V3.AUG_FRACTION,
            "aug_copies_per_trace": V3.AUG_COPIES, "embedder": embedder.name,
            "constraints": {"max_fa_overall": D2.MAX_FA, "max_fa_bucket_c": D2.MAX_FA_C, "max_fa_bucket_e": max_e},
            "feature_names": DR.REG_FEATURE_NAMES, "lambda_grid": list(D2.LAMBDA_GRID),
            "n_dev_traces": len(dev), "n_dev_v1": len(v1d), "n_dev_v2": len(v2d),
            "n_dev_traces_with_registry": len(regs), "n_dev_registry_entries": n_entries,
            "inputs_dev_sha256": {k: dg[k] for k in ("v1_dev_traces", "v2_dev_traces", "reg1_dev_registries")},
            "augmentation_digest": dg["augmentation_digest"]}
    return {"detectors": dets, "ops": ops, "meta": meta, "tab": tab}


def _pct(x) -> str:
    return f"{100 * x:.1f}%"


def render_report(res: dict, file_sha: dict, d9_check: str) -> str:
    m, ops, dets = res["meta"], res["ops"], res["detectors"]
    L = ["# D9b / D9c fit report (SPEC_V3)\n",
         f"Fit on **{m['fit_on']}** ({m['n_dev_traces']} dev traces: {m['n_dev_v1']} v1, {m['n_dev_v2']} v2; "
         f"{m['n_dev_traces_with_registry']} with extractor-1 entries, {m['n_dev_registry_entries']} entries). "
         f"Embedder `{m['embedder']}`, seed {m['seed']}. Test traces were loaded then discarded, never used (dropped before any feature, label or registry was read).\n",
         "## Dev operating points (original dev traces, post-denial proposals scored)\n",
         "Constraints: FA overall <= 5%, (c) <= 10%, (e) <= 10% (D9b/D9c enforce all three; D9 enforces only the first two).\n",
         "| detector | threshold | lambda | FA overall | FA (c) | FA (e) | first-violation recall | violation recall | feasible |",
         "|---|---|---|---|---|---|---|---|---|"]
    for k in DETS:
        o, d = ops[k], dets[k]
        feas = "n/a (no (e) constraint)" if k == "D9" else ("yes" if d.fit_info["feasible"] else "**INFEASIBLE**")
        thr = "inf" if o["threshold"] == float("inf") else f"{o['threshold']:.4f}"
        L.append(f"| {k} | {thr} | {o['lambda']:g} | {_pct(o['fa_overall'])} | {_pct(o['fa_c'])} | {_pct(o['fa_e'])} | "
                 f"{_pct(o['first_violation_recall'])} ({o['counts']['first_violation_hits']}/{o['counts']['first_violations']}) | "
                 f"{_pct(o['violation_recall'])} ({o['counts']['violation_hits']}/{o['counts']['violations']}) | {feas} |")
    c = ops["D9"]["counts"]
    L += ["", f"Denominators: {c['nonviolation_steps']} non-violation steps (overall), {c['c']} benign post-denial proposals (c), "
              f"{c['e']} regex-trap proposals (e).", ""]
    for k in ("D9b", "D9c"):
        if not dets[k].fit_info["feasible"]:
            L.append(f"**{k} INFEASIBLE**: {dets[k].fit_info['note']}. The constraint was not relaxed.\n")
    fi = dets["D9c"].fit_info
    L += ["## Details\n",
          f"- D9b: lambda {dets['D9b'].lam:g}, thresholds in-sample {fi_get(dets['D9b'], 'threshold_in_sample')}, out-of-fold {fi_get(dets['D9b'], 'threshold_oof')} (threshold = max).",
          f"- D9c: {fi['n_original_traces']} originals + {fi['n_augmented_copies']} registry-dropout copies "
          f"({m['aug_copies_per_trace']} per trace, {int(100 * m['aug_fraction'])}% of pooled entries removed, seeds {m['aug_seeds']}); "
          f"training rows {fi['n_rows']} ({fi['n_pos']} positive); CV grouped by original id; thresholds pooled/original, "
          f"in-sample/out-of-fold: {fi_get(dets['D9c'], 'threshold_in_sample')}, {fi_get(dets['D9c'], 'threshold_oof')}, "
          f"{fi_get(dets['D9c'], 'threshold_in_sample_orig')}, {fi_get(dets['D9c'], 'threshold_oof_orig')} (threshold = max).",
          f"- D9 re-fit vs frozen D9 of the v2 registry run: {d9_check}.",
          "", "## Inputs (sha256)\n",
          *(f"- whole file `{k}`: `{v}`" for k, v in sorted(file_sha.items())),
          "- (whole-file hashes are informational; the frozen file records only the dev-subset hashes below, so it does not change when TEST traces change)",
          *(f"- dev subset `{k}` (canonical JSON, recorded in the frozen file): `{v}`" for k, v in m["inputs_dev_sha256"].items()),
          f"- augmentation digest (3 dropout copies, recorded in the frozen file as `_meta.augmentation_digest`): `{m['augmentation_digest']}`",
          "", "## Caveats\n",
          "- Operating points are IN-SAMPLE on dev (the thresholds were calibrated on these rows, also out-of-fold); they are not performance estimates.",
          "- D9c's copies of traces without registry entries (all v1 and part of v2) are exact duplicates of the original (nothing to drop), so these traces weigh 4x in D9c's training set; "
          "the 30% dropout acts on the pooled entries of the v2 dev registries only.",
          "- D9, D9b, D9c share lambda grid, features, seed and CV protocol; D9c's folds are over ORIGINAL ids (copies follow their original) and are identical to D9b's.", ""]
    return "\n".join(L)


def fi_get(det, key):
    v = det.fit_info.get(key)
    return "n/a" if v is None else (v if isinstance(v, str) else f"{v:.4f}")


def d9_consistency(d9, path=D9_FROZEN) -> str:
    p = Path(path)
    if not p.exists():
        return "eval/results_registry/frozen_registry_models.json not found, not compared"
    try:
        fz = json.loads(p.read_text())["D9"]
        same = (np.max(np.abs(np.array(fz["weights"]) - d9.weights)) <= 1e-9 and DR._dec(fz["threshold"]) == d9.threshold)
        return "identical weights and threshold" if same else "DIFFERENT from the frozen D9 (inputs changed since that fit)"
    except Exception as exc:
        return f"could not compare ({exc})"


def run(v1, v2, reg1, out_dir, embedder_kind="minilm", seed=DEFAULT_SEED, max_e=V3.MAX_FA_E_B, file_sha=None) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    res = fit_all(v1, v2, reg1, make_embedder(embedder_kind), seed, max_e)
    dets = res["detectors"]
    V3.dump_frozen_registry_v3(out / "frozen_registry_models_v3.json", {k: dets[k] for k in ("D9b", "D9c")}, meta=res["meta"])
    (out / "FIT_REPORT_V3.md").write_text(render_report(res, file_sha or {}, d9_consistency(dets["D9"])))
    bad = [k for k in ("D9b", "D9c") if not dets[k].fit_info["feasible"]]
    for k in DETS:
        o = res["ops"][k]
        print(f"{k}: thr={o['threshold']:.4f} FA={_pct(o['fa_overall'])} (c)={_pct(o['fa_c'])} (e)={_pct(o['fa_e'])} "
              f"first-viol recall={_pct(o['first_violation_recall'])} viol recall={_pct(o['violation_recall'])}")
    if bad:
        print(f"INFEASIBLE: {bad} (not relaxed; see FIT_REPORT_V3.md)", file=sys.stderr)
    print(f"wrote {out / 'frozen_registry_models_v3.json'} and {out / 'FIT_REPORT_V3.md'}")
    return 3 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.fit_registry_v3", description=__doc__.splitlines()[0])
    ap.add_argument("--v1", nargs="+", required=True)
    ap.add_argument("--v2", nargs="+", required=True)
    ap.add_argument("--reg1", required=True, help="extractor-1 registries {trace_id: registry dict}")
    ap.add_argument("--out", default="eval/results_registry_v3")
    ap.add_argument("--embedder", choices=["minilm", "stub"], default="minilm")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--max-e", type=float, default=V3.MAX_FA_E_B, help="bucket-(e) FA bound (testing infeasibility only)")
    a = ap.parse_args(argv)
    try:
        for flag, pats in (("--v1", a.v1), ("--v2", a.v2), ("--reg1", [a.reg1])):
            refuse_v3_paths(flag, pats)
        V3._check_rate("--max-e", a.max_e)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        v1, v2 = load_traces(a.v1), load_traces(a.v2)
        reg1 = _load_registries(a.reg1, "extractor 1")
    except TraceLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    dup = sorted({t["id"] for t in v1} & {t["id"] for t in v2})
    if dup:
        print(f"error: duplicate trace ids across v1 and v2: {dup[:5]}", file=sys.stderr)
        return 2
    files = {}
    for lab, pats in (("v1", a.v1), ("v2", a.v2)):
        for p in pats:
            for f in sorted(glob.glob(p)):
                files[f"{lab}:{f}"] = _file_sha(f)
    files[f"reg1:{a.reg1}"] = _file_sha(a.reg1)
    try:
        return run(v1, v2, reg1, a.out, a.embedder, a.seed, a.max_e, files)
    except ValueError as exc:                                  # e.g. duplicate dev trace ids
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
