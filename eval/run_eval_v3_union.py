"""v3-union one-shot (eval/SPEC_V3_UNION.md): frozen registry detector OR D3, under the v3-degrade degradations. POST-HOC design."""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from . import metrics as M
from .detectors_union import UnionDetector
from .embed import StubEmbedder, get_shared_embedder
from .run_eval import load_traces
from .run_eval_registry import _load_registries, _score
from . import run_eval_v3_degrade as G
from .run_eval_v3 import (_point, cond_block, fa_in, file_sha256, load_candidates, load_refs, on_time_in, paired_gain)
from server import registry as REG

MAX_FA, MAX_C, MAX_E, MIN_ON, MIN_GAIN = 0.05, 0.10, 0.10, 0.55, 0.15
BASES = {"U8": "D8", "U9b": "D9b", "U9c": "D9c"}
ORDER = ["U8", "U9b", "U9c"]


def undegraded_criteria(m: dict) -> dict:
    ok = lambda c, x, t, hi: (G._le if hi else G._ge)(x, t)
    lo = (m["gain_d7"]["ci"] or [None])[0]
    lo6 = (m["gain_d3"]["ci"] or [None])[0]
    c = {"U1": (m["on_time"], MIN_ON, G._ge(m["on_time"], MIN_ON)), "U2": (m["fa"], MAX_FA, G._le(m["fa"], MAX_FA)),
         "U3": (m["fa_c"], MAX_C, G._le(m["fa_c"], MAX_C)), "U4": (m["fa_e"], MAX_E, G._le(m["fa_e"], MAX_E)),
         "U5": (m["gain_d7"]["diff"], MIN_GAIN, G._ge(m["gain_d7"]["diff"], MIN_GAIN) and isinstance(lo, float) and lo > 0),
         "U6": (m["gain_d3"]["diff"], MIN_GAIN, G._ge(m["gain_d3"]["diff"], MIN_GAIN) and isinstance(lo6, float) and lo6 > 0)}
    return {k: {"value": v, "threshold": t, "status": "pass" if p else "fail"} for k, (v, t, p) in c.items()}


def run(emb, n_boot=2000, seed=M.DEFAULT_SEED):
    v3 = load_traces([G.PATHS["traces"]])
    base = {t: REG.Registry.load(r) for t, r in _load_registries(G.PATHS["author1"], "author1").items()}
    orc = {t: REG.Registry.load(r) for t, r in _load_registries(G.PATHS["oracle"], "oracle").items()}
    frozen = {"v2posthoc": G.PATHS["v2posthoc"], "registry": G.PATHS["registry"], "v3": G.PATHS["v3"]}
    refs, cands = load_refs(frozen, emb), load_candidates(frozen, emb)
    d3 = refs["D3"]
    unions = {u: UnionDetector(u, f"{b} OR D3", [cands[b], d3]) for u, b in BASES.items()}
    reg_m1, reg_m2, hit = G.m1_m2(v3, base)
    reg_b1, pop = G.b1(v3, base, orc)
    regs_m3 = {s: G.m3({t["id"]: base.get(t["id"]) for t in v3}, s) for s in G.SEEDS}
    scen = {"base": base, "m1": reg_m1, "m2": reg_m2, "b1": reg_b1, **{f"m3_{s}": regs_m3[s] for s in G.SEEDS}}
    ref_res = {k: _score(refs[d], v3, {}, emb, False) for d, k in (("D3", "D3"), ("D7", "D7"))}
    out = {"meta": {"design": "POST-HOC on seen data", "m1_m2_traces": hit, "b1_population_n": len(pop), "n_boot": n_boot,
                    "frozen_sha256": {k: file_sha256(p) for k, p in frozen.items()}}, "detectors": {}}
    mean = lambda xs: sum(xs) / len(xs)
    d3pt = [_point(ref_res["D3"]) for _ in G.SEEDS]
    for u in ORDER:
        r = {k: _score(unions[u], v3, regs, emb, False) for k, regs in scen.items()}
        on1, n1 = on_time_in(r["m1"], hit)
        on2, n2 = on_time_in(r["m2"], hit)
        d3on, _ = on_time_in(ref_res["D3"], hit)
        m3pt = [_point(r[f"m3_{s}"]) for s in G.SEEDS]
        x = {"m1": {"n": n1, "on_time": on1, "d3": d3on}, "m2": {"n": n2, "on_time": on2, "d3": d3on},
             "m3": {"on_time": mean([p["on_time"] for p in m3pt]), "d3_on_time": d3pt[0]["on_time"], "fa": mean([p["fa_overall"] for p in m3pt])},
             "b1": {"n": len(pop), "fa": fa_in(r["b1"], pop), "d3_fa": fa_in(ref_res["D3"], pop)},
             "fa_m1": _point(r["m1"])["fa_overall"], "fa_m2": _point(r["m2"])["fa_overall"]}
        pt, blk = _point(r["base"]), cond_block(r["base"], n_boot, seed)
        lat = sorted(s.latency_s for t in r["base"] for s in t.steps)
        und = {"on_time": pt["on_time"], "fa": pt["fa_overall"], "fa_c": pt["fa_c"], "fa_e": blk["bucket_e_regex_traps"]["rate"],
               "gain_d7": paired_gain(ref_res["D7"], r["base"], n_boot, seed), "gain_d3": paired_gain(ref_res["D3"], r["base"], n_boot, seed),
               "median_step_ms": 1000 * lat[len(lat) // 2]}
        deg, ud = G.criteria(x), undegraded_criteria(und)
        rob = G.robust(deg) and all(v["status"] == "pass" for v in ud.values())
        out["detectors"][u] = {"name": unions[u].name, "degraded_inputs": x, "degraded": deg, "undegraded_inputs": und, "undegraded": ud,
                               "robust": rob, "members": BASES[u] + " + D3"}
    rob = [u for u in ORDER if out["detectors"][u]["robust"]]
    sel = max(rob, key=lambda u: (out["detectors"][u]["undegraded_inputs"]["on_time"], -out["detectors"][u]["undegraded_inputs"]["fa"], -ORDER.index(u))) if rob else None
    out["verdict"] = {"robust": rob, "selected": sel, "label": f"robust; selected {sel}" if sel else "shortfall: no union is robust"}
    return out


def render(res):
    f = G._f
    L = ["# v3-union results (one-shot, POST-HOC design on seen data; eval/SPEC_V3_UNION.md)", "", f"**Verdict: {res['verdict']['label']}**", "",
         "## Degradations", "", "| detector | S1 missing | S2 stale-internal | S3 sparse | S4 stale-relay FA | S5 FA |", "|---|---|---|---|---|---|"]
    for u in ORDER:
        c = res["detectors"][u]["degraded"]
        L.append(f"| {u} ({res['detectors'][u]['members']}) | {f(c['S1']['value'])} vs {f(c['S1']['threshold'])} {c['S1']['status']} | {f(c['S2']['value'])} {c['S2']['status']} | "
                 f"{f(c['S3']['value'])} vs {f(c['S3']['threshold'])} {c['S3']['status']} | {f(c['S4']['value'])} (D3 {f(c['S4']['d3_fa'])}) {c['S4']['status']} | {f(c['S5']['value'])} {c['S5']['status']} |")
    L += ["", "## Undegraded author1 registry", "", "| detector | " + " | ".join(["U1 on-time", "U2 FA", "U3 FA(c)", "U4 FA(e)", "U5 gain vs D7", "U6 gain vs D3"]) + " | robust |", "|---|---|---|---|---|---|---|---|"]
    for u in ORDER:
        d = res["detectors"][u]
        L.append(f"| {u} | " + " | ".join(f"{f(d['undegraded'][k]['value'])} {d['undegraded'][k]['status']}" for k in ("U1", "U2", "U3", "U4", "U5", "U6")) + f" | {d['robust']} |")
    L += ["", "Median per-step latency (ms): " + "; ".join(f"{u} {res['detectors'][u]['undegraded_inputs']['median_step_ms']:.2f}" for u in ORDER)]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m eval.run_eval_v3_union")
    ap.add_argument("--out", default="eval/results_v3_union")
    ap.add_argument("--embedder", choices=["minilm", "stub"], default="minilm")
    ap.add_argument("--n-boot", type=int, default=2000)
    a = ap.parse_args(argv)
    out = Path(a.out)
    if (out / "results.json").exists():
        print(f"error: {out/'results.json'} exists; scored once", file=sys.stderr)
        return 4
    res = run(StubEmbedder() if a.embedder == "stub" else get_shared_embedder(), a.n_boot)
    out.mkdir(parents=True, exist_ok=True)
    (out / "REPORT.md").write_text(render(res))
    (out / "results.json").write_text(json.dumps(res, indent=1, default=str))
    print(render(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
