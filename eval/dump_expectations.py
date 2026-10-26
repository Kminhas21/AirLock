"""Offline expectations for live replay tests.

    python -m eval.dump_expectations --detector D1|D3|D5|D6|D7 [--frozen eval/results_v2/frozen_models.json] --traces eval/final/traces.json --ids a,b --out exp.json
    python -m eval.dump_expectations --detector D8|D9 --registry registry.json [--frozen eval/results_registry/frozen_registry_models.json] ...

Runs the offline detector (eval.detectors.run_trace, built via eval.run_eval._build) on each trace with exactly the
inputs the live loop provides: only proposal-bearing steps, ``{"tool","args"}`` as the proposal, and agent_text =
the message-only steps since the previous proposal joined with a space + the proposal step's own text
(this is what tests/browser/fake_llm.py serves as the turn's content). Per trace id it writes the step indices
with alert==true and their proposal ordinals (the n-th tool_pending of the live session).
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")

REPO = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = REPO / "eval" / "results" / "results.json"
DEFAULT_THRESHOLDS = {"D2": 0.5, "D3": 0.6}
DETECTORS = ("D0", "D1", "D2", "D3", "D4", "D4_and", "D5", "D6", "D7", "D8", "D9")
REGISTRY_DETECTORS = ("D8", "D9")
DEFAULT_FROZEN_REGISTRY = REPO / "eval" / "results_registry" / "frozen_registry_models.json"


def load_thresholds(results_path=DEFAULT_RESULTS) -> dict:
    """D2/D3 thresholds from the calibration block of results.json; documented defaults when absent."""
    thr = dict(DEFAULT_THRESHOLDS)
    p = Path(results_path)
    if p.exists():
        cal = json.loads(p.read_text()).get("calibration", {})
        for k in ("D2", "D3"):
            v = (cal.get(k) or {}).get("threshold")
            if isinstance(v, (int, float)):
                thr[k] = float(v)
    return thr


def merge_trace(trace: dict) -> dict:
    """Keep proposal-bearing steps only; message-only steps are joined (space) into the NEXT proposal's agent_text.
    Trailing message-only steps are dropped (they form the live session's final text-only turn)."""
    steps, buf = [], []
    for st in trace["steps"]:
        buf.append(st["agent_text"])
        if st.get("proposal") is None:
            continue
        s = copy.deepcopy(st)
        s["agent_text"] = " ".join(buf)
        steps.append(s)
        buf = []
    out = {k: v for k, v in trace.items() if k != "steps"}
    out["steps"] = steps
    return out


def build_detector(did: str, thresholds: dict | None = None, embedder_kind: str = "minilm", frozen: str | None = None,
                   registry: str | None = None):
    """``frozen``: path to eval/results_v2/frozen_models.json. When given, D3-D7 are the EXACT frozen detectors the
    live monitor loads (thresholds/weights from that file); D1 is always the rules detector.
    D8 / D9 (registry detectors) are always frozen: ``frozen`` defaults to eval/results_registry/frozen_registry_models.json
    and ``registry`` is ONE destination registry file used for every trace (None: the built-in defaults, i.e. no entries)."""
    from .embed import MiniLMEmbedder, StubEmbedder

    emb = StubEmbedder() if embedder_kind == "stub" else MiniLMEmbedder()
    if did in REGISTRY_DETECTORS:
        from .detectors_registry import load_frozen_registry

        return load_frozen_registry(frozen or DEFAULT_FROZEN_REGISTRY, emb, registry, only=[did])[did]
    if frozen is not None and did != "D1":
        from .detectors_v2 import load_frozen

        return load_frozen(frozen, emb, only=[did])[did]
    from .run_eval import _build

    return _build(emb, thresholds or load_thresholds())[did]


def expectations(did: str, traces: list[dict], thresholds: dict | None = None, embedder_kind: str = "minilm",
                 frozen: str | None = None, registry: str | None = None) -> dict:
    from .detectors import run_trace

    det = build_detector(did, thresholds, embedder_kind, frozen, registry)
    out = {}
    for t in traces:
        merged = merge_trace(t)
        res = run_trace(det, merged)
        psteps = [s["i"] for s in merged["steps"]]
        to_ord = {i: k for k, i in enumerate(psteps)}
        alerts = [s.i for s in res.steps if s.alert]
        out[t["id"]] = {
            "detector": did,
            "category": t["category"],
            "alert_steps": alerts,
            "alert_ordinals": [to_ord[i] for i in alerts],
            "proposal_steps": psteps,
            "step_to_ordinal": {str(i): k for i, k in to_ord.items()},
            "decisions": [s["proposal"]["decision"] for s in merged["steps"]],
        }
    return out


def _load(paths: str) -> dict[str, dict]:
    by_id = {}
    for p in filter(None, paths.replace(",", ":").split(":")):
        data = json.loads(Path(p).read_text())
        for t in data if isinstance(data, list) else [data]:
            by_id[t["id"]] = t
    return by_id


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--detector", required=True)
    ap.add_argument("--traces", default="eval/final/traces.json", help="JSON file(s), colon- or comma-separated")
    ap.add_argument("--ids", required=True, help="comma-separated trace ids")
    ap.add_argument("--out", required=True)
    ap.add_argument("--results", default=str(DEFAULT_RESULTS), help="results.json with the D2/D3 calibration")
    ap.add_argument("--embedder", choices=("minilm", "stub"), default="minilm")
    ap.add_argument("--frozen", default=None, help="frozen_models.json: use the exact frozen D3-D7 the live monitor runs")
    ap.add_argument("--registry", default=None,
                    help="destination registry JSON (D8/D9 only): ONE file for all ids; it must lint clean (server/registry.py)")
    a = ap.parse_args(argv)
    if a.detector not in DETECTORS:
        ap.error(f"unknown detector {a.detector!r}; choose from {DETECTORS}")
    if a.registry is not None:
        if a.detector not in REGISTRY_DETECTORS:
            ap.error(f"--registry applies to {REGISTRY_DETECTORS} only, not {a.detector}")
        from server.registry import Registry

        try:
            reg = Registry.load(a.registry)
        except (OSError, ValueError) as exc:
            ap.error(f"cannot read registry {a.registry}: {exc}")
        errs = reg.validate()
        if errs:
            ap.error(f"registry {a.registry} has {len(errs)} lint error(s): {'; '.join(errs[:5])}")
    if a.detector in REGISTRY_DETECTORS and a.embedder == "stub":
        ap.error(f"{a.detector} needs the real MiniLM embedder (hashed stub vectors carry no semantics)")
    by_id = _load(a.traces)
    ids = [i for i in a.ids.split(",") if i]
    missing = [i for i in ids if i not in by_id]
    if missing:
        ap.error(f"trace ids not found in {a.traces}: {missing}")
    out = expectations(a.detector, [by_id[i] for i in ids], load_thresholds(a.results), a.embedder, a.frozen, a.registry)
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(f"wrote {a.out}: {len(out)} traces, {sum(len(v['alert_steps']) for v in out.values())} alert steps", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
