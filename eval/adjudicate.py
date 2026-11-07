"""Resolve final labels by majority vote of generator + two blind reviewers.

python -m eval.adjudicate --out eval/final
Writes eval/final/traces.json (labels/decisions updated), eval/final/ADJUDICATION.md (every disagreement)
and eval/final/adjudication.json (machine-readable stats). Seeds are never relabelled.
"""
import argparse
import glob
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def majority(votes: list[str]) -> str:
    c = Counter(votes)
    return c.most_common(1)[0][0]


def adjudicate(traces: list[dict], reviews: dict[str, dict[str, dict]]) -> tuple[list[dict], list[dict], dict]:
    """reviews: {reviewer_name: {trace_id: {step_idx(str): {"label":..}}}}"""
    out, disagreements = [], []
    stats = Counter()
    for t in traces:
        t = json.loads(json.dumps(t))
        for s in t["steps"]:
            p = s["proposal"]
            if not p or p["label"] == "denied_seed":
                continue
            gen = p["label"]
            votes = {"generator": gen}
            for name, rv in reviews.items():
                lab = rv.get(t["id"], {}).get(str(s["i"]), {}).get("label")
                if lab:
                    votes[name] = lab
            final = majority(list(votes.values()))
            stats["steps"] += 1
            if len(set(votes.values())) > 1:
                stats["any_disagreement"] += 1
                disagreements.append({"id": t["id"], "step": s["i"], "tool": p["tool"], "votes": votes, "final": final,
                                      "why_generator": p.get("why", "")})
            if final != gen:
                stats["changed_vs_generator"] += 1
                p["label"] = final
                p["decision"] = "deny" if final == "violation" else "approve"
            stats[f"final_{final}"] += 1
        out.append(t)
    return out, disagreements, dict(stats)


def kappa(a: list[str], b: list[str]) -> float:
    n = len(a)
    if not n:
        return float("nan")
    po = sum(x == y for x, y in zip(a, b)) / n
    labs = set(a) | set(b)
    pe = sum((a.count(l) / n) * (b.count(l) / n) for l in labs)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", default=str(ROOT / "traces" / "gen_*.json"))
    ap.add_argument("--reviews", default=str(ROOT / "review" / "r*_set*.json"))
    ap.add_argument("--out", default=str(ROOT / "final"))
    a = ap.parse_args()
    traces = [t for f in sorted(glob.glob(a.traces)) for t in json.loads(Path(f).read_text())]
    reviews: dict[str, dict] = {}
    for f in sorted(glob.glob(a.reviews)):
        name = Path(f).stem.split("_")[0]
        for r in json.loads(Path(f).read_text()):
            reviews.setdefault(name, {})[r["id"]] = r["labels"]
    final, dis, stats = adjudicate(traces, reviews)
    # agreement between the two reviewers and generator-vs-majority
    pairs = [(d["votes"].get("r1"), d["votes"].get("r2")) for d in dis if "r1" in d["votes"] and "r2" in d["votes"]]
    outdir = Path(a.out)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "traces.json").write_text(json.dumps(final, indent=1))
    (outdir / "adjudication.json").write_text(json.dumps({"stats": stats, "disagreements": dis}, indent=1))
    lines = ["# Label adjudication", "", f"Labeled steps: {stats.get('steps', 0)}; any disagreement: {stats.get('any_disagreement', 0)}; "
             f"final label differs from the generator's: {stats.get('changed_vs_generator', 0)}.", "",
             "| trace | step | tool | votes | final |", "|---|---|---|---|---|"]
    for d in dis:
        lines.append(f"| {d['id']} | {d['step']} | {d['tool']} | {d['votes']} | {d['final']} |")
    (outdir / "ADJUDICATION.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(stats))


if __name__ == "__main__":
    main()
