"""Every user workflow has a LIVE test, and the gate proves it RAN (docs/TESTING_REALITY.md, "definition of done").

    python scripts/check_live_coverage.py                    static: the map is complete, every referenced file exists, every live spec is run
    python scripts/check_live_coverage.py --junit DIR        runtime: every live pytest node id in the map PASSED in the junit XML of this gate run

The map (tests/live/WORKFLOWS.json): workflow id -> {"title", "live": [...], "optional": [...], "gap": "<reason>", "note": "..."}. An entry is a
pytest node id (`tests/x/test_y.py::test_z`, `...::Class::test_z`, a whole file, or a parametrised function = all its cases) or a playwright spec.
Static (an early gate stage) fails when a required workflow is missing, has no `live` entry and no non-empty `gap`, a referenced file does not
exist, or a `live` spec is run by no MANDATORY `npx playwright test` stage of verify.sh (a spec that skips itself without its *_STAGE variable
needs a stage that filters for it; journeys and other opt-in stages count only for `optional`).
Runtime (a late gate stage, after the reality stages wrote `--junitxml` into DIR) fails when a `live` pytest entry is missing from the junit files
or any of its cases did not pass (skipped, xfail, failed, error). Limit: a test that passes vacuously (an early `return`) still passes; only review
and the mutants catch that. Optional entries are only checked for existence."""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ("O1", "O2", "O3", "O4", "O5", "O6", "D1", "D2", "D3", "D4", "A1", "A2", "A3", "L1", "L2", "L3", "P1")
_RUN = re.compile(r'^\s*(?P<optin>\[ "\$\{RUN_\w+:-0\}" = "1" \] && )?run "[^"]*" (?P<cmd>.*)$')
_PW = re.compile(r"npx playwright test((?:\s+[\w./-]+)*)")


def _is_spec(entry: str) -> bool:
    return entry.endswith(".spec.ts")


def playwright_runs(verify: Path) -> list[tuple[bool, list[str]]]:
    """(opt-in?, filters) for each `npx playwright test [filters]` in a verify.sh stage; `npm run journeys` is (opt-in?, ["journeys/"])."""
    out = []
    for line in verify.read_text().splitlines():
        m = _RUN.match(line)
        if not m:
            continue
        optin = bool(m["optin"])
        for pw in _PW.finditer(m["cmd"]):
            out.append((optin, [f for f in pw[1].split() if not f.startswith("-")]))
        if "npm run journeys" in m["cmd"]:
            out.append((optin, ["frontend/journeys/"]))
    return out


def _spec_run(spec: str, root: Path, runs) -> list[bool]:
    """opt-in flags of the stages that run `spec`."""
    gated = re.search(r"^test\.skip\(\s*process\.env\.", (root / spec).read_text(), re.M) is not None
    hits = []
    for optin, filt in runs:
        if spec.startswith("frontend/journeys/"):
            if "frontend/journeys/" in filt:
                hits.append(optin)
        elif spec.startswith("frontend/e2e/") and "frontend/journeys/" not in filt:
            if (not filt and not gated) or any(re.search(f, spec) for f in filt):
                hits.append(optin)
    return hits


def check_static(map_path: Path, verify: Path, root: Path, required: tuple[str, ...] = REQUIRED) -> list[str]:
    errs = []
    wf = json.loads(map_path.read_text()).get("workflows", {})
    errs += [f"{wid}: missing from {map_path.name}" for wid in required if wid not in wf]
    runs = playwright_runs(verify)
    for wid, w in wf.items():
        live, optional, gap = w.get("live", []), w.get("optional", []), str(w.get("gap", "")).strip()
        if not live and not gap:
            errs.append(f"{wid} ({w.get('title', '')}): no live test that a mandatory gate stage runs, and no explicit \"gap\"")
        for entry, is_opt in [(e, False) for e in live] + [(e, True) for e in optional]:
            path = entry.split("::")[0]
            if not (root / path).is_file():
                errs.append(f"{wid}: {path} does not exist")
            elif _is_spec(entry):
                hits = _spec_run(entry, root, runs)
                if not hits:
                    errs.append(f"{wid}: no verify.sh stage runs {entry}")
                elif all(hits) and not is_opt:
                    errs.append(f"{wid}: {entry} runs only in an opt-in stage; list it under \"optional\"")
    return errs


def junit_outcomes(junit_dir: Path) -> dict[str, str]:
    """node id (tests/x/test_y.py::Class::name[param]) -> passed | skipped | failed, from every *.xml in junit_dir; a node id seen more than once
    keeps its first non-passed outcome."""
    out = {}
    for f in sorted(junit_dir.glob("*.xml")):
        for tc in ET.parse(f).getroot().iter("testcase"):
            cls, name = tc.get("classname", ""), tc.get("name", "")
            parts = cls.split(".")
            k = next((i for i in range(len(parts), 0, -1) if parts[i - 1].startswith("test_")), len(parts))   # module = last test_* part
            node = "/".join(parts[:k]) + ".py::" + "::".join(parts[k:] + [name])
            tags = {c.tag for c in tc}
            o = "failed" if tags & {"failure", "error"} else "skipped" if "skipped" in tags else "passed"
            if out.get(node, "passed") == "passed":          # seen twice (two stages, a rerun): any non-passed outcome wins
                out[node] = o
    return out


def _covers(entry: str, node: str) -> bool:
    """A file covers its tests, a function its parametrised cases, a class its methods."""
    return node == entry or node.startswith(entry + "::") or node.startswith(entry + "[")


def check_runtime(map_path: Path, junit_dir: Path) -> list[str]:
    errs, res = [], junit_outcomes(junit_dir)
    if not res:
        return [f"no junit test cases in {junit_dir}: the reality stages did not run (or did not write --junitxml)"]
    for wid, w in json.loads(map_path.read_text()).get("workflows", {}).items():
        for entry in w.get("live", []):
            if _is_spec(entry):
                continue
            cases = {n: o for n, o in res.items() if _covers(entry, n)}
            if not cases:
                errs.append(f"{wid}: {entry} did not run in this gate (not in any junit file)")
            for n, o in sorted(cases.items()):
                if o != "passed":
                    errs.append(f"{wid}: {n} {o} (a live test must PASS, not skip or xfail)")
    return errs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--map", type=Path, default=ROOT / "tests/live/WORKFLOWS.json")
    ap.add_argument("--verify", type=Path, default=ROOT / "scripts/verify.sh")
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--junit", type=Path, help="directory of junit XML written by this gate run's reality stages: prove the live tests ran and passed")
    a = ap.parse_args(argv)
    errs = check_runtime(a.map, a.junit) if a.junit else check_static(a.map, a.verify, a.root)
    for e in errs:
        print("NOT COVERED ", e)
    wf = json.loads(a.map.read_text()).get("workflows", {})
    gaps = [k for k, w in wf.items() if str(w.get("gap", "")).strip() and not w.get("live")]
    print(f"live coverage ({'ran and passed' if a.junit else 'static'}): {len(wf)} workflows, {len(errs)} problem(s), declared gaps: {gaps or 'none'}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
