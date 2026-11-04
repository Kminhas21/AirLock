# T06 re-review (eval/run_eval_v3.py after the B1/B2 fixes)

Reviewer: independent re-check. No run on eval/final_v3 or eval/registries_v3; no v3 scores read. All experiments used synthetic stub-embedder fixtures
(the test file's `scenario` fixture, probe files under `.../scratchpad/re/`, mutation copy under `.../scratchpad/mut_t06_re/`). The only real-file touch was
`provenance_guard` on the real frozen files with an EMPTY v3 file list (passed, frozen_v3 sha256 6864d477...40ee). No repo file other than this one was modified.
Env: OMP_NUM_THREADS=1 HF_HUB_OFFLINE=1.

## Verdict: APPROVE FOR SCORING

Blocking items: none.

## Test runs
- `tests/eval/test_eval_run_v3.py`: 124 passed, run twice (4.5 s, 4.7 s).
- `python -m pytest tests/eval -o addopts="" -q`: 734 passed (51 s).

## (1) B1 closed
Own probes (`re/test_b1.py`, end-to-end through `main` with the real `run`, 5 passed):
- Report rendering raises: nothing on disk (no marker, no report, no .tmp); a plain rerun (no `--post-hoc`) then exits 0 and writes REPORT_V3.md + results_v3.json.
- NaN/inf in the result (`allow_nan=False` ValueError): serialisation happens before any write, nothing on disk, plain rerun exits 0.
- Marker write fails (`os.replace` of results_v3.json raising KeyboardInterrupt; separately `fsync` raising OSError on the second file): the already-written report is removed, the temp file is removed, directory empty, plain rerun exits 0. BaseException is handled.
- Overwrite protection: a pre-existing results_v3.json, REPORT_V3.md, results_v3_posthoc.json or REPORT_V3_POSTHOC.md each gives exit 4 and the file is untouched and nothing else is created. With only the originals present, `--post-hoc` works and leaves the originals unchanged; a second `--post-hoc` gives 4; `--post-hoc --post-hoc-force` gives 0; then a plain run is still 4.
- Order: REPORT first, results_v3.json (the marker) last, both via temp file + fsync + `os.replace`.
- Residual (non-blocking, nit): a hard kill (SIGKILL, power loss) in the instant between the two renames would leave REPORT_V3.md without the marker; a plain rerun is then refused with exit 4 (the report may already contain scores, so refusing is the conservative outcome). A stale `*.tmp` could also remain after a hard kill. Neither can occur through any Python exception.

## (2) B2 closed: 55 own mutants, 0 survivors
Scratch copy of eval/ server/ tests/ pytest.ini; each mutant run against `tests/eval/test_eval_run_v3.py` (baseline in the copy: 124 passed). All 55 KILLED:
- Thresholds: C1 55->50, C2 85->80, C3 5->6, C4 10->12, C5 10->12, C6 20->25, C7 15pp->10pp, C8 margin 5->10, C9 100->200 ms; `_ge` / `_le` EPS sign flips.
- Floors: C6 15->14 and ->16, C8 8->7 and ->9, C6 floor bypassed (`if True`), insufficient counted as fail.
- Strata precedence: stale over listed, missing-first, stale never detected.
- Bootstrap N_BOOT 2000->1000; C7 CI bound `>0` -> `>=0`, and CI condition dropped.
- Selection: tie order reversed, FA tie-break direction, on-time strict `>` -> `>=`; authored2/oracle applying selection; PRIMARY = oracle.
- Verdict wording: `recommended_default` set, PROVISIONAL removed from the qualifies message, from the shortfall message, `provisional` flag False.
- Metrics sources: C8 d3 + margin, D3 baseline taken from the candidate, C2 reading `missing`, C9 from D1, gain over D7 fed from D3, `fa_in` denominator +1, bucket (c) widened to (b), trap category renamed, C6 population ignoring the denial or accepting `external`, `none` keeping its entries.
- Operational: json written before report, no report cleanup on marker failure, post-hoc check on only one file of the pair (both directions), exit 4 -> 0, exit 3 -> 2, v3 trace parse inserted before the guard, hash comparison in the guard skipped, `set_registry` check removed.

## (3) Criteria semantics unchanged
I diffed the current runner against the pre-fix baseline copy kept in the scratchpad (`mut_t06/base/eval/run_eval_v3.py`) and read every changed hunk, then compared constants and logic with SPEC_V3 + Amendments 1-3 line by line.
- Constants: C1 0.55, C2 0.85 (listed), C3 0.05, C4 0.10, C5 0.10 (bucket c restricted to benign_ext_v3), C6 0.20 with n >= 15 else `insufficient data`, C7 0.15 and CI lower bound > 0 vs D7, C8 D3 on-time minus 0.05 with n >= 8 traces else insufficient, C9 100 ms. All unchanged and equal to the spec.
- Strata: first violating proposal under the authored registry; listed (registered relay/external with a party) > stale (explicit `internal` entry) > missing. The only change is the added informational `no_tokens` flag (does not alter the stratum). C6 population (ok, strictly after a denial, via a registered `relay` entry) unchanged. Selection (highest on-time, lower overall FA, D8<D9<D9b<D9c) unchanged; PROVISIONAL / `recommended_default = None` unchanged.
- Other changed hunks are non-semantic or hardening: `fa_bucket` local copy of `metrics._bucket` (identical logic, pinned by a test), constants interpolated in prose, `score_candidate` (raises if no `set_registry`), absent-registry and lint warnings, atomic writes, exit-code handling, `--post-hoc-force`, report text additions.

## (4) Exit codes (end-to-end through `main`)
- 0: scored (prints "provenance guard PASSED", frozen sha256s, PROVISIONAL verdict).
- 2: `--latency-n 5`; `--post-hoc-force` without `--post-hoc`; missing `--author1` file; missing `--v2` file; v3 ids overlapping v1/v2 (an identical-file case is a guard refusal instead, 3); malformed/non-UTF8 inputs; a ValueError inside scoring. All print `error: ...` on stderr, no traceback.
- 3: missing frozen-v3 file, and every tamper case in (5), message begins "REFUSING TO RUN (provenance guard, SPEC_V3 AMENDMENT 3)".
- 4: existing output, message names the files and says use `--post-hoc` / `--post-hoc-force`.

## (5) Provenance guard
`re/test_exit.py` with the v3 traces replaced by an invalid-JSON file, so any parse of v3 before the guard would surface as exit 2: all of these give exit 3, the garbage file is never passed to `load_traces`, and no output directory is created: changed v1 dev traces, changed v2 dev traces, emptied ex1 registries, extra recorded key (`v3_traces`), missing recorded hash, no `_meta`, `final_v3` path inside the frozen file, sha256 of a v3 input inside the frozen file, `inputs_file_sha256` naming a non-allowed hash. Also exit 3 when a v3 file is identical to an allowed input. The real frozen files pass the guard with an empty v3 list. Guard order in `main` is unchanged: v1/v2/ex1 parsed, v3 files only byte-hashed, then guard, then v3 parse.

## (6) Diff skim for introduced bugs
None found. Points checked: the new `except (OSError, ValueError)` clauses come after `TraceLoadError`/`ProvenanceError`, so they cannot shadow the 2/3 paths; the broad ValueError catch around `run` turns a scoring ValueError into exit 2 with a message (no output written, rerun allowed), which is acceptable; `raw`/`allowed_hashes`/`frozen_sha` refactors in the guard keep the same returned values (sha of the primary file equals `file_sha256`); lint/absent warnings only read the registries and do not change scoring; `build_metrics` lost its unused `did` parameter and the single caller was updated.

## Nits (not blocking)
- Hard-kill window and stale `.tmp` described under (1).
- `except (OSError, ValueError)` around `run` could present a genuine ValueError bug as "error:" exit 2; the message is printed, so it is visible.

**APPROVE FOR SCORING**
