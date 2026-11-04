# T01 spec-compliance review (D9b / D9c) vs SPEC_V3 and the ticket

Reviewer scope: read-only. I did not open eval/traces_v3, eval/final_v3, eval/review_v3 or eval/registries_v3.
Environment for all commands: `OMP_NUM_THREADS=1 HF_HUB_OFFLINE=1`.

## Acceptance criteria

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| 1 | D9b == D9 except constraint (e); disabled => D9's weights/threshold within 1e-9 | MET | `RegistryLearnedB(max_e=None)` delegates to `D2.calibrate_single` (detectors_registry_v3.py:50-52); lambda selection, standardisation, logistic fit, `max(in-sample, OOF)` threshold are line-for-line D9's `fit` (detectors_registry.py:356-407 vs v3:~108-150). Test `test_d9b_without_extra_constraint_equals_d9` passes (rerun: 1 passed; full v3 test files: all pass). Real data: `fit_registry_v3` re-fits D9 with the same seed and reports "identical weights and threshold" against `eval/results_registry/frozen_registry_models.json` (D9 thr 0.4197, lambda 1); the run reproduced this. Eval-side: the D9b path adds a `_verify` step that D9 does not have (see F5), not a difference in fitting. |
| 2 | D9c: exactly 3 seeded 30% dropout copies per dev trace, originals kept | MET | `AUG_SEEDS=(101,102,103)`, `AUG_FRACTION=0.30` (v3:37-39); `augment_traces` makes one copy per seed using `run_eval_registry._pooled(..., REG.degrade, 0.30, seed)` (the same pooled-dropout as the scored v2 drop30 condition). `RegistryLearnedC.fit` builds the table from `traces + aug` (originals kept). Tests: `test_augment_makes_exactly_three_seeded_copies_and_keeps_originals`, `test_augment_drops_thirty_percent_of_pooled_entries_per_copy`, `test_d9c_trains_on_originals_plus_three_copies`, `test_d9c_uses_the_registry_dropout_in_training_tables`. Real fit: 101 originals + 303 copies, 1112 rows (FIT_REPORT_V3.md). |
| 2b | CV grouped by ORIGINAL id (SPEC_V3) | MET | `_fit_table` builds folds over `sorted(set(orig_of.get(t,t)))` and maps rows through `fold_of_traces` (v3:68-72, 104-111). Tests `test_d9c_cv_folds_are_grouped_by_original_trace_id` (copy and original share a fold). `test_d9c_cv_never_splits_a_group` is weak (only asserts fit_logistic was called; its own comment says grouping is asserted elsewhere) -> F6. |
| 3 | Dev FA overall <= 5%, (c) <= 10%, (e) <= 10% for both; else infeasible, never silently relaxed | MET | Independent recompute from the committed frozen file (loaded with `load_frozen_registry_v3`, scored on a fresh `RegStepTable` of the 101 original dev traces, ex1 for dev v2 only): D9b overall 3/866 = 0.35%, (c) 3/202 = 1.5%, (e) 3/35 = 8.6%; D9c overall 3/866 = 0.35%, (c) 3/202 = 1.5%, (e) 2/35 = 5.7%. All within bounds; matches FIT_REPORT_V3.md. Infeasible path: `calibrate_single_e` returns +inf, `_verify` forces threshold +inf and `feasible=False`, CLI exits 3 and still writes report; tests `test_calibrate_single_e_infeasible_is_inf_not_relaxed`, `test_d9b_infeasible_constraint_is_reported_and_never_alerts`, `test_d9c_infeasible_reported`, `test_infeasible_constraint_is_reported_with_nonzero_exit`, `test_roundtrip_preserves_infinite_threshold`. Caveat: "independent" recompute reuses `RegStepTable` for features/labels (bucket definitions are shared with D9); I did not re-derive bucket (e) membership by hand. `TRAP_CATEGORIES` drives (e) (detectors_registry.py:200), same as the scored runs. |
| 4 | Deterministic | MET | `test_d9b_deterministic`, `test_d9c_deterministic_and_differs_from_d9b`, `test_cli_deterministic` (byte-identical json + report). Real data: reran `python -m eval.fit_registry_v3 --v1 eval/final/traces.json --v2 eval/final_v2/traces.json --reg1 eval/registries_v2/ex1.json --out <scratch>` (22 s); `cmp` of `frozen_registry_models_v3.json` and `FIT_REPORT_V3.md` against `eval/results_registry_v3/` => byte-identical (both). |
| 5 | Fit sees only v1/v2 DEV traces (spy test + byte-identical under TEST perturbation) | MET (with notes) | `fit_all` filters with `split_for(id) == "dev"` (sha1 parity of the id only, so content cannot influence the split: no leak path); registries are restricted to dev v2 ids (fit_registry_v3.py:~75). Tests: `test_only_dev_traces_reach_the_fit` (spies on `RegStepTable.__init__` ids incl. `~aug` copies, and on every embedded text, asserting no TEST marker text), `test_perturbing_test_traces_leaves_frozen_output_byte_identical` (perturbs TEST traces text/why/args/task and TEST registries). Grep of the four implementation/test files for `final_v3|traces_v3|review_v3|registries_v3`: no hits. Notes: TEST traces ARE loaded into memory by `load_traces` before filtering (never featurised; acceptable) -> F7; the CLI accepts arbitrary `--v1/--v2` globs and has no guard against v3 paths -> F3. |
| 6 | load/dump round trip | MET | `test_roundtrip_and_loader_shape` (weights, threshold, lambda, seed, constraints, per-step alert+score identical, dump twice => identical bytes), `test_loader_rejects_wrong_feature_set`. On the real frozen file: `load_frozen_registry_v3` then `to_dict()` gave identical weights and thresholds for D9b and D9c (ran). |
| 7 | Works with the live-monitor loader API shape `load_frozen_registry_v3(path, embedder, registry, only=[...])` | MET | Signature at v3 bottom; same call shape as `DR.load_frozen_registry`; `only=["D9c"]` and registry given as dict/Registry/None exercised in `test_roundtrip_and_loader_shape`. I did not exercise the actual monitor integration (not part of T01). |
| - | Must not edit eval/detectors_registry.py / run_eval_registry.py | MET | `git diff --stat` for both: empty; `git status`: only new untracked files (v3 modules, tests, results, plus `eval/check_v3_integrity.py`, `docs/v3/INTEGRITY_CHECKS.md` which are outside T01). Reuse of `_pooled` is a private import (F8). |
| - | Frozen file + a fit report written to eval/results_registry_v3/ | MET | Both present and reproducible. |

## SPEC_V3 statements

| Statement | Verdict | Evidence |
|---|---|---|
| D9b = D9's model + (e) <= 10% added to dev calibration | MET | see #1, #3 |
| D9c = D9b + 3 fixed-seed 30% dropout copies, originals kept | MET | see #2 |
| CV grouped by original id | MET | see #2b |
| Fitted on v1 dev + v2 dev with the `full` extractor-1 registries only | MET | `fit_all`: v1 dev + v2 dev, `reg1` = ex1.json filtered to dev v2 ids; 17 of 34 dev v2 traces have entries (27 entries), v1 dev use defaults, exactly as the frozen D9 was fitted. Inputs: ex1 sha256 285271ed... matches the report. |
| No silent relaxation | MET | see #3; every constraint failure sets +inf and `feasible=False`, plus nonzero exit. The `--max-e` CLI flag is only for tests (F4). |
| Determinism | MET | see #4 |
| Provenance hashes (Amendment 3: "records the sha256 of every input in the frozen file ... runner verifies the frozen file's recorded inputs are exactly the allowed v1/v2/ex1 files with matching hashes and contain no v3 file") | PARTIALLY | The frozen file's `_meta.inputs_dev_sha256` holds only canonical-JSON hashes of the dev SUBSETS (v1 dev, v2 dev, ex1 dev registries) and NO file names/paths. The whole-file sha256 and the paths live only in FIT_REPORT_V3.md, not in the frozen file. I verified the whole-file hashes in the report match the files on disk (`sha256sum`: 4143fb45..., 318ab333..., 285271ed...). So a runner that checks "frozen file records exactly the allowed files" cannot do so from the frozen file alone -> F1. |

## Claims in FIT_REPORT_V3.md

| Claim | Verdict | Evidence |
|---|---|---|
| Operating point table (thresholds, FA, recalls, denominators 866/202/35) | TRUE | reproduced byte-for-byte by the rerun; FA recomputed from the frozen file as above |
| "D9 re-fit identical to frozen D9" | TRUE | rerun printed it; D9 threshold 0.4197 equals frozen D9 |
| "Test traces were not read" | OVERSTATED | TEST traces are loaded into memory and dropped before use; never featurised/embedded (spy test). Wording should be "not used". F7 |
| 101 dev traces (67 v1, 34 v2), 17 with entries, 27 entries | TRUE | meta and recompute (101 dev, 17 registries) |
| Caveat that D9c weights traces without registries 4x | TRUE and well disclosed | copies are identical to originals |
| D9c recall is not lower than D9b by more than a hair; D9b/c recall drop vs D9 (73.6 / 71.7% vs 96.2% first-violation) | TRUE, but worth flagging | cost of constraint (e) is large (about -23 points of in-sample first-violation recall); report states it, no spin |

## Findings

| ID | Severity | Finding |
|---|---|---|
| F1 | should-fix | Provenance is weaker than Amendment 3 promises: frozen file lacks input file names and whole-file sha256 (only dev-subset hashes). The v3 runner cannot "verify the frozen file's recorded inputs are exactly the allowed v1/v2/ex1 files" from the frozen file; it would have to trust FIT_REPORT_V3.md. Fix by adding the file map (`files` dict from `main`) to `_meta`, which would change the frozen bytes (acceptable only BEFORE v3 scoring; otherwise record the mapping in a separate sidecar and declare it). Alternatively amend SPEC_V3 wording to say dev-subset hashes. Not blocking for detector correctness: the weights and thresholds are reproducible and the dev-subset hashes are present. |
| F2 | note | Independent recomputation reused `RegStepTable`/bucket definitions. Bucket (e) is `is_c & category in TRAP_CATEGORIES`, consistent with the scored D9 protocol. Dev (e) denominator is only 35 steps, so "<= 10%" means <= 3 alerts; D9b sits at the limit (3/35). Dev-fit rates are in-sample and say little about v3 FA. |
| F3 | should-fix | CLI has no guard rejecting v3 paths (`--v1/--v2` globs unchecked); blindness rests on the operator's discipline and on tests. A 3-line check (`any("_v3" in p ...)`) would make "blind by construction" enforceable. |
| F4 | note | `--max-e`, `--seed`, `--embedder` are overridable on the CLI; the committed frozen file records `constraints`, `seed`, `embedder` in `_meta`, so a deviating run would be visible. Default `--embedder minilm` is what was used (`all-MiniLM-L6-v2`). Fine. |
| F5 | note | D9b/D9c differ from D9 beyond "the extra constraint" in two documented ways: (i) fail-safe +inf if dev rates exceed bounds after the threshold is chosen (`_verify`; D9 has no such check), (ii) D9c takes the max over four calibrations (pooled and original-only rows, in-sample and OOF) so (c)/(e)/overall hold on the originals. Both are conservative and disclosed in the module docstring; ticket criterion 3 requires (i). (ii) makes D9c's threshold slightly more conservative than a plain D9b-on-augmented-rows would be; fine, but it is a design choice the spec does not state. |
| F6 | should-fix (test quality) | `test_d9c_cv_never_splits_a_group` asserts nothing about grouping (only that `fit_logistic` was called; the comment admits it). Grouping is covered by `test_d9c_cv_folds_are_grouped_by_original_trace_id`, which tests `fold_of_traces` and the stored folds but not that `_fit_table` actually used them for the training/validation masks. Replace with a spy on `fit_logistic` checking that no validation row's original id is in the training rows. |
| F7 | note | Report says "Test traces were not read" but `load_traces` reads them (then discards). Reword to "not used". |
| F8 | note | `detectors_registry_v3` imports the private `_pooled` from `run_eval_registry` (frozen module), and `_enc/_dec` from `detectors_v2`. Acceptable (reuse of scored code is the point) but fragile if those modules are ever refactored. |

No BLOCKING findings: all seven acceptance criteria are met, the frozen file is byte-reproducible from the declared v1/v2 dev inputs, thresholds satisfy the FA bounds on the original dev rows, and weights round-trip.

## Verdict

APPROVE (with should-fix items F1, F3, F6; F1 needs a decision before the v3 runner is written because Amendment 3 relies on it).
