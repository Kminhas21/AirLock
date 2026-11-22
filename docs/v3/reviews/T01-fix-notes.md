# T01 fix notes (after the spec and quality reviews)

Scope: `eval/detectors_registry_v3.py`, `eval/fit_registry_v3.py`, `tests/eval/test_eval_registry_v3_*.py`
(new: `test_eval_registry_v3_guards.py`). No v3 data opened, no frozen/scored module edited. Model PARAMETERS are unchanged
(weights, biases, means, stds, thresholds, lambdas, cv_loss, cv_folds of D9b and D9c are identical, max abs diff 0.0).

## Decision: what the frozen file records, and how provenance is verified
The frozen file keeps hashes of the DEV subsets only (`_meta.inputs_dev_sha256`: v1 dev traces, v2 dev traces, dev-v2
ex1 registries, canonical JSON) plus `_meta.augmentation_digest` (golden sha256 of the 3 dropout copies: ids, original id,
step count, dropped registry). So it stays byte-identical when TEST traces change (tested). Whole-file sha256 and paths live in
`FIT_REPORT_V3.md` as INFORMATIONAL only. The v3 runner verifies provenance by RECOMPUTATION:
`eval.fit_registry_v3.dev_subset_digests(v1_path, v2_path, reg1_path)` (same code path as `fit_all`, tested to equal the
written `_meta`) over the allowed v1/v2/ex1 files, and compares with the frozen `_meta`. This resolves spec-review F1 without
changing SPEC_V3 Amendment 3's intent ("verifies the recorded inputs"): a v3 file cannot reproduce the recorded dev hashes.

## Findings and resolutions
| Finding | Resolution | Test |
|---|---|---|
| B1 CV leakage untested | `cv_masks(row_trace_ids, orig_of, folds)` is the single place that builds the train/validation masks used by the CV loop. The test instruments the real D9c fit (spies `cv_masks`, `_fit_table`, `D2.fit_logistic`): no original id on both sides of any split, and the arrays given to `fit_logistic` equal the standardised rows of those masks, in order | `test_d9c_cv_never_splits_a_group`, `test_cv_masks_unit_copies_follow_their_original` |
| B2 threshold rule untested | pure `combine_thresholds` and `candidate_thresholds`; fixture where (e) binds, FA rates are (e) 10%, (c) 5%, overall 2.5%, and pooled-only / `min` give 0.1 vs 0.95; detector-level test that D9b's threshold depends on `max_e` | `test_combine_*`, `test_candidate_thresholds_values_on_binding_fixture`, `test_e_constraint_binds_and_dev_rates_are_not_zero`, `test_d9b_threshold_depends_on_max_e`, `test_d9b_passes_max_e_to_the_calibration`, `test_d9c_threshold_is_the_combination_of_its_recorded_candidates` |
| B3 schema | `schema_version = "registry_models_v3/1"`; `_meta.augmentation_digest`; loader raises `FrozenRegistryError` (a `ValueError`) for missing/unknown schema, unknown detector id in file, `only` id unknown or absent from the file, entry id != key; dump refuses ids other than D9b/D9c; golden key list pinned | `test_loader_*`, `test_dump_refuses_*`, `test_frozen_file_has_schema_version_and_golden_keys`, `test_augmentation_digest_*` |
| S1 `_pooled` coupling | golden augmentation digest (pins seeds, fraction, `sorted(regs)` order, `degrade`); `_pooled` stays imported, not promoted (frozen module) | `test_augmentation_digest_is_golden_and_deterministic` |
| S2 `_fit_table` copy of D9.fit | comment naming what it mirrors; equality test also compares `cv_loss` and `cv_folds` | `test_d9b_without_extra_constraint_equals_d9` |
| S3 `_verify` | renamed `_verify_and_failsafe` (documented side effect); fail-safe tested; batch vs 1-row probabilities bit-equal tested (no `nextafter` needed, they are equal) | `test_failsafe_*`, `test_batch_and_row_probabilities_are_bit_equal`, `test_verify_counts_original_rows_only` |
| S4 e tests | non-zero limit (`ne=20` -> 2 allowed) and tie case | `test_calibrate_single_e_nonzero_limit_and_ties` |
| S5 OR / seeds | pairwise inequality; `AUG_SEEDS == (101,102,103)` literal | detectors tests |
| S6 one trace | `ValueError("need at least 2 original traces ...")` | `test_single_original_trace_is_a_clear_error` |
| S7 negative rates | rates validated in `[0,1]` (class, `calibrate_single_e`, CLI `--max-e` -> exit 2); infeasibility in tests now uses real single-class data or a monkeypatched calibration | `test_rates_are_validated`, `test_cli_rejects_out_of_range_max_e` |
| S8 NaN | single-class `cv_loss` is `None`; dump uses `allow_nan=False` and writes nothing on error | `test_no_nan_reaches_the_frozen_json` |
| N1/N2/N6/N7/N8/N9/N10/N11-partial | dead `_dec` removed, lambdas -> `def`, `glob` hoisted, `D9_FROZEN` resolved from `__file__`, report wording, fit_info keys documented, `cv_folds` equality tested | |
| N5 duplicates | `ValueError("duplicate trace ids")` in D9b/D9c fit and `fit_registry_v3.dev_inputs` (CLI exit 2) | `test_duplicate_trace_ids_are_rejected`, `test_fit_all_rejects_duplicate_dev_ids` |
| Spec F3 | CLI refuses any `--v1/--v2/--reg1` pattern, glob expansion or resolved path containing "v3" (exit 2, nothing written) | `test_cli_refuses_paths_marked_v3`, `test_cli_refuses_glob_into_v3_dir` |
| Spec F6, F7 | see B1; report now says "Test traces were loaded then discarded, never used" | `test_report_wording_about_test_traces` |

## Not done / disagreements
* N3 (sibling test-module imports): left; it works under the repo's `pythonpath` and the new test file follows the same pattern.
* N12 (code hash in `_meta`): not added. A code hash would make the frozen file change on any refactor, contradicting the
  decision above; the augmentation digest and parameter-identity check guard the behaviour that matters.
* Quality-review S3 suggestion `np.nextafter`: not needed; batch and row probabilities are bit-equal (test).
* Spec F2/F4/F5/F8: notes, no change. F5(ii) (max over four calibrations) is documented in the module docstring.
* `tests/eval/test_eval_run_v3.py` imports `eval.run_eval_v3`, which does not exist yet (another ticket); it fails at collection,
  independent of T01. It uses only `F.fit_all(...)["meta"]["inputs_dev_sha256"]`, which is unchanged.
