# T01 re-check (D9b / D9c) after the fix round

Env: `OMP_NUM_THREADS=1 HF_HUB_OFFLINE=1`. No v3 data opened or run. Mutations ran in a scratch copy
(`.../scratchpad/mut_t01_re/`); the only repo file written is this one. (One CLI guard probe used a glob into the v3
directory: the guard refused before any file was opened; only directory names were listed.)

## Run results
- T01 tests (detectors + guards + fit, 72 tests): all pass, twice in the repo, twice in the scratch copy.
- `python -m eval.fit_registry_v3 --v1 eval/final/traces.json --v2 eval/final_v2/traces.json --reg1 eval/registries_v2/ex1.json --out <scratch>`
  run twice: `frozen_registry_models_v3.json` and `FIT_REPORT_V3.md` byte-identical between the two runs AND to the files in
  `eval/results_registry_v3/` (`cmp`). D9b thr 0.8848, D9c thr 0.8556, both feasible; frozen file has no `NaN`, loads with the
  strict loader (`D9b`, `D9c`, `max_e` 0.1).

## (1) B1, B2, B3
My own mutations (different from the fixer's), 31 in total, applied to `eval/detectors_registry_v3.py` (one to `run_eval_registry._pooled`):

RED (caught): copy fold via crc32 / via char-sum hash instead of the original's fold; `cv_masks` ignoring `orig_of` (crc32 folds);
in-sample-threshold only (D9b and D9c-only variants); min instead of max (global and D9c-only); drop `_orig` subsets in
`candidate_thresholds`; dropout 0.30 -> 0.25; copies 3 -> 2; seeds reordered (103,102,101); seeds (101,102,104); `max_e` set to
`None` inside `candidate_thresholds` (the "drop the max_e check" mutation) and the D9c-only variant of it; (e) term removed from
`calibrate_single_e`; e limit -1; ties `left` vs `right`; fail-safe `threshold=inf` removed; `from_dict` not restoring `max_e`;
schema check off; NaN guard in `combine_thresholds` off; duplicate-id check off; originals dropped from the D9c table;
`_pooled` iterating `sorted(regs, reverse=True)` (caught by the golden augmentation digest).

Survivors (green), none of them touching the B1/B2/B3 mechanisms themselves:
| mutation | assessment |
|---|---|
| `_fit_table` combines only the OOF candidate / only the pooled candidates / only the `_orig` candidates (D9c call-site wiring) | The pure `combine_thresholds` / `candidate_thresholds` tests and `test_d9c_threshold_is_the_combination_of_its_recorded_candidates` kill min, in-sample-only and `max_e=None`, but on the synthetic fixture the real D9c has its largest candidate at the OOF/pooled value, so filtering the key set at the call site is not detected. Should-fix: one spy test (monkeypatch `V3.combine_thresholds`, assert it receives all four keys for D9c, two for D9b). Low risk: the line is `combine_thresholds(ts)` with `ts` straight from `candidate_thresholds`. |
| `_verify_and_failsafe` counts alerts on all rows (copies included) / uses `>=` | The original quality-review M19/N6. `test_verify_counts_original_rows_only` checks the denominators only. Non-blocking; the frozen D9c dev rates in the fit report are computed on original rows (D9c FA 0.3%, (c) 1.5%, (e) 5.7%). |
| lambda tie-break `-l` -> `l` | Inherited from D9; equality test with D9 is green on the fixture and on the real data D9 re-fit is reported identical. Non-blocking. |
| `base` dict reversed before `_pooled` | Equivalent mutation (`_pooled` sorts). |

B1: FIXED. `cv_masks` is the single construction point, and the instrumented D9c fit test checks that no original id is on both
sides and that `fit_logistic` receives exactly those standardised rows. All my fold mutations turn it (or the fold-grouping
test) red.
B2: FIXED for the rule itself (`combine_thresholds`, `candidate_thresholds` with a fixture where pooled/min/orig-only differ and the
(e) bound is binding with non-zero rates) and for the (e) dependence at detector level. The call-site wiring survivor above is the only
residue (should-fix, not blocking).
B3: FIXED. `schema_version = "registry_models_v3/1"`, loader raises `FrozenRegistryError` for missing/unknown schema, unknown id in the
file, absent/unknown `only`, wrong entry id (each tested, and the schema/id mutations go red); dump refuses ids other than D9b/D9c;
golden key list and golden augmentation digest pinned.

## (2) Determinism
Two runs plus the committed frozen file and report: byte-identical (see above).

## (3) Provenance
`_meta` has `inputs_dev_sha256` {v1_dev_traces, v2_dev_traces, reg1_dev_registries}, `augmentation_digest`, seeds, fraction, copies,
constraints, feature names, lambda grid, embedder. `F.dev_subset_digests(v1, v2, reg1)` on the real allowed files reproduces all four
values exactly. On a perturbed COPY of the v1/v2 traces (all 53 + 46 TEST traces changed: task and every agent_text) the refit
writes a frozen file byte-identical to `eval/results_registry_v3/frozen_registry_models_v3.json`, and `dev_subset_digests` still equals the
frozen `_meta`. (Only the informational whole-file hashes in `FIT_REPORT_V3.md` differ, by design.) Dev-change sensitivity is covered by
`test_dev_subset_digests_ignore_test_traces_but_see_dev_changes`.

## (4) CLI guard and loader
Exit 2, nothing written, for `--v1 eval/final_v3/...`, `--reg1 eval/registries_v3/...`, `--v2 eval/traces_v3/*.json` (glob), a symlink
resolving into a v3 dir, and `--max-e nan` / `-1`. Loader errors are strict as listed under B3.

## (5) Diff skim for new bugs
- `_check_rate` rejects NaN, bool and strings; `calibrate_single_e` with NaN scores, empty input, `max_e=None`: finite or `inf`, never NaN.
- `combine_thresholds` rejects NaN (including `np.float64`) and empty dict; `inf` wins. (np.float32 NaN would slip through the `isinstance(v, float)`
  test: not reachable, thresholds are Python/np.float64.)
- `candidate_thresholds` on empty arrays returns `inf` for both keys (consistent with the inherited D2 behaviour).
- `load_frozen_registry_v3` on a non-dict top-level JSON would raise `AttributeError` rather than `FrozenRegistryError` (cosmetic).
- Model parameters unchanged (frozen file regenerates identically; `D9` re-fit still "identical" to the frozen D9 of the v2 registry run).
- `tests/eval/test_eval_run_v3.py` fails collection (`eval.run_eval_v3` missing): other ticket, not T01.
No new defect found.

## Verdict
No blocking item. Should-fix (optional before freeze): the call-site wiring spy test for `combine_thresholds` in `_fit_table`; make
`_verify_and_failsafe` test alerts on copy rows.

APPROVE FOR FREEZE
