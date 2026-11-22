# T01 code-quality review: D9b / D9c (registry_learned_e, registry_learned_dropout)

Scope: `eval/detectors_registry_v3.py`, `eval/fit_registry_v3.py`, `tests/eval/test_eval_registry_v3_detectors.py`,
`tests/eval/test_eval_registry_v3_fit.py` (context: `eval/detectors_registry.py`, `eval/detectors_v2.py`,
`eval/run_eval_registry.py`). No v3 data opened. No real file edited; mutations were run in a scratch copy
(`/tmp/scratch_rev`, eval/ server/ tests/ copied).

## Run results
- 27 tests (21 detectors + 6 fit), `OMP_NUM_THREADS=1 HF_HUB_OFFLINE=1`: all pass.
- Wall time (whole pytest process) 1.79 s / 1.80 s / 1.72 s over three runs; slowest single test 0.17 s. No flakiness: identical
  results over 5 runs, also under `PYTHONHASHSEED=1` and `=777`. Each file also passes when run alone, and the detectors file
  passes when run from inside `tests/eval/` (the `from test_eval_registry_detectors import ...` imports work because of
  `pytest.ini: pythonpath`/rootdir conftest, see nit N3).
- Code behaviour read as correct: folds (`D2._folds` over sorted ORIGINAL ids, copy takes the fold of its original, so no
  copy/original leakage in the fit path), strict `>` everywhere (calibration `searchsorted(...,"right")`, `_verify`, `_step`),
  denominators (`n`=all non-violation steps incl. unscored NaN rows, `nc`, `ne` computed on the same `nonviol & subset` mask as
  `D2.calibrate_single`; `is_e` is a subset of `is_c`), no set/dict-order dependence (sorted ids, sorted tids in `_pooled`,
  result invariant to input order of traces: checked), no mutation of inputs (`_as_dict` deep-copies).
- Edge probes (scratch): empty trace list, all-proposal-free traces, `None` registries, no registries, all-empty-entry
  registries, `max_e=0`, `max_e=-1`: all return a model with `threshold=inf` or a finite feasible threshold, never NaN. Two
  crash/accept cases: 1 original trace (see S6) and duplicate trace ids (N5).

## Mutation results (scratch copy; "GREEN" = the whole suite still passes = test cannot fail for this bug)
RED (good): drop (e) term in `calibrate_single_e`; e-denominator `n` instead of `ne`; `ceil` instead of floor for the e limit;
`>=` tie rule in calibration; threshold min instead of max (D9b path only); fit on originals missing from table;
same seed for all three copies; per-trace instead of pooled dropout; copy id without `~aug<k>`; loader ignoring `only`;
fit using all traces / test v2 traces / test-trace registries (caught by the byte-identity test); exit code 3 dropped; meta seed.

GREEN (not caught), in priority order:

| # | mutation | what it means |
|---|---|---|
| N1 | D9c only: give each augmented copy a different fold than its original in `_fit_table` (line 128) | CV leakage between copies and originals passes all tests |
| N2 | D9c: threshold ignores the `_orig` (original-rows-only) calibration (line 162) | the headline D9c guarantee ("constraints hold on the original dev traces") is untested |
| N3 | D9c: `min` instead of `max` over the four calibrations | same |
| M3 | `subsets["_orig"]` never built (line 157) | same |
| M5 | `_verify` no longer forces `threshold = inf` when constraints are broken on dev (line 190) | fail-safe untested (only the already-inf path is exercised) |
| M19/N6 | `_verify` counts all rows instead of originals / uses `>=` | dev_rates and feasibility verdict untested for D9c |
| M8/N4 | D9b ignores `max_e` in the calibration but not in `_verify` | only the fit CLI test goes red (via an INFEASIBLE exit), no detector-level test shows that (e) changes the threshold |
| M9 | e limit off by one (`_allowed(ne)-1`) | unit test for e uses `ne=2` only, so the bound `floor(0.1*ne)` is not tested at a non-zero limit |
| M15 | `from_dict` does not restore `max_e` | constraints round-trip untested (only the JSON text is) |
| N9 | `AUG_SEEDS` changed to (101,102,104) | the tests compare `AUG_SEEDS` with itself; the frozen seeds are not pinned |
| N11 | `dump_frozen_registry_v3` writes every detector it is given | the `("D9b","D9c")` filter is untested |
| _pooled | `tids = sorted(regs, reverse=True)` in `run_eval_registry._pooled` | D9c silently trains on different dropout copies, all 27 tests still green |

## Findings

### BLOCKING

**B1. The D9c "CV grouped by original id" guarantee is not tested where it matters.**
`tests/eval/test_eval_registry_v3_detectors.py:189-199` (`test_d9c_cv_never_splits_a_group`) only asserts `seen` is non-empty,
a spy on `fit_logistic` that cannot fail (its own comment admits it). Lines 177-186 test `fold_of_traces` in isolation, but
`_fit_table` line 128 could ignore it (mutation N1/M4-for-D9c) and everything stays green. Suggested change: delete the spy test
and replace with a test that spies `D2.fit_logistic` (or better, `D2._sigmoid` inputs) during `RegistryLearnedC.fit` and
checks that for every CV call the set of original ids in the validation rows is disjoint from the set of original ids in the
training rows (derive the original id from `tab.trace_ids`/`orig_of`, e.g. by monkeypatching `RegStepTable.__init__` to capture
`trace_ids`, or by refactoring the fold assignment out into a small pure method `_row_folds(tab, orig_of, folds)` that the test calls
and the fit uses). Negative control to keep: N1 and M4 must turn it red.

**B2. The D9c threshold rule (max over pooled and original-only, in-sample and out-of-fold) has no test.**
`eval/detectors_registry_v3.py:155-164`. Mutations N2, N3 and M3 are all green. The module docstring (lines 14-16) and the report
promise the constraints hold on the original dev traces, and the only assertion is `test_d9c_meets_constraints_on_original_dev_traces`
(lines 202-205), which is vacuous on the synthetic data (all three measured rates are exactly 0.0, so `<= 0.05/0.10` is trivially true;
verified: D9b `dev_rates` fa/fa_c/fa_e = 0). Suggested change: (a) extract the combination into a pure function, e.g.
`combine_thresholds(ts: dict) -> float` and unit-test it with hand-made dicts (max wins, `inf` wins, `_orig` keys honoured);
(b) add a D9c test on a hand-built table where the pooled set is easy (copies dominate) but the originals alone are hard, and
assert `fit_info['threshold_in_sample_orig']`/`threshold_oof_orig` exist and `threshold >= each of them`; (c) make the rate
tests non-vacuous: assert the constraint BINDS, e.g. that `d9b.threshold > d9.threshold` strictly on a fixture where (e) steps
score above the D9 threshold (the current `>= ... - 1e-12` at line 106 is satisfied by a no-op), and that dev FA counts are
`== floor(limit)` at least once.

**B3. The frozen file has no schema version and the loader accepts anything.**
`eval/detectors_registry_v3.py:232-245`. `_meta` is free-form (`meta or {}`), there is no `schema`/`version` key, no code or
feature-set hash beyond `feature_names`, and `from_dict` never checks `d["id"]`. The loader silently returns `{}` entries for
names missing from the blob (`if k in blob`), so `load_frozen_registry_v3(path, emb, only=["D9c"])` on a file without D9c
returns `{}` with no error (the live-monitor call shape then fails later with a KeyError far from the cause). Because the file
is going to be frozen before data, adding a version later is itself a schema change. Suggested change: write
`out["_schema"] = "registry_models_v3/1"` (plus `AUG_SEEDS`, `AUG_FRACTION`, `AUG_COPIES`, `MAX_FA_E_B` already in meta, so keep
them in `_meta`), in the loader `raise ValueError` if `_schema` is missing or unknown, raise `KeyError(f"{k} not in {path}")` when an
`only` id is absent, and in `from_dict` assert `d.get("id") == cls.id`. Add tests for each (unknown schema, missing id, wrong id).
Also pin `test_roundtrip...` with a golden key list for one detector so an accidental schema change is visible.

### should-fix

**S1. Silent coupling to a private helper of a frozen module.** `eval/detectors_registry_v3.py:30,75` imports
`run_eval_registry._pooled`; `fit_registry_v3.py:29` imports `_load_registries`; plus `D2._enc/_dec/_allowed/_folds/_standardise/
_sigmoid/_bal_logloss/fit_logistic` and `DR._table_for/_enc/_dec`. Measured effects of editing `_pooled` in the scratch copy:
swapping the order of two params -> 3 ERRORs (loud, fine); changing the id separator -> 1 FAIL (fine); but `sorted(regs)` ->
`sorted(regs, reverse=True)` changes which entries every augmented copy drops and ALL TESTS STAY GREEN, i.e. a refit of D9c
after an innocent refactor would produce a different frozen model with no signal. Suggested change: add a golden test that pins the
augmentation output, e.g. a sha256 of `json.dumps({k: Registry.load(v).to_dict() ...}, sort_keys=True)` of
`augment_traces(dev, regs)` for the fixture (this also pins `AUG_SEEDS` literally, closing N9), and record that digest of the
actual augmented registries in `fit_all`'s `meta` (`aug_registries_sha256`). Optionally promote `_pooled` to a public
`pooled_degrade` (a one-line alias in `run_eval_registry.py` is a non-behavioural change to a frozen file, so it needs sign-off; if
not allowed, keep the golden digest as the guard).

**S2. `_fit_table` is a 55-line copy of `DR.RegistryLearned.fit`** (`detectors_registry_v3.py:110-167` vs
`detectors_registry.py:356-407`). The equality test (`test_d9b_without_extra_constraint_equals_d9`) protects D9b, but any future
change to D9 (frozen, so unlikely) or a bug fix in only one copy diverges silently. Acceptable given D9 is frozen; at minimum
add a comment at line 110 naming the exact lines of D9.fit it mirrors and keep the equality test, and extend it to also assert
`b.fit_info['cv_loss'] == d9.fit_info['cv_loss']` and equal `cv_folds`.

**S3. `_verify` mutates state and re-derives probabilities by a different code path than inference.** `detectors_registry_v3.py:169-193`:
it checks `prob > threshold` using the batch `predict_proba(tab.feats[...])`, while `_step` calls the 1-row path. The threshold is
exactly one of the observed batch probabilities and the test is strict `>`, so a 1-ulp difference between batch (gemm) and row
(gemv) arithmetic on another BLAS/thread count could flip a boundary row to an alert and break the FA bound at deployment.
Measured here: 0 differing values for 54 rows at `OMP_NUM_THREADS=1`, so low risk, but the freeze should be robust. Suggested
change: either compute `prob` in `_verify` row by row with the same call `_step` uses, or add a regression test that for every
scored row batch and 1-row probabilities are bit-equal (if not, calibrate with `np.nextafter(t, inf)`). Also `_verify` has side
effects (sets `self.threshold = inf`, line 190) that are invisible from the name: rename to `_verify_and_failsafe` or return the new threshold
and assign it in `_fit_table`. M5/M19 (untested) belong here: add a test that forces broken constraints on dev (for example by
monkeypatching `calibrate_single_e` to return `-inf`) and asserts `threshold == inf`, `feasible is False`, note contains
"constraints violated on dev".

**S4. Tests for (e) pass without (e).** `test_d9b_is_at_least_as_conservative_and_meets_e` (lines 103-110) is satisfied by a
D9b that ignores `max_e` (mutation M8 is green in this file; threshold equality passes `>=`). See B2(c). Likewise
`test_calibrate_single_e_binds_on_trap_steps` (lines 70-78) uses `ne=2` so `floor(0.10*2)=0`; add a case with `ne=20` expecting 2
allowed, and one with a tie (several equal scores at the threshold) to pin that ties are all-or-nothing.

**S5. `test_augment_drops_thirty_percent...` ends with an OR.** Line 154 `sets[0] != sets[1] or sets[1] != sets[2]` would pass with two identical
copies. Use pairwise inequality (`len({frozenset(s) for s in sets}) == 3`). Also line 131 compares `V3.AUG_SEEDS` and `AUG_FRACTION`
with literals only for fraction; pin `V3.AUG_SEEDS == (101, 102, 103)`.

**S6. Degenerate sizes.** `RegistryLearnedB/C().fit(one_trace)` raises `ValueError: cannot reshape array of size 0 ...` from the CV
(`_folds` returns one fold, the training part of every fold is empty; `_standardise` of an empty X). D9 has the same flaw, but D9b/D9c are the
new public entry points. Suggested change in `_fit_table` before line 128: `if len(folds) < 2: raise ValueError("need at least 2 original traces for grouped CV")`
(or return the explicit INFEASIBLE model), and a test.

**S7. Infeasibility is simulated with a negative rate.** Tests use `max_e=-1.0` (detectors lines 115, 217, 267; fit line 115; CLI `--max-e -1`).
`D2._allowed(24,-1.0)` is `-23`, a nonsensical bound that happens to never be met; the default type allows it silently. Validate in
`__init__`/`calibrate_single_e` (`0 <= max_e <= 1`, raise `ValueError`) and construct infeasibility in tests through real data
(for example base alerts exceeding the limit, as `test_calibrate_single_e_infeasible_is_inf_not_relaxed` already does) or `max_e=0.0` with
an (e) step that outscores every non-(e) step.

**S8. `NaN` can reach the frozen JSON.** `cv_loss` is `math.nan` in the single-class branch (line 124) and `json.dumps(..., default=float)` emits
the non-standard token `NaN`. The Python loader tolerates it, other JSON parsers (the frontend/live monitor) do not. Use `None` or the `_enc` string convention.

### nits

- N1. `detectors_registry_v3.py:37` `_enc, _dec = D2._enc, D2._dec`: `_dec` is unused in this module (dead); import `_enc` only.
- N2. `detectors_registry_v3.py:178` `rate = lambda ...` and `fit_registry_v3.py:61-62` `n = lambda`, `r = lambda` (assigned lambdas, PEP 8 E731; `n`/`r` are poor names): use small nested `def`s named `count`/`ratio`.
- N3. Both test files import sibling test modules (`from test_eval_registry_detectors import ...`), which only works with the repo's `pythonpath` setup and breaks under `--import-mode=importlib`. Move `synth_registries`, `acme_registry`, `split`, `synth_v2` into `tests/eval/conftest.py` fixtures or a `tests/eval/_synth.py` helper.
- N4. `detectors_registry_v3.py:214-216`: `D9c.fit(table=...)` raises a bare `ValueError`; the message is fine but the signature advertises a parameter that can never be used. Say so in the docstring, and make `fit_all` (line 83-84 of fit_registry_v3.py) the documented reason one table is shared for D9/D9b only.
- N5. Duplicate trace ids in `fit()` are silently accepted (`where` dict in `fold_of_traces` keeps the last; scratch probe with duplicated dev traces fit without error). Add `if len(set(ids)) != len(ids): raise ValueError(...)` in `_fit_table`; `fit_registry_v3.main` already checks across v1/v2 but not `fit_all`.
- N6. `fit_registry_v3.py:205` `import glob` inside the loop; hoist. `D9_FROZEN` (line 32) is cwd-relative so `FIT_REPORT_V3.md` text depends on the working directory (determinism test only runs from one cwd); resolve against `Path(__file__).parent.parent`.
- N7. Report wording `render_report` line 110 "Test traces were not read" is imprecise: `load_traces` reads them and `_file_sha` hashes the full files; say "loaded but dropped before any feature, label or registry is read" (as the module docstring does).
- N8. `fit_info` key naming is inconsistent: `threshold_in_sample_orig` vs `threshold_oof_orig` (suffix) while the dict keys are `"in_sample_orig"`; fine but document the four keys in the class docstring, and note that the D9c keys are absent when no copy exists (only D9b).
- N9. `calibrate_single_e` returns `inf` ("infeasible") when there are no finite non-violation scores even if the constraints would trivially hold (inherited from `D2.calibrate_single`); label it in the docstring so `note` text "no threshold satisfies the constraints" is not misleading in that case.
- N10. `fit_registry_v3.py:134` the report states "D9c uses different folds only through its grouping (folds are over original ids, identical to D9b's)"; this is true only because `_folds` is called with sorted original ids and the same seed. The test suite does not check it (compare `d9b.fit_info['cv_folds'] == d9c.fit_info['cv_folds']`, a one-line add that also guards B1).
- N11. `test_roundtrip_and_loader_shape` (lines 237-262) bundles about eight behaviours in one test; split into dump shape / round-trip scores / `only` / byte-stability so a failure names the cause.
- N12. `meta` in `fit_all` lacks the code identity (no git sha or file hashes of `detectors_registry_v3.py`/`detectors_v2.py`); the sha256 of inputs is recorded but not of the code that produced the model.

## Answers to the specific questions
- Off-by-one in folds: none found (`rank % k` assignment and `range(len(folds))`; empty validation fold is skipped, which leaves NaN out-of-fold p that never alert in calibration; harmless).
- Leakage between augmented copies and folds: none in the code; untested (B1).
- Wrong FA denominators: none; (c) and (e) denominators are counts on the same masks as D8/D9 and as the original-rows-only `_verify`. The pooled calibration weights traces without registry 4x (documented in the report caveat).
- Non-determinism: none observed (order of input traces, `PYTHONHASHSEED`, two process runs, byte-identical JSON).
- Ties: strict `>` consistently; with the S3 caveat about batch vs row arithmetic.
- NaN / empty / no proposals / no registry: handled (see probes), 1-trace crash (S6).
- Frozen schema: unversioned (B3).

VERDICT: CHANGES REQUESTED
