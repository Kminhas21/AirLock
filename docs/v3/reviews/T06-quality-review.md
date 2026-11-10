# T06 quality review: eval/run_eval_v3.py + tests/eval/test_eval_run_v3.py

Reviewer: code-quality pass. Real v3 data and scores were not touched (no run on eval/final_v3 or eval/registries_v3).
Every experiment used synthetic stub-embedder fixtures and a scratch copy under
`/tmp/claude-0/-home-user/e75e68e8-47af-5ec4-a8ee-01cf711b4198/scratchpad/` (`mut_t06/`, `edge/`).
No repo file other than this one was modified.

Test file: 56 passed, run twice (about 2.7 s each), no flakiness seen.

## Verdict: CHANGES REQUESTED

Blocking items:

- B1. A report-render crash after `results_v3.json` is written locks the one-shot run.
- B2. The per-condition registry application and the `verdict_inputs` numbers are not covered by any test. 9 of 28 mutants survived (list below), including the removal of `set_registry`.

The scoring logic itself looks correct. Strata, C6 population, FA buckets, bootstrap, ordering and state leakage were all checked and found sound. The blockers are about the single-shot operational risk and about tests that cannot fail.

---

## BLOCKING

### B1. One-shot lock-out if report rendering fails (eval/run_eval_v3.py:886-889)

`rj.write_text(...)` runs before `render_report(res)`. If rendering raises, `results_v3.json` is already on disk, there is no REPORT_V3.md, and a plain rerun is refused with exit 4 (line 845). The only way out is `--post-hoc`, which labels a faithful first scoring as a post-hoc rerun.

Reproduced: I forced `render_report` to raise `KeyError` after the JSON was written. Result: `results_v3.json` only, then rerun rc=4.

`render_report` is exercised only on synthetic data. Real data can hit untested branches, for example `rec['criteria'][k]['n']`, or `None` values after `_clean`.

Suggested change:
```python
text = render_report(res)                      # may raise: do it before touching disk
out.mkdir(parents=True, exist_ok=True)
rm.write_text(text)
rj.write_text(json.dumps(res, indent=1, allow_nan=False))   # JSON last, because it is the one-shot marker
```
Also serialise to a string first (`s = json.dumps(...)`) so a `ValueError` from `allow_nan=False` cannot leave a partial file. Better still, write both to `*.tmp` and rename.

### B2. Tests cannot fail for the most important run-level behaviours (tests/eval/test_eval_run_v3.py:528-592)

I mutated a scratch copy of eval/, server/ and tests/ and ran the test file against each mutant.

Mutants KILLED (19): C3 comparison flip, C6 floor 15 to 10, reversed TIE_ORDER, dropped FA tie-break, skipped provenance hash comparison, precedence stale over listed, C6 population ignoring "after a denial", dropping the C7 CI lower bound, `none` condition keeping its entries, secondary run getting selection, denied_before off by one, v3 scan limited to the first frozen file, first violation changed to last, exit-4 guard removed, `_registered` always true, listed without a party, and C6 relay changed to any registered. All were caught by a unit-level test.

Mutants that SURVIVED:

| # | Mutation | Why it survives |
|---|---|---|
| M06 | remove `det.set_registry(...)` in `run_eval_registry._score` | no test compares a candidate's result across conditions |
| M11 | score every condition with the authored1 registries (line 547) | same |
| M12 | `fa_in` denominator `len(pop)+1` | C6 is always `insufficient data` in the fixture (6 < 15), so the FA value is never asserted |
| M13 | C8 baseline taken from the candidate instead of D3 (line 366) | `verdict_inputs` is never asserted numerically |
| M14 | C2 reads the `missing` stratum instead of `listed` (line 364) | same |
| M15 | `gain_vs_D7` fed from `over_D3` (line 569) | same |
| M16 | C9 reads D1's latency | `warm_latency` is monkeypatched to a constant for every detector |
| M22 | trap bucket (e) computed over all traces | fixture FA is 0 everywhere |
| M23 | `fa_c` taken from the overall rate | same |

M06 and M11 are the serious ones. Registry application per condition is the core of the experiment. They survive even though the fixture does discriminate: D8's on-time is authored1 0.5, authored2 0.0, oracle 1.0, none 0.0 (verified on the test scenario with a real D9b/D9c fit). The tests simply never assert it.

Suggested additions, all cheap on the existing `smoke` / `_run_direct` fixtures:

1. In `test_smoke_none_condition_equals_defaults`, assert `res["conditions"][c]["D8"]["timing"]["on_time"]["rate"]` per condition: authored1 0.5, authored2 0.0, oracle 1.0, none 0.0 (pin them), or at least `none < authored1 < oracle`. That kills M06 and M11.
2. Assert `verdict_inputs["authored1"]["D8"]` fields: `listed == {"n": 6, "on_time": 1.0}`, `missing == {"n": 6, "on_time": 0.0, "d3_on_time": 1.0}`, `stale_fa.n == 6`, and `gain_vs_D7["diff"] == -0.5`. That kills M13, M14 and M15.
3. Add a unit test of `build_metrics` / `fa_in` with a hand-built `TraceResult` list. Assert `fa_in` returns k/len(pop) exactly, and returns NaN for an empty population. That kills M12.
4. Add a fixture variant with at least 15 relay-reaching benign post-denial proposals (n >= 15 for C6), with a known number of alerts, so a real C6 pass/fail value is asserted. Add a benign trap trace that alerts, so C5 and (e) are non-zero (kills M22 and M23).
5. For C9, let the `warm_latency` stub return a per-detector median (for example `{D8: 7.0, D9: 9.0, ...}`) and assert that `vin[c][d]["warm_median_ms"]` equals the one for that detector.

Also fine, but noted: M24 (`_isnum` without the NaN clause) survives only because NaN comparisons are already False, so the clause at line 85 is redundant (see N5). M25 (always clearing the cache) is an equivalent mutant because results do not depend on caching.

---

## should-fix

### S1. Uncaught OSError/ValueError in `main` gives a traceback with exit 1, outside the documented 0/2/3/4 (eval/run_eval_v3.py:852-863, 868-873, 883)

Reproduced: `--author1 /nonexistent/a1.json` gives `FileNotFoundError` from `file_sha256` inside `provenance_guard` (line 437-438), because the v3 files are hashed before the existence check. Unreadable or invalid input should be exit 2.

Likewise, a malformed registry (`REG.Registry.load` ValueError in `build_conditions`), a missing frozen file in `load_refs`, or a `FrozenRegistryError` from the loader gives exit 1 after the provenance banner.

Suggested change: wrap both try blocks and the `run(...)` call in `except (OSError, ValueError) as exc: print(f"error: {exc}", file=sys.stderr); return 2`. Document the exit codes in the module docstring: 0 ok, 2 bad input or usage, 3 provenance refusal, 4 already scored (use `--post-hoc`). Exit 1 would remain "bug".

### S2. `--post-hoc` silently overwrites an earlier post-hoc result (eval/run_eval_v3.py:845, 887)

The check at line 845 only guards `results_v3.json`. The help text says "never overwrites", but a second `--post-hoc` run replaces `results_v3_posthoc.json` and `REPORT_V3_POSTHOC.md` (reproduced, rc 0 twice). Suggested change: refuse (exit 4) if the target files for the chosen mode already exist, or require a numbered suffix.

### S3. `_score` skips `set_registry` silently via `hasattr` (eval/run_eval_registry.py:277, used at eval/run_eval_v3.py:547)

If a future D9b/D9c class loses `set_registry`, it would be scored under the default registry in all four conditions with no error. Nothing in the tests would notice (this is M06). Suggested change in `load_candidates`: after loading, `assert all(hasattr(d, "set_registry") for d in cands.values())`, raising `ValueError`. Cheap and independent of the other module.

### S4. The real D9b/D9c loader is never exercised through `run`/`main` (tests: 496-510, 670-681)

Tests monkeypatch `R3._load_v3` with a D9-shaped stand-in. `test_real_v3_loader_api_shape_if_available` only checks the loading call. I checked outside the test suite that `run()` works end-to-end with the real `load_frozen_registry_v3` and a real `fit_all` on the synthetic fixture (stub embedder). It does, so this is a missing test, not a bug. Suggested change: add one end-to-end `R3.run(...)` test that uses the real loader and does not use the autouse fake.

### S5. Strata hides what it cannot see (eval/run_eval_v3.py:220-236)

The logic is correct for the edge cases I tried:

- no destination tokens gives `missing`;
- several tokens: precedence listed > stale > missing;
- a default-internal token is `missing`, an explicit `internal` entry is `stale`.

Two things are not visible to the reader:

- Violating first proposals with no destination tokens (for example a `read_file` violation) count in `missing`. This inflates C8's denominator and cannot be told apart from a truly unlisted route. Suggested change: add `no_tokens: bool` to `info` and count it in `strata[c]` and in the report's strata table.
- An entry whose id is literally `"default"` or `"unknown"` is treated as unregistered (line 217, also `server/registry.py:652`). Harmless as long as the lint forbids those ids. Assert it in a test or in `_reg`.

### S6. Traces without an authored registry are silently scored under defaults (eval/run_eval_v3.py:878-882)

Only stray registry ids are warned about. A v3 trace missing from author1 gets `default_registry()` (edge test `partial_a1`: strata become 3 listed / 9 missing, no warning). Suggested change: print a warning (or refuse, for author1) listing v3 ids with no registry in each of author1/author2/oracle. Also warn on stderr when `lint_errors > 0`; a silently dropped invalid entry (tested: `{"id":"x","kind":"relay"}` with no match, rc 0) is only visible in the JSON.

### S7. C2 has no minimum-size rule while C6 and C8 do (eval/run_eval_v3.py:126)

A listed stratum of 1 trace passes at 100%, and one of 0 fails (NaN). The spec gives no floor for C2, so this is faithful. Suggested change: say so in the report (n is stored; show it in the criteria table cell, for example "0.900 (n=20)").

---

## nit

- N1. Hard-coded numbers in prose duplicate constants: "15 proposals / 8 violating traces" (line 645), "needs 15" (line 725), "(20 traces)" (line 642). Use `MIN_C6_N` and `MIN_C8_N` in f-strings so the report cannot disagree with the criteria.
- N2. `_load_v3` indirection (lines 471-474) exists only so tests can patch it; `eval.detectors_registry_v3` now exists. Import it at the top. Keep the module-level function if you want the patch point, but drop the "may still be edited" rationale.
- N3. Dead or odd code:
  - `build_metrics(did, ...)`: `did` is unused (line 361).
  - `run()`: `v1`, `v2`, `reg1` are only counted for `meta`.
  - `_point` returns `n_c`, which is not used.
  - `CRIT_ids()` (line 808) is defined after use and is just `list(CRITERIA)`.
  - `lint` calls `r.validate()` twice per registry (line 600).
  - `set(allowed_sha.values())` is rebuilt inside a loop (line 448).
  - `file_sha256(p)` is computed 3 times for the primary frozen file (lines 454, 462, 465).
- N4. Cache sizing: `emb.cache_size = max(old, 200000)` (line 524) is far above the unique texts for about 80 traces (a few thousand), so it costs nothing today; use a smaller, justified number or `0 -> unlimited`. Memory and runtime are otherwise fine: the full test scenario runs in about 2.7 s, and the bootstrap work is O(n_boot x traces) for 28 condition x detector blocks.
- N5. `_isnum`'s `not math.isnan(x)` is redundant: every comparison in `_ge`/`_le` is already False for NaN. Keep it for the explicit `_fv`/status semantics, or add a comment.
- N6. `test_smoke_none_condition_equals_defaults` asserts only strata and reference invariance, not what its name says. Rename it or add the per-condition assertions from B2.
- N7. `none` uses author1's `defaults` rather than the built-in defaults (lines 507-510, honesty item 8). It is disclosed, so keep it, but name it `none_authored_defaults` in JSON keys or meta to avoid confusion with the "defaults only" wording in the spec.
- N8. Tests import fixtures from other test modules (`test_eval_registry_detectors`, `test_eval_v2_detectors`) and patch private names (`R3._load_v3`, `M.warm_latency`). If those modules are renamed or collected differently, this file breaks at import time. Move the shared builders to `conftest.py`.

---

## Things checked and found correct

- **FA bucket definitions.** `denied_before_map` (line 262) matches `eval.detectors.run_trace`: the flag is recorded before the step's decision is applied. `fa_c` and (e) use `M.false_alarm_summary` bucket (c), which is a denied-before step with a proposal that is not a violation. C6's population (label `ok`, after a denial, reaching a party via a registered relay) is a strict subset of bucket (c), because the schema's LABELS are only `ok`/`violation`/`denied_seed`.
- **Empty strata and denominators.** I ran no benign_ext_v3 traces, no violating traces, a single trace, zero traces, partial and empty registries, and tokenless violations. All completed without division by zero or a crash. NaN inputs fail their criterion, and the JSON serialises via `_clean`. Report rendering survived every case.
- **State leakage.** Scoring all four conditions in order and in reverse order with the same detector instances gave identical alerts and scores. Reused and freshly loaded detectors also gave identical results. `RegistryExtractor.set_registry` resets `_pending`, `reset()` keeps the registry, and `run_trace` calls `reset()` per trace. The shared embedder cache only affects speed. `cache_size` is restored in `finally`.
- **Bootstrap.** One seed for every block and a trace-sorted resample give paired, order-invariant intervals. `on_time_difference` handles empty or zero-violation draws (`hb > 0` mask). Determinism and shuffle tests exist and are meaningful.
- **Selection rule.** Highest on-time, then lower overall FA within EPS, then simplest. Mutating the comparison, the FA tie-break or `TIE_ORDER` is caught.
- **Provenance.** Changed inputs, missing and extra recorded keys, v3 path/hash/marker in the primary and other frozen files, and non-allowed file hashes are each covered by a failing test. Test traces do not enter the hash. The recipe is pinned to `fit_registry_v3`.

## Underscore-prefixed imports from other eval modules (hidden coupling)

| Imported name (line) | Source | Used for | What breaks if it changes |
|---|---|---|---|
| `_ci_pct`, `_pct`, `_rate`, `_table` (40) | `eval.run_eval` | report formatting | Signature or None/NaN handling: report text changes, or `render_report` raises after the JSON is written (see B1) |
| `_clean` (40) | `eval.run_eval` | NaN to None conversion before `json.dumps(..., allow_nan=False)` (line 888) | If it stops converting NaN, serialisation raises after the one-shot lock exists (B1) |
| `_num` as `_num0` (41) | `eval.run_eval` | number formatting in tables | Output format only |
| `_load_registries` (42) | `eval.run_eval_registry` | JSON read and shape check; raises `TraceLoadError` (exit 2) | A different return shape breaks `build_conditions`/`raw`; a different exception type escapes `main` as exit 1 |
| `_score` (42) | `eval.run_eval_registry` | the scoring loop (`set_registry` per trace, `registry_for` fallback, cache clearing) | Any change in its semantics changes every number; a dropped `set_registry` is silent (M06, S3). Positional signature `(det, traces, regs, emb, clear)` |
| `M._bucket` (349) | `eval.metrics` | by-category FA (c) in `_point` | A rename raises `AttributeError` in `_run` after all scoring has finished. Suggested change: use public `M.false_alarm_summary` per category, or make `_bucket` public |
| (implicit) `_file` key added by `load_traces` | `eval.run_eval` | stripped in `_content` before hashing (line 389-390) | Any new annotation key in the loader changes the dev hash and the guard refuses with "changed input" |

Related coupling not in this file: `eval/detectors_registry_v3.py:31` imports `run_eval_registry._pooled`.

## Report/JSON accuracy

- Report numbers are taken from the same `res` dict that is written to JSON, so they cannot drift. Constants quoted in prose are the exception (N1).
- The report's "C6 uses benign post-denial proposals reaching a party through a registered relay entry" matches the code. SPEC_V3 says "STALE relay entry"; the mechanical population is every registered relay (AMENDMENT 3). The criteria table labels it stratum `stale`, which could mislead a reader, because none of the v3 families that would make it genuinely stale exist (AMENDMENT 2). Suggest one sentence in the C6 criteria row of the report saying so.
- Exit codes today: 0 success; 2 bad usage or input (argparse, `--latency-n`, `TraceLoadError`, v3 ids overlapping v1/v2); 3 provenance refusal (including a missing frozen file); 4 `results_v3.json` already exists; anything else is an uncaught exception, exit 1 (S1).

APPROVE is withheld until B1 and B2 are fixed. S1-S3 are strongly recommended before the real run.
