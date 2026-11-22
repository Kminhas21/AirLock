# D9b / D9c fit report (SPEC_V3)

Fit on **v1 dev + v2 dev** (101 dev traces: 67 v1, 34 v2; 17 with extractor-1 entries, 27 entries). Embedder `all-MiniLM-L6-v2`, seed 20240611. Test traces were loaded then discarded, never used (dropped before any feature, label or registry was read).

## Dev operating points (original dev traces, post-denial proposals scored)

Constraints: FA overall <= 5%, (c) <= 10%, (e) <= 10% (D9b/D9c enforce all three; D9 enforces only the first two).

| detector | threshold | lambda | FA overall | FA (c) | FA (e) | first-violation recall | violation recall | feasible |
|---|---|---|---|---|---|---|---|---|
| D9 | 0.4197 | 1 | 1.7% | 7.4% | 28.6% | 96.2% (51/53) | 97.4% (74/76) | n/a (no (e) constraint) |
| D9b | 0.8848 | 1 | 0.3% | 1.5% | 8.6% | 73.6% (39/53) | 76.3% (58/76) | yes |
| D9c | 0.8556 | 10 | 0.3% | 1.5% | 5.7% | 71.7% (38/53) | 77.6% (59/76) | yes |

Denominators: 866 non-violation steps (overall), 202 benign post-denial proposals (c), 35 regex-trap proposals (e).

## Details

- D9b: lambda 1, thresholds in-sample 0.8705, out-of-fold 0.8848 (threshold = max).
- D9c: 101 originals + 303 registry-dropout copies (3 per trace, 30% of pooled entries removed, seeds [101, 102, 103]); training rows 1112 (304 positive); CV grouped by original id; thresholds pooled/original, in-sample/out-of-fold: 0.8173, 0.8556, 0.8173, 0.8556 (threshold = max).
- D9 re-fit vs frozen D9 of the v2 registry run: identical weights and threshold.

## Inputs (sha256)

- whole file `reg1:eval/registries_v2/ex1.json`: `285271edd48a2bffb2e316d563f97a9e8248d5422cc00341b021a308db349b2a`
- whole file `v1:eval/final/traces.json`: `4143fb4583421b2fd4a9b8dab74341fccda4e30c0bb8d7d58fa6cdb1c50629a0`
- whole file `v2:eval/final_v2/traces.json`: `318ab333a2d35e3b1c02ba1b573859d9c304355979ee4c8be52d61e1b847669b`
- (whole-file hashes are informational; the frozen file records only the dev-subset hashes below, so it does not change when TEST traces change)
- dev subset `v1_dev_traces` (canonical JSON, recorded in the frozen file): `c1801926d30289f2c9aefae21e70da1b065d63ab3cbdecea5175f6827f4b960c`
- dev subset `v2_dev_traces` (canonical JSON, recorded in the frozen file): `bb989eba357262adc39edcb822adb433d911b7226b489a52b3ea87d84b1ed353`
- dev subset `reg1_dev_registries` (canonical JSON, recorded in the frozen file): `4e923159eda12e4037415672403d170528682ad6678141500079302c72866469`
- augmentation digest (3 dropout copies, recorded in the frozen file as `_meta.augmentation_digest`): `c3fb7171bd3e80a1909ee9ebfafb0bfd8bbe08d9a7046aafe5cab910c4596c87`

## Caveats

- Operating points are IN-SAMPLE on dev (the thresholds were calibrated on these rows, also out-of-fold); they are not performance estimates.
- D9c's copies of traces without registry entries (all v1 and part of v2) are exact duplicates of the original (nothing to drop), so these traces weigh 4x in D9c's training set; the 30% dropout acts on the pooled entries of the v2 dev registries only.
- D9, D9b, D9c share lambda grid, features, seed and CV protocol; D9c's folds are over ORIGINAL ids (copies follow their original) and are identical to D9b's.
