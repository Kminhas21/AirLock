# v3-degrade results (one-shot, eval/SPEC_V3_DEGRADE.md)

M1/M2 affected traces: 22; B1 population: 74 proposals.

**Verdict: shortfall: no registry detector is robust**

| detector | S1 missing | S2 stale-internal | S3 sparse (on-time, FA) | S4 stale-relay FA | S5 FA | robust |
|---|---|---|---|---|---|---|
| D8 | 0.045 vs 0.405 (n=22) fail | 0.000 vs 0.405 fail | [0.153, 0.016] vs [0.317, 0.050] fail | 0.446 (D3 0.081, n=74) inherent cost | [0.021, 0.021, 0.016] pass | False |
| D9 | 0.182 vs 0.405 (n=22) fail | 0.136 vs 0.405 fail | [0.407, 0.049] vs [0.317, 0.050] pass | 0.986 (D3 0.081, n=74) inherent cost | [0.055, 0.055, 0.049] fail | False |
| D9b | 0.000 vs 0.405 (n=22) fail | 0.045 vs 0.405 fail | [0.293, 0.010] vs [0.317, 0.050] fail | 0.946 (D3 0.081, n=74) inherent cost | [0.016, 0.016, 0.010] pass | False |
| D9c | 0.000 vs 0.405 (n=22) fail | 0.136 vs 0.405 fail | [0.293, 0.010] vs [0.317, 0.050] fail | 0.986 (D3 0.081, n=74) inherent cost | [0.018, 0.018, 0.010] pass | False |

## Reference detectors on the same inputs

| detector | M1/M2 on-time | M3 on-time | M3 FA | B1 FA |
|---|---|---|---|---|
| D1 | 0.273 | 0.300 | 0.046 | 0.149 |
| D3 | 0.455 | 0.367 | 0.020 | 0.081 |
| D7 | 0.455 | 0.367 | 0.052 | 0.108 |

## Paired on-time difference vs D3 on the affected traces (bootstrap 95% CI)

- D8: M1 -0.409 [-0.636, -0.227]; M2 -0.455 [-0.682, -0.273]
- D9: M1 -0.273 [-0.455, -0.091]; M2 -0.318 [-0.501, -0.136]
- D9b: M1 -0.455 [-0.682, -0.273]; M2 -0.409 [-0.591, -0.227]
- D9c: M1 -0.455 [-0.682, -0.273]; M2 -0.318 [-0.501, -0.136]

Undegraded (author1) reference: D3 on-time 0.367, FA 0.020; D8 on-time 0.333, FA 0.021; D9 on-time 0.767, FA 0.055; D9b on-time 0.733, FA 0.016; D9c on-time 0.733, FA 0.018
