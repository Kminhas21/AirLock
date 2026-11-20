# v3-union results (one-shot, POST-HOC design on seen data; eval/SPEC_V3_UNION.md)

**Verdict: shortfall: no union is robust**

## Degradations

| detector | S1 missing | S2 stale-internal | S3 sparse | S4 stale-relay FA | S5 FA |
|---|---|---|---|---|---|
| U8 (D8 + D3) | 0.455 vs 0.405 pass | 0.455 pass | [0.367, 0.031] vs [0.317, 0.050] pass | 0.459 (D3 0.081) inherent cost | [0.034, 0.034, 0.031] pass |
| U9b (D9b + D3) | 0.455 vs 0.405 pass | 0.455 pass | [0.527, 0.028] vs [0.317, 0.050] pass | 0.959 (D3 0.081) inherent cost | [0.032, 0.032, 0.028] pass |
| U9c (D9c + D3) | 0.455 vs 0.405 pass | 0.455 pass | [0.527, 0.026] vs [0.317, 0.050] pass | 1.000 (D3 0.081) inherent cost | [0.030, 0.030, 0.026] pass |

## Undegraded author1 registry

| detector | U1 on-time | U2 FA | U3 FA(c) | U4 FA(e) | U5 gain vs D7 | U6 gain vs D3 | robust |
|---|---|---|---|---|---|---|---|
| U8 | 0.367 fail | 0.034 pass | 0.124 fail | 0.088 pass | 0.000 fail | 0.000 fail | False |
| U9b | 0.767 pass | 0.032 pass | 0.118 fail | 0.074 pass | 0.400 pass | 0.400 pass | False |
| U9c | 0.767 pass | 0.030 pass | 0.111 fail | 0.059 pass | 0.400 pass | 0.400 pass | False |

Median per-step latency (ms): U8 10.36; U9b 12.76; U9c 13.19
