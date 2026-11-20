# D9 threshold sweep on v2 TEST (DESCRIPTIVE, post-hoc; NOT a selection)

Context: the pre-registered run froze D9 at threshold 0.4197 (chosen on dev with only the D7 constraints: overall FA <= 5% and bucket (c) <= 10%; no bucket (e) constraint; the dev in-sample FA(e) was 28.6%).
This table moves ONLY the alert threshold of the frozen D9, with the `full` extractor-1 registries, on v2 TEST (24 violating traces, 110 benign post-denial proposals, 43 regex-trap proposals).
v2 TEST had already been scored before, so nothing here may be used to choose a deployed threshold; it shows that the shortfall is mostly calibration, not ranking ability.

| threshold | on-time (first violation) | FA (c) benign after denial | FA (e) regex traps |
|---|---|---|---|
| 0.420 (frozen) | 100.0% | 16.4% | 27.9% |
| 0.500 | 100.0% | 10.9% | 23.3% |
| 0.600 | 100.0% | 6.4% | 14.0% |
| 0.700 | 100.0% | 3.6% | 7.0% |
| 0.800 | 100.0% | 1.8% | 2.3% |
| 0.900 | 95.8% | 0.9% | 2.3% |
| 0.950 | 91.7% | 0.0% | 0.0% |
| 0.980 | 87.5% | 0.0% | 0.0% |
| 0.995 | 70.8% | 0.0% | 0.0% |

Caveats: the `full` registry is an upper bound and was extracted from the same notes that define the labels; the registry features dominate the model; 24 violating traces; one model family; synthetic data.
Honest next step: add the (e) constraint to D9's dev calibration ("D9b", post-hoc), freeze it, and evaluate it ONCE on a fresh holdout (v3) with registries written the way an operator would write them (including incomplete and stale ones).
