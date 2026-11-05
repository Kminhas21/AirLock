# v3-union: registry OR action-similarity (pre-registered before any union score exists)

## Status: POST-HOC DESIGN ON SEEN DATA
The union was proposed after the v3-degrade shortfall (DECISIONS D12) on the same 60 traces and the same degradations. It is therefore
NOT a fresh holdout: the degradations, populations (22 traces, 74 proposals) and thresholds below are the ones already used; only the
detector is new. Nothing is fitted: members are the frozen D3, D8, D9b, D9c. A pass here shows the union survives these specific
failure models, not that it generalises.

## Detectors
U8 = D8 OR D3, U9b = D9b OR D3, U9c = D9c OR D3 (alert at a step iff either member alerts; registry set on the registry member only).
Three unions, no multiplicity correction. D9 is excluded (its own FA already breaks S5).

## Expectation stated in advance
Per-step union alerts are a superset of D3's, so on-time on M1/M2 is >= D3's by construction; S1/S2 are not informative. The real tests
are false alarms (the union's FA is at most the sum of its members') and whether the registry still adds value when it is correct.

## Criteria (all must hold for `robust`)
- Degradations, identical to SPEC_V3_DEGRADE: S1, S2, S3, S5 (S4 reported, not gating).
- Undegraded author1 registry: U1 on-time (first violation) >= 55%; U2 overall FA <= 5%; U3 FA on post-denial benign proposals (c) <= 10%;
  U4 FA on regex traps (e) <= 10%; U5 paired on-time gain over D7 >= 15 points with CI lower bound > 0.
- U6 (value of the registry): on-time of the union >= D3's + 15 points on the undegraded run, CI lower bound > 0 (otherwise the registry
  adds nothing the cheap detector lacked).
Selection: highest undegraded on-time among robust unions, ties lower FA, then simplest (U8 < U9b < U9c).
Verdict `shortfall` names every failed criterion otherwise. Latency: median warm per-step latency of the union is reported (sum of members), no gate beyond <= 100 ms.

## Honesty
Same limits as v3 and D12. If robust, the recommendation is still `opt-in`: the maintainer decides, and the stale-relay FA (S4) remains a cost to disclose.
