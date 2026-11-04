# PRD: v3 fresh holdout for the destination registry

## Problem
The registry detectors (D8 rule, D9 learned) were scored on v2 TEST, which had already been scored for earlier detectors, with registries written from the very notes that define the labels (perfect, label-circular). D9's alert threshold was calibrated without the benign-trap false-alarm constraint. Result: "Shortfall", and a post-hoc sweep that hints at a calibration fix but cannot be trusted (test already seen).
We cannot yet say whether a registry-aware monitor works with REALISTIC registries on data nobody has tuned against.

## Goal
Decide, with pre-registered criteria and one scoring run on fresh data, whether a registry-aware detector (with a realistic operator registry: incomplete, stale, noisy) clears the bar to be the RECOMMENDED configuration when a registry is configured.

## Non-goals
Real LLM traffic; a UI for editing registries; auto-discovering routes; changing defaults without the evidence.

## User stories
- As an operator I can write an inventory of my destinations in plain text, convert it to a registry, and know how well the monitor works given how incomplete my inventory is.
- As the maintainer I get a mechanical verdict (qualifies / does not) with every criterion shown, plus a breakdown by registry quality (listed / missing / stale routes) so I know where it fails.

## Design principles
1. Independence: truth routing (labels) and the operator's inventory (what the registry is built from) are DIFFERENT texts, so the registry is no longer label-circular.
2. Realistic imperfection by construction (not by random dropping): some true routes are absent from the inventory, some inventory entries are stale (say internal when it relays now; say relay when the bridge was removed), some are noise.
3. Freeze before looking: detectors, thresholds and criteria are committed before any v3 label, registry or score exists.
4. Fresh data only: ALL v3 traces are test data. No tuning on v3, ever.
5. Every implementation ticket goes through implement -> spec-compliance review -> code-quality review -> fix -> integration test.

## Tickets (vertical slices; see docs/v3/tickets/)
T01 D9b/D9c detectors frozen on v1+v2 dev | T02 v3 data generation x5 | T03 blind review x4 + adjudication | T04 operator registry authoring x2 (+ truth extractor) | T05 integrity and leakage checks | T06 v3 runner + verdict | T07 review packages | T08 integration + end-to-end (Playwright, full gate) | T09 final report and docs.
