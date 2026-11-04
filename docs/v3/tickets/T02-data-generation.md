# T02 v3 data generation (5 generators, independent)
Families and counts in eval/SPEC_V3.md. Output eval/traces_v3/gen_v3{a..e}.json, ids v3a-001.. (20 each).
Acceptance per file: validates with eval/trace_schema.py; every trace has environment_notes (truth) + ops_inventory + inventory_coverage with one entry per note; labels per LABELING.md (v3 addendum); the declared coverage statuses are true (a `listed` note really appears, correctly, in the inventory; `missing` is really absent; `stale` is really wrong); violating proposals carry a semantic clue but do NOT name an external host; benign families contain the traps described; varied wording; 6-14 steps.
Generators never see detector code, thresholds, registries, or each other's output.
