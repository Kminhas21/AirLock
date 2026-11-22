# T05 spec-compliance review (eval/check_v3_integrity.py)

Reviewer scope: read-only except this file. Inputs read: T05 and T04 tickets, GENERATOR_GUIDE, SPEC_V3 (Amendments 1-3), docs/v3/INTEGRITY_CHECKS.md, the checker, its tests, eval/final_v3/traces.json, eval/registries_v3/*.json, server/registry.py (resolve_token).
Scratch fixtures and outputs: /tmp/claude-0/-home-user/e75e68e8-47af-5ec4-a8ee-01cf711b4198/scratchpad/ (real.md, fx/*).
Test run: `pytest tests/eval/test_check_v3_integrity.py` -> all pass (53 tests).
Real-data run: exit 0, 0 hard failures, 1 warning (duplicate agent_text 2.2%).

## 1. Ticket checks

| Check | Verdict | Evidence |
|---|---|---|
| Schema validity | MET | `validate()` on every trace, each failure is a hard entry with id; real data 60/60. Caveat: a structurally broken trace (`steps` a string) makes later passes crash with a traceback (exit 1 by accident, no report written) -> F6. |
| Unique ids / format | MET | Duplicate-id fixture: hard, exit 1. Format `v3[a-e]-NNN` regex; real data 0 off-format. |
| Category counts (amended spec) | MET | Default table = relay_known 20, benign_ext_v3 20, mixed_v3_adv 10, mixed_v3_benign 10, dropped families 0 (Amendments 1-2). Real data matches. Removing relay_known -> hard "missing entirely" exit 1. Dropped-family traces -> warning only. `--expected` override replaces the table. Note: the stale `eval/final_v3/INTEGRITY.md` in the repo is from an older run against the UNamended table (5 hard failures incl. 30% coverage); it must be regenerated (F7). |
| No external host in violating proposals | MET (with gaps) | Scans every string value recursively: email, URL host, scp-style, bare host with a TLD list; `team.com` / `*.team.com` allowed. Fixtures all hard, exit 1: nested list-of-dict `ops@evil-partner.com`; `.dev` host; upper-case `HTTP://EVIL.COM`; `a@team.com.evil.com`; `x@evilteam.com`. NOT caught: IP literals (`203.0.113.9`) and a host used as a dict KEY (only values are scanned); exotic TLDs. The IP gap is documented, the dict-key gap is not (F3). Only `label == violation` is scanned; `denied_seed` is intentionally exempt per the guide. |
| No label words in inventories | MET (narrow) | Case-insensitive substring; `Note: DETECTOR Pager` -> hard, exit 1. Misses paraphrase and whitespace variants (`ground  truth` with two spaces, `denied-party`): fixture exit 0 (F4, documented as substring/five words only). The word `violation` is also a legitimate word, but real data has 0 hits. |
| Duplicate text | MET | Normalised cross-trace share, warn above 2%; real 14/630 = 2.2% (matches my recompute). The ticket says "report"; warning is acceptable. |
| Partner reuse | MET | Uses oracle party slugs and relay/external match values; real data 0 reuse. Only oracle registries are examined (authors' party spellings are not), acceptable. |
| Coverage consistency listed/missing/stale | PARTIALLY | Definitions are faithful to the guide and to the ticket text (see section 3), but the test is per-trace "some oracle token supports it", so it cannot detect a status on the wrong note (F1). |
| Author agreement | MET | Token-level, resolved kind+party, plus a registered-only restricted share, warning below 50%. Real 465/468 (99.4%) and 233/236 (98.7%). See F5 on how flattering this is. |
| Registry lint | MET | `Registry.validate()` for all three files; fixture with `kind: bogus` -> hard with id, exit 1; missing entry for a v3 trace -> hard; non-object registry -> hard; malformed `entries:"x"` -> hard (3 failures), no crash. |
| Statistics | MET | Lines per trace (mean 3.60, min 2, max 6, 0 empty), coverage mix, 30/30 adversarial/benign, 503 proposals, 67 violations. |
| Exit codes | MET | 0 clean, 1 on any hard failure, 2 on unreadable input / non-object registry file / bad `--expected` (verified: missing file gave exit 2). |
| "Tests with fixtures" | MET | 53 tests; cover each hard path above. They do not cover the per-note masking weakness (F1), nested-key hosts or the crash in F6. |

## 2. Independent recomputation (real data)

| Number in report | My method | Result |
|---|---|---|
| 67 violating proposals, 0 external hosts | Own regex over `json.dumps(args)` of every violation: emails, `://` URLs, bare TLD domains, IPs. Only `team.com`, `hooks.team.com`, `tools.team.com` found (15/7/2). Label counts: ok 376, violation 67, denied_seed 60. | MATCH |
| Duplicate agent_text 2.2% | Normalised (lower, whitespace-collapsed) text owned by more than one trace id: 14/630 | MATCH (2.2%) |
| Author agreement 99.4% / 98.7% | Entry-set comparison (match, kind, party) between author1 and author2: 158/219 (72.1%) identical, 161/219 (73.5%) ignoring party spelling; 58 entries differ (mostly one author listing an explicit `internal` entry the other left to defaults, which resolve identically, plus party slug spelling `harbor-pine` vs `harborpine`, and key choice `path_prefix` vs `any_glob` in v3a-014). Resolution-level agreement is consistent with the report: 3 token disagreements. | MATCH at resolution level; entry-level agreement is much lower (note N2). |
| Coverage 2/95 (author1) and 1/95 (author2) | Re-derived per NOTE, pairing oracle entry i with coverage entry i (valid in 50 of 60 traces: oracle entry count equals note count; 9 traces have an empty oracle, 1 more both empty). | author1 2/86 (same two: v3a-014 listed, v3e-018 missing); author2 2/86 (v3e-018 missing, and v3e-010 note 2 declared stale while author2 simply left the line unregistered). The checker reports 1 for author2 because of masking. Conclusion unchanged (about 2%, far below 15%), but the checker undercounts by 1. |

Manual reading of the 22 traces with a declared `stale` status confirms they are genuinely stale inventory lines (inventory says relay/external, truth says internal, or the reverse). v3e-018 note 1 is a real generator mislabel (`missing` declared but the inventory lists `/project/design/shared-out/ - local scratch`), correctly flagged.

## 3. Coverage definition vs the guide

- Guide: listed = inventory states the truth correctly (relay stated as relay, or internal stated as internal); missing = destination not mentioned; stale = mentioned but wrong.
- Implementation, relay/external truth: listed = author resolves relay/external; missing = no registered entry (default/unknown); stale = explicit entry that is internal or has a different party string. Faithful. `resolve_token` returns only `internal` (defaults) or `unknown` for unregistered tokens, so a silent author cannot satisfy `listed` for relay truth.
- Internal truth: listed = author does not resolve it relay/external (explicit internal or default); missing = no entry; stale = explicit relay/external. Faithful to the guide's "says it is internal when it truly is", with the inherent ambiguity that a silent author makes both `listed` and `missing` true (documented).
- Ticket wording ("listed => oracle's relay destination also resolves relay/external; missing => resolves as default") is implemented.

Ways a WRONG declared status still passes (false negatives):
1. Per-trace existence test: statuses are not tied to notes. Fixture A: rotate every trace's statuses one position -> still 2/95, exit 0. Fixture B: set EVERY status to `listed` (about 60% wrong) -> 7/95 = 7.4%, exit 0. Fixture C: all `stale` -> 7.4%, exit 0. Only all-`missing` fails (41%). So the 15% gate only catches gross errors in a direction the registries do not support.
2. Internal-truth `listed` is satisfied by any non-relay resolution; combined with 1, any trace with one internal token accepts `listed` everywhere.
3. Traces whose oracle is empty (9 traces, 9 declared statuses per author): counted consistent unconditionally ("no claim"). A wrong `stale`/`missing` there is never checked, and these 9 stay in the denominator, diluting the rate.
4. A relay-truth `stale` is supported by any party-string difference (`helix` vs `helix-biologics`), not only by a real contradiction, so a spurious "stale" can pass when the author is correct and the slugs merely differ.
5. Author registers an explicit `internal` where the oracle says relay and the generator declared `listed`: caught only if no other token masks it.
6. Representation mismatch (author keys a route differently from the oracle, e.g. v3a-014) produces a false positive, not a false negative (documented).
7. The oracle is an LLM extraction, not the truth notes; an oracle error shifts both directions. It is the ticket's chosen reference.

## 4. Threshold and hard-fail semantics

- 15% inconsistent per author, strict `>`: exactly 15.0% passes. Computed over declared entries across all traces (not per status/stratum), so a bad `missing` stratum (the one that matters for C8) can hide: 1/18 missing in the real data is fine, but 3/18 would still be under 15% overall.
- The 15% figure appears in the code and INTEGRITY_CHECKS.md ("pre-registered, unchanged") but NOT in the T05 ticket, SPEC_V3 or PRD (grep); I cannot verify the pre-registration claim from the repository (F2).
- Hard vs warning follows the ticket: unreadable input exit 2, any hard failure exit 1, warnings never change the exit code. Dropped families present: warning; expected-but-absent: hard. Duplicate text and partner reuse are warnings, which matches "reports problems".

## 5. Findings

| ID | Severity | Finding | Suggested fix |
|---|---|---|---|
| F1 | should-fix | Coverage check is per-trace existence: rotating or blanket-setting statuses passes (rotation 2/95; all `listed` or all `stale` 7.4%). In 50/60 real traces the oracle entry order equals the note order, so a per-note comparison (entry i vs `note_index` i) is feasible and gives the exact numbers (author1 2/86, author2 2/86). | Use index pairing when `len(oracle entries) == len(notes)`; fall back to existence otherwise and report which mode applied. At minimum add a test showing the blind spot. Does not change the real-data verdict. |
| F2 | should-fix | 15% threshold is not in the ticket, spec or PRD, yet documented as "pre-registered". Also computed pooled, not per status. | Cite where it was fixed, or relabel it as the implementer's choice; also report/limit the `missing` stratum separately. |
| F3 | should-fix | External-host scan reads only string VALUES: a host used as a dict key, and IP literals, are not seen (fixtures exit 0). Only IPs are documented. | Scan keys too and flag non-RFC1918 IPs, or document. |
| F4 | note | Label-word match is a five-word substring list; `ground  truth` (double space) and `denied-party` pass. | Normalise whitespace/hyphens before matching. |
| F5 | note | Agreement headline (99.4%) counts default-resolved tokens and treats explicit-internal and silent as equal; entry-level agreement is 72%. Report the entry-level number too. | Add one line to the report. |
| F6 | should-fix | A trace with non-list `steps` passes the schema pass as a hard failure but later sections raise `AttributeError`: traceback, no report written, exit 1 only by accident (not the documented exit 2 / report). | Skip schema-invalid traces after recording them, or wrap the analysis. |
| F7 | should-fix | `eval/final_v3/INTEGRITY.md` is stale (older run: 5 hard failures, 30% coverage). A reader will see a failing report that contradicts the current checker. | Regenerate with the final command after approval (I did not touch it). |
| N1 | note | `denied_seed` proposals are not host-scanned (consistent with the guide). | none |
| N2 | note | Duplicate-text 2.2% is just above the 2% warn line; 14 steps shared between traces, not a hard fail. | Inspect which texts repeat (probably generic "that was blocked" lines). |

No BLOCKING items: every required check exists, fails hard with exit 1 on the adversarial fixtures I built (nested external host, upper-case label word, invalid registry, missing/non-object registry, duplicate id, missing category, grossly wrong coverage), the three recomputed real-data numbers match, and the real data passes with a per-note recomputation giving the same ~2% inconsistency.

## Verdict

APPROVE (with the should-fix items F1, F2, F3, F6 and F7 to be handled before the final report relies on the integrity statement).
