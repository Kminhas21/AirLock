# T05 re-check (v3 integrity checker)

Scope: eval/check_v3_integrity.py, tests/eval/test_check_v3_integrity.py, docs/v3/INTEGRITY_CHECKS.md, eval/final_v3/INTEGRITY_ALLOW.json, regenerated eval/final_v3/INTEGRITY.md. Read-only except this file. Scratch fixtures and mutants: the session scratchpad (`m/`, `mw/`, `mut.py`).

Verdict: **APPROVE** (no blocking item; 3 should-fix, 3 nits).

## Test runs

`pytest tests/eval/test_check_v3_integrity.py` run twice: all pass both times (same count, no flakiness).

## 1. Quality BLOCKING items B1 and B2: fixed

All of these give exit 2, a one-line stderr message, no traceback, no report written:

| input | message |
|---|---|
| `steps: null` | `trace v3a-001: steps must be a list, got NoneType` |
| `steps: [null x6]` | `step 0 is not an object (NoneType)` |
| `steps: "abc"` | `steps must be a list, got str` |
| non-dict proposal | `step 0: proposal must be an object or null` |
| top-level JSON string | `traces must be a JSON list of trace objects` |
| trace list of ints | `trace #0 is not an object (int)` |
| `[]` | `no traces in input` |
| empty / list-valued registry file | `registry file is empty` / `must be a JSON object` |
| `ops_inventory: "abc"`, `id: 5` | clear input errors |
| unwritable `--out` (`/proc/x`, `/dev/null/x`) | `cannot write ...` |
| non-UTF8 traces file / non-UTF8 registry file | `cannot read ...: 'utf-8' codec can't decode ...` |
| missing traces file, bad `--expected` | exit 2 with message |

(Running as root, a chmod 555 directory is writable, so that case was not testable; the /proc and /dev/null cases cover the OSError path.)

Genuine content failures still exit 1: dropping `id`, `task`, `denied_effect_summary`, `environment_notes`, `ops_inventory`, `inventory_coverage`, `steps`, `step.i`, `step.agent_text` each gives exit 1 with a `schema ...` hard failure. The real data without `--allow` gives exit 1 (see 3). A 152-case type fuzz (8 wrong types over every trace, step, proposal, coverage and note field of one trace) produced 0 tracebacks; 114 exit 1, 38 exit 2.

### New findings from the fuzz (should-fix, not blocking)

- **S-A. A wrong-typed or missing `category` is reported as exit 2 `internal error (TypeError)` instead of a schema finding (exit 1).** Cause: `sorted(cat.items())` at check_v3_integrity.py:691 sorts a dict whose key may be `None`/int/etc. Same exit 2 for `inventory_coverage` = 5/True/1.5, `proposal.tool` or `proposal.label` = list/dict, and `coverage.status` = list/dict (unhashable). It fails closed (non-zero, no traceback, no report) so it cannot hide a defect, but docs/v3/INTEGRITY_CHECKS.md says "A trace that merely lacks a required key is a schema finding (exit 1)", which is false for `category`. Fix: `sorted(..., key=lambda kv: str(kv[0]))`, guard the unhashable cases, or correct the sentence in the doc.
- **S-B.** No test pins the nested `--out` directory creation: replacing `p.parent.mkdir(...)` with `pass` survives (mutant 17 below).

## 2. Per-note coverage is faithful

Real data, both authors: **per-note on 50 traces, per-trace on 0 traces, no claim on 9 traces** (60 traces; 1 more trace has no coverage list). The fallback is never used on the real data.

Fixtures on the real traces (all with `--allow`, oracle and both authors):

| manipulation | author1 | author2 | exit |
|---|---|---|---|
| none | 2/95 (2.1%) | 2/95 (2.1%) | 0 |
| rotate each trace's statuses by one | 50/95 (52.6%) | 49/95 (51.6%) | 1 |
| every status `listed` | 35/95 (36.8%) | 34/95 (35.8%) | 1 |
| every status `stale` | 38/95 (40.0%) | 39/95 (41.1%) | 1 |
| every status `missing` | 68/95 (71.6%) | 67/95 (70.5%) | 1 |
| rotate `note_index` only | 45/95 (47.4%) | 44/95 (46.3%) | 1 |

The previous blind spot (rotation 2/95, all-listed 7.4%) is closed. The test file has per-note tests for rotation, all-listed, all-stale, `note_index` use, and for each fallback trigger (entry count differs, entry not in its note, glob entry).

## 3. Allow-list

Without `--allow`, real data: exit 1, exactly 2 hard failures (v3a-019 steps 10 and 12, `incidents.shared`), 1 warning. With the committed file: exit 0, 0 hard, 2 allow-listed, the regenerated INTEGRITY.md is byte-identical to a fresh run. I checked the `incidents.shared` text: `queue-pub incidents.shared '...'`, a topic name; and the other dotted tokens in violating proposals (`vendor_sync.helio_feed`, `reporting.churn_q3`, `orders.vendor.out`, `reporting.cobalt_extract`) either contain `_` or are excluded as designed; I found no other host-like token in the 67 violations by an independent regex.

Handling, tested on the real data:

| entry | result |
|---|---|
| only step 10 | step 12 still hard, exit 1 |
| wrong steps (11, 13) | 2 hard, 2 stale-entry warnings, 0 suppressed |
| token case/space/partial (`Incidents.Shared`, `incidents.shared `, `incidents`, `shared`) | nothing suppressed, stale warnings |
| other trace id | nothing suppressed |
| duplicate entries | suppressed once, the duplicate gets a `stale allow entry` warning (noisy but safe) |
| extra entry for a non-existent hit | warning only, real hits still suppressed |
| step as `10.0`, `true`, `"10"`; blank reason; unknown key; dict instead of list | exit 2 |
| empty list | valid, behaves as no allow |

Mutants "match on token only" and "suppress the whole proposal" are killed by the tests. The allow list affects only the host check; no threshold or regex can be changed through it.

## 4. Mutation testing (20 mutants, my own, scratch copy of eval/ server/ tests/)

First pass had stale `.pyc` risk, so I reran with `PYTHONDONTWRITEBYTECODE` and `__pycache__` removed before each mutant. Result: **19 killed, 1 survived.**

Killed: threshold 15% -> 20%; `>` -> `>=`; drop IPv6 scan; drop dict-key scan; id `fullmatch` -> `match`; allow matching on token only; allow suppressing whole proposal; per-note disabled (always fall back); `_in_note` check dropped; InputError exit 2 -> 1; empty-input check removed; NFC removed; depth limit removed; label-word scan removed; whitespace/hyphen collapse removed; entry-level agreement line removed; stale-allow warning removed; `endswith(domain)` suffix bug; ValueError no longer caught on read.

Survived: **`p.parent.mkdir(parents=True, exist_ok=True)` replaced by `pass`** (S-B: no test writes `--out` into a missing directory). Behaviour is documented and works; low risk.

## 5. Hand recomputation from registries and traces (independent code, `python -I`)

| report number | my result | report |
|---|---|---|
| violating proposals | 67 of 503 proposals | 67 / 503 |
| per-note coverage inconsistency | oracle entry i vs note i, 50 traces, 86 declared: author1 2 (v3a-014 note 0 `listed`, repo vs path_prefix key mismatch; v3e-018 note 1 `missing`), author2 2 (v3e-010 note 2 `stale`, no entry for `#internal-launchcomms`; v3e-018 note 1); plus 9 no-claim = 95 declared | 2/95 and 2/95, same four items, per-note on 50, no claim on 9 |
| entry-level agreement | union 216 entries, 158 identical, 55 in only one author | 158/216 (73.1%), 55 one-author |

(Oracle has no entries for 10 traces, 9 of which declare coverage. Oracle entry count equals note count in exactly 50 traces.) A first naive recomputation gave 9/10 mismatches because I ignored URL scheme and `any_glob`; once matching was made equivalent it gave the checker's numbers, so the discrepancy was mine. The earlier spec review's 158/219 used a different union; 158/216 is what the report states.

## 6. Documentation

- "pre-registered" no longer appears in the checker, tests assert its absence, INTEGRITY_CHECKS.md, or INTEGRITY.md. The 15% line is described as "an operational threshold chosen by the maintainer", not in SPEC_V3, the T05 ticket or the PRD, applied pooled and not per status or stratum.
- Limits section is honest: per-trace blind spot and mixture, internal `listed` vs `missing` ambiguity, representation mismatch, LLM oracle, host-scan misses (decimal/hex IPs, single-label hosts, `.sh/.md/.py/.zip/.pl/.rs/.go` hosts, obfuscated hosts), the `incidents.shared` false positive and `done.Thanks` style false positives, flattering token agreement, `default`/`unknown` coupling.
- One inaccurate sentence: "A trace that merely lacks a required key is a schema finding (exit 1)" is false for a missing or wrong-typed `category` (S-A).

## Items

Blocking: none.

Should-fix: S-A (category and similar wrong-typed fields exit 2 as `internal error`, contradicting the doc; fix code or doc); S-B (add a test for `--out` into a missing directory); duplicate allow entries produce a stale warning for the second copy (acceptable, maybe say so in the doc).

Nits: per-trace fallback path is untested on real data (0 traces), exercised only by synthetic tests; allow `step` of `10.0` is rejected (fine, strict); the hard-failure lines in the CLI are capped at 5 on stderr (full list in the report).

APPROVE
