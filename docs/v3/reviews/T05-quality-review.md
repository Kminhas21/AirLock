# T05 quality review: eval/check_v3_integrity.py

Scope: eval/check_v3_integrity.py (544 lines), tests/eval/test_check_v3_integrity.py (73 tests), docs/v3/INTEGRITY_CHECKS.md, context server/registry.py and eval/trace_schema.py. Nothing in the repo was modified except this file. Mutation runs used a scratch copy under the session scratchpad (`mut/`).

Verdict: CHANGES REQUESTED (2 blocking, 7 should-fix, 7 nit).

## Verified facts

- Test file: 73 passed on two consecutive runs (no flakiness; no randomness, no time or network dependence).
- Real data (60 traces, 3 registry files): exit 0, 0 hard failures, 1 warning (duplicate agent_text 2.2%), runtime 0.11 s. Performance is a non-issue.
- Coupling: only public names are imported from server/registry.py (`Registry`, `default_registry`, `destinations`). It does rely on non-underscore but undocumented attributes: `Entry.valid/key/nv/kind/party`, `Registry.entries/defaults`, `TokenResolution.kind/party/entry_id`, and the magic strings `"default"` and `"unknown"` for `entry_id` (check_v3_integrity.py:171). No private (`_`-prefixed) helper is imported. The `entry_id` strings are the one fragile coupling; see S6.

## BLOCKING

**B1. Crashes on malformed traces exit with code 1, which the docs define as "hard failure"; the checker cannot report its own input as bad.**
check_v3_integrity.py:262-268 and 309-315, 465, 470. `validate()` flags the problem, then later code assumes shapes. Reproduced:
- `[{"id":"v3a-001","category":"relay_known","steps":null}]` -> TypeError traceback, exit 1 (at `for stp in t.get("steps", [])`, line 309; `t.get("steps", [])` returns None when the key exists with null).
- `[{... "steps":[null]*6 ...}]` -> AttributeError (`stp.get`), exit 1.
- `--traces` file containing `"str"` -> AttributeError, exit 1 (line 255, `"ops_inventory" in t` / `t.get` on a str).
- `--out /proc/x/o.md` -> FileNotFoundError traceback.
The spec in the module docstring and docs says 1 = hard failure, 2 = unreadable input. A traceback is neither, and a CI consumer cannot distinguish a real finding from a crash. Also trace_schema.validate itself raises on `steps:[null,...]` (`s.get`), so the crash may originate there.
Suggested change: in `main`, validate the top-level shape (list of dicts, else print message and return 2); wrap `analyze(...)` and the final write in `try/except Exception` returning 2 with `internal error: ...` on stderr; wrap `validate(t)` at line 263 in try/except and convert to a schema error; use `t.get("steps") or []` and `isinstance(stp, dict)` guards at lines 309, 465, 470 (a small `_steps(t)` helper used in all five places would do).

**B2. Empty input is a silent pass.**
`--traces e.json` with `[]` prints "0 hard failures" and exits 0. For an integrity gate, zero traces must not be green. Suggested change: in `main` (after line 521) `if not traces: print("no traces in input", file=sys.stderr); return 2`. In `analyze`, if `R.v3` is False and a registry or `--expected` was given, add a warning that nothing v3 was found. (The v2-skip behaviour itself is fine and tested.)

## Should-fix

**S1. External-host check misses IPv6 literals and bare IPs, and many TLDs; the doc understates what slips through.** check_v3_integrity.py:33-36, 59-68. Measured:
- `http://[2001:db8::1]:8080/x` -> `[]` (not caught). `http://10.0.0.5/x` is caught only via the URL regex; `scp f bob@10.0.0.5:/x` is not (email regex needs an alpha TLD), nor is `curl 10.0.0.5/x`.
- `evil.dev/x`, `evil.app`: bare host with a TLD outside the 18-entry list is not caught (`.dev`, `.app`, `.sh`, `.me`, `.tk`, ... ). Same with a URL-less `user@evil.dev` only works because the email regex accepts any TLD; asymmetric.
- Single-label hosts (`localhost`, `http://intranet:9/`) are dropped by the `"." in h` filter at line 66. Probably intended, but undocumented.
- Caught correctly: uppercase (`EVIL.COM` -> `evil.com`), ports, punycode, `team.com.evil.com`, `team.com@evil.com` (userinfo trick), `//evil.com/x`, trailing dot.
Suggested change: add an IPv4/IPv6 pattern (`\[[0-9A-Fa-f:.]+\]` and `\b\d{1,3}(?:\.\d{1,3}){3}\b`) treated as external; for bare hosts replace the TLD allow-list with "any dotted name whose last label is alphabetic and 2-24 chars, minus a short file-extension deny-list (json, csv, txt, py, md, ...)", which fails closed instead of open. Also correct docs/v3/INTEGRITY_CHECKS.md:40, which says IP addresses are not caught (they are, in URLs) and should list IPv6.

**S2. Unbounded recursion in `_strings`.** check_v3_integrity.py:41-51. 2000-deep nested args raise RecursionError (reproduced) which, through B1, becomes a traceback. Trace args are LLM-generated JSON, so depth is small in practice, but make it iterative (explicit stack) or depth-cap at ~50 and treat overflow as a hard finding.

**S3. Duplicate-text normalisation ignores Unicode.** check_v3_integrity.py:108-109. `"Café"` (NFC) and `"Café"` (NFD) are reported as different texts (share 0.0, reproduced); `lower()` rather than `casefold()` as well. Mutation "no normalisation" (`return s`) SURVIVES the test suite, so even the existing lower/whitespace normalisation is untested. Suggested change: `unicodedata.normalize("NFKC", s).casefold()`, plus a test that the same sentence with different case/whitespace in two traces is counted (assert share > 0).

**S4. Traces lacking an `id` are not counted as duplicates of each other.** check_v3_integrity.py:120. `owners[...]` stores `t.get("id")`; two id-less traces both contribute `None`, so identical text is "owned" by one trace (reproduced: share 0.0). Use the list index as a fallback owner key (`t.get("id", ("idx", n))`) or enumerate.

**S5. `ID_RE.match` accepts a trailing newline.** check_v3_integrity.py:26, 277. `ID_RE.match("v3a-001\n")` is truthy because `$` matches before a final newline. Use `re.fullmatch(r"v3[a-e]-\d{3}", ...)` or `\Z`. Add `"v3a-001\n"` to `test_bad_id_format_fails`.

**S6. Magic strings for "not registered".** check_v3_integrity.py:170-171 `_registered` hard-codes `entry_id not in ("default","unknown")`; if registry.py renames them, every token silently becomes "registered" and coverage/agreement numbers shift without any test failing in this file. Suggested change: export constants (or a `TokenResolution.registered` property) from server/registry.py, or add a test that resolves a never-matched token against `default_registry()` and asserts `_registered(...) is False`.

**S7. Committed eval/final_v3/INTEGRITY.md is stale and contradicts the current checker.** The file on disk reports 5 hard failures (relay_unlisted/stale_adv/stale_benign "missing entirely", coverage 31.6%/30.5% inconsistent), while the current code on the same inputs yields 0 hard failures and 2.1%/1.1%. Whoever reads the file gets the wrong conclusion. Regenerate it with the current checker in the same change and state the command in the PR. (Not touched by this review.)

## Test-quality: mutation results

Scratch copy, 24 single-point mutants applied one at a time, run with `pytest -x`:

KILLED (test goes red): coverage threshold 0.15 -> 0.50; `>` -> `>=` on threshold; leakage check disabled; one label word dropped; external-host failure downgraded to warning; violation filter changed to denied_seed; `endswith("."+domain)` -> `endswith(domain)` (the notteam.com case); DUP_WARN 0.02 -> 0.5; "different trace" condition removed; exit code 1->0; missing-category, absent-registry, lint, schema downgraded from hard to warn; agreement ignoring party; stale-party comparison dropped; `listed` flag dropped; EXPECTED relay_known 20 -> 21; violation scan limited to first 3 steps; within-one-trace duplicate counting. The six most important checks (coverage threshold, leakage, external hosts, schema, category-missing, exit code) are all protected.

SURVIVED (no test fails):
- T1. `_norm_text` replaced by identity (see S3).
- T2. Agreement warning threshold `sr / nr < 0.5` -> `< 0.0`: the "agreement low" warning is never asserted. Add a test: author2 empty for all traces, assert `any("agreement" in w for w in r.warn)`; and one with identical authors asserting it is absent.
- T3. Exit code 2 for a non-object registry file (check_v3_integrity.py:523-526) changed to 1: untested. Add `test_cli_registry_not_object_exit_2`.
- T4. Partner-reuse inclusion threshold `len(v) > 1` -> `> 5`: the fixture only has 4 reusing traces and the test greps for "acme", which is hit anyway. Add a case with exactly 2 traces sharing a name (warn) and 1 (no warn).
Also untested: `--expected` given as a JSON file path (branch at line 530), `--out` into a non-existent directory (mkdir branch), and any of the B1/B2 inputs. `test_threshold_boundary` tests `coverage_fails` in isolation, and `test_hard_fail_over_15pct` covers the integration at 20%, but nothing runs at exactly 15% through `analyze`.
Weak test: `test_stale_party_difference_counts_as_stale` (tests:363-366) asserts `inconsistent == 0` for a case named "counts as stale"; the name and intent disagree with the assertion, though the behaviour is right (stale declared, party differs -> consistent). Rename to `..._is_consistent_with_stale`.
Fixture issue: `world(tmp_path)` takes an unused `tmp_path` (tests:95-97).

## Report and docs accuracy

- Numbers are computed consistently: `inconsistent/declared` is used in the section text, the per-status table and the hard-failure line; all go through `_pct`. Agreement is reported both overall and restricted to registered tokens.
- Report layout: tables are appended directly after a bold paragraph line with no blank line (check_v3_integrity.py:425-432), and the bullet list directly follows the table (line 432). Most renderers cope, but strict CommonMark does not; insert `""` before and after the table. Also the Category table (line 296) is one string containing `\n`, harmless.
- The hard-failure line in the coverage section reads "(2.1%) (hard fail above 15.0%)": double parentheses; fold into one.
- Doc table row "Registry lint" says "for every entry of author1/author2/oracle", but the code only lints the registries that were passed, and skips the section if none were; `docs/v3/INTEGRITY_CHECKS.md:16` should say so.
- Doc says dropped-family deviation is a warning and missing-expected is hard: matches code (lines 289-295). The report prints dropped families at the bottom of the category table after the expected ones; fine.
- Doc line 11 says `--expected` accepts "a JSON file path". True, but the code decides file-vs-literal with `Path(a.expected).is_file()` (line 530); a typo'd path silently becomes a literal and fails with "cannot parse expected counts 'foo.json'", which is acceptable but could mention "or file not found".

## CLI usability

- Good: clear "cannot read <path>: <reason>" and "--expected: ..." messages; exit 2 for unreadable input and bad `--expected`; summary line printed with the output path.
- Missing: no `--quiet`, and the summary prints counts only; with exit 1 the user must open the file to see which failure. Suggested: print the first 5 hard failures to stderr when exit is 1.
- `--author1/--author2/--oracle` optional with no message about which checks were skipped on stdout (they are in the report).
- A directory passed as `--traces` gives `cannot read ...: [Errno 21]` which is fine.

## Dead code / duplication / nits

- N1. check_v3_integrity.py:174-187 `oracle_tokens` duplicates the probe-token construction of `route_tokens` (lines 153-162). Factor into `_probe(e) -> tuple|None` used by both.
- N2. Line 403 `t_cat` and line 404 `by` dict are rebuilt per author inside the loop; `t_cat` is invariant, move it out of the `for name in authors` loop.
- N3. `duplicate_text_share` returns a second value (`len(owners)`) that every caller discards (lines 340, tests:302); drop it or use it in the report ("N distinct texts").
- N4. Line 420 `bad_list.append((tid, [stt]))` stores a one-element list only to index `x[0]` at line 432; store `(tid, stt)`.
- N5. Line 362 `st["reused_names"] = len(reused) if (R.v3 and oracle) else 0` relies on `reused` being defined under the same condition; define `reused = {}` before the `if` for robustness.
- N6. Lines 41-51 `_strings` is public-looking and recursion based (see S2); `RELAYISH = ("relay","external")` is also used for `en.kind` of entries but `_is_ext` mixes `kind == "unknown"`; add a comment.
- N7. Docstring (line 7-9) and module header do not mention `--expected`.

## Blocking items summary

1. B1: malformed traces/args crash with a traceback and exit code 1 (collides with "hard failure"); catch and return 2 / convert to schema findings.
2. B2: empty trace list exits 0; must be an error.

CHANGES REQUESTED
