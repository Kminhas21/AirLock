# T08 spec-compliance review (integration + end-to-end)

Reviewer: spec-compliance pass, 2026-11-05. Ticket: `docs/v3/tickets/T08-integration-e2e.md`. Scope: the uncommitted working tree on top of `904c746`.
Nothing in `eval/run_eval_v3.py`, `eval/results*/` or `eval/final*/` was run or modified. Probe scripts live only in the session scratchpad.

## Verdict: APPROVE

No blocking items. Five should-fix items (all documentation wording) and several notes are listed below.

## Requirement table

| # | Requirement | Verdict | Evidence |
|---|---|---|---|
| 1 | Two opt-in modes `registry_learned_e` / `registry_learned_dropout` | MET | `MODES` maps them to D9b / D9c, `V3_MODES` and `REGISTRY_MODES` include them, and `_frozen_loader` selects `load_frozen_registry_v3`. With a valid registry, `/health` reports `monitor == requested_monitor == <mode>` and a `RegistrySessionMonitor` is built (probe `ok_control`, both modes). |
| 2 | Defaults unchanged (default monitor `action_sim`) | MET | `DEFAULT_MODE` is untouched. `_resolve_basic` and the `rules` / `action_sim` / `learned` / `registry` / `registry_learned` code paths are unchanged in `git diff HEAD -- server/proposal_monitor.py`. The only edits to existing paths are a shared `_frozen_loader` indirection, the extra env var in the factory cache key, and the `message += "\n" + monitor_line` guarded by `self.mode in V3_MODES`. `tests/server`, `tests/e2e` and `tests/eval` all pass (exit 0). The default Playwright stage passes, 19 passed and 6 skipped. `/health` with nothing set gives `action_sim/action_sim` and no `frozen_model` key. |
| 3 | Mandatory loud fallback to `action_sim` for EVERY failure cause | MET (one documented exception, see S1) | Probe with `get_monitor_factory` + `new_session` + `monitor_info`, 15 causes x 2 modes: SENTINEL_REGISTRY unset, whitespace-only, missing file, a directory, unparseable JSON, JSON that is not an object, lint error (duplicate id), valid registry with an empty `entries` list, frozen file missing / corrupt / wrong `schema_version` / no `schema_version` / the v2 registry frozen file / `{}`. Every one resolves to `active=action_sim`, `registry=None`, `frozen_model=None`, a plain `SessionMonitor`, and a WARNING that names the cause and the fallback. The control case (valid registry) is the only one that stays on the v3 mode. A frozen file that becomes corrupt after the factory was cached is also caught in `new_session` (logged with a traceback, `action_sim` session, `monitor_errors` becomes 1). The one exception is the stub embedder: the factory falls to `rules`, not `action_sim`, because `action_sim` itself cannot run on hashed vectors. A registry detector never runs, which is the safety property. See S1. |
| 4 | `/health`: requested vs active, registry digest, `frozen_model` | MET | Probe via TestClient: `{"monitor": "registry_learned_e", "requested_monitor": "registry_learned_e", "registry": {path, digest, entries}, "frozen_model": {path, sha256: "6864d4777a6fa0a3", schema_version: "registry_models_v3/1"}, ...}`. The sha prefix equals the freeze hash in DECISIONS D10 (`6864d477...`). After a fallback the response is `monitor: action_sim, requested_monitor: <mode>, registry: null, frozen_model: null`. Playwright `registry-ui-v3` asserts both shapes against real servers (3 passed). |
| 5 | Alert text incl. the Monitor line | MET | `Monitor: <mode> (frozen, provisional: see DECISIONS D10)` is the last line of the message for V3 modes only. `.alert-message` has `white-space: pre-line`, so the banner shows it as its own line. The Playwright spec asserts it is the final line of the visible banner. The parity test asserts it on every alert. The old D8 / D9 alert text is unchanged (the guard is on `V3_MODES`). |
| 6 | Parity over all 60 v3 traces, both modes | MET | `tests/e2e/test_registry_parity_v3.py` has 120 parametrised cases (60 traces x 2 modes) with each trace's authored1 registry. Live alert ordinals equal the offline frozen detector's. Alerts precede `tool_pending`. The test asserts the v3 mode is active (no silent fallback), that no other triggers appear, and that the selection is not vacuous (>= 15 alerting traces per mode). All pass. |
| 7 | `--frozen-v3` in `dump_expectations` | MET | D9b / D9c are in `DETECTORS`. `--frozen-v3` is required for them, rejected for other ids, and mutually exclusive with `--frozen`. The file is loaded early for a clean error message. `--registry` is accepted and linted, and the stub embedder is refused. 46 new test lines in `tests/eval/test_dump_expectations.py`, passing. |
| 8 | Replay registry conflict-free and verify-stage "is current" | MET | `make_replay_registry.py --v3` over the 12 ids: 41 entries, conflict-free, lint clean, `cmp` equal to the committed `tests/browser/replay_registry_v3.json` (printed CURRENT). verify.sh stage "v3 replay registry is current and conflict-free" does exactly this. A pytest also pins the committed file and checks that the ids match verify.sh. |
| 9 | New Playwright stages | MET | Three new stages in verify.sh, all inside the Chromium guard. (1) The registry-current stage. (2) Replay parity for `registry_learned_e` over 12 v3 ids. I ran it and 13 passed. (3) `registry-ui-v3` (3 passed): `/health`, the banner on screen before the click with the Monitor line, and the fallback backend on port 8082 with `registry: null`. D9c has no browser stage; it is covered only by pytest parity, which the ticket accepts. |
| 10 | Docs honest about v3 limits | PARTIALLY | `docs/registry.md` ("What the v3 evaluation showed" and "Keeping the registry current") and the README block carry the provisional status, C6 6/7, C8 0/6, the none-condition result, the mixed-trace result, and the "no default recommended" statement. Wording issues S1 to S4 below. |
| 11 | 2 new mutants | MET | R3 (v3 frozen-file failure no longer falls back) and R4 (denied-party pool ignores the match) are in `MUTANTS`. I ran both against a throwaway copy with the v3 unit file: both KILLED. The target strings match exactly once (not stale). |

## Probes requested

### (a) Defaults and existing modes unchanged
Confirmed by the diff review and the test runs described in row 2. One additive change to note (N1).

### (b) No path lets a v3 mode run without a valid registry
Tried the 15 causes x 2 modes shown in row 3, plus a TestClient `/health` check for the empty-entries and warnings-only registries. The only way a v3 detector is instantiated is `_resolve_registry` (after `load_registry` returned a Registry and, for V3 modes, `entries` is non-empty) and `_new_registry_session` (reached only from a factory whose `mode` is a registry mode, which exists only after that resolution). A registry that lints with warnings only (an unknown top-level key; `Registry.validate()` returned `[]`) correctly stays active, because warnings are not errors in `server/registry.py` (see N2).

### (c) Documentation claims versus `eval/results_v3/REPORT_V3.md`

| Claim | Report | Status |
|---|---|---|
| D9b on-time 73.3% [56.7, 88.2] vs 36.7% for action_sim | same | supported |
| FA overall 1.6%, benign-after-denial 5.9%, traps 2.9% (DECISIONS) | 1.6 / 5.9 / 2.9 | supported |
| "false alarms 1.6% overall" (registry.md) | same | supported |
| C6 6/7 (85.7%), bar 20%, n=7 | 0.857, n=7 | supported |
| C8 D9b 0/6, action_sim about 1/6 | 0.000 vs 0.167, n=6 | supported as a point estimate |
| none-condition: D9b 0%, D9 16.7%, D8 3.3% vs 36.7% | same | supported |
| mixed traces: 40% on time | D9b 40.0% | supported |
| relay_known 90% vs 50% | 90.0 / 50.0 | supported |
| listed routes 22/22 | C2 1.000, n=22 | supported |
| "D9c scored the same" | on-time identical (73.3%), but FA 1.8% vs 1.6% and (c) 6.5% vs 5.9% | imprecise, see S2 |
| "in v3 slightly worse than `action_sim`" where the registry is silent | 0/6 vs 1/6, strata flagged as insufficient data | overstated, see S3 |
| DECISIONS D10 "7.8 ms" | Report: median 0.08 ms, p95 42 ms, C9 value 0.078 | not supported, see S4 |

### (d) No recommended default
README and `docs/registry.md` state "No monitor was recommended as the default; the default stays `action_sim`". The word "recommended" appears only in that negation. Consistent with SPEC_V3 Amendment 2 and the report ("recommended as default: None"). OK. The older one-line "Recommendation rule" at SPEC_V3 line 46 is superseded by the Amendment and is not repeated in the docs.

### (e) verify.sh
`bash -n scripts/verify.sh` is clean. The new stages use `$R`-based absolute paths for traces, registry and frozen file, run inside the existing Chromium guard, and register failures through `run`. The scratch registry is created in `mktemp -d`. I ran the replay stage with the wrong monitor (`SENTINEL_MONITOR=action_sim`, D9b expectations): 7 of 13 tests FAILED (v3a-009, v3a-013, v3e-001, v3e-008, v3d-007, v3d-008, v3e-011), so the stage discriminates. The correct monitor passes 13/13. The "is current" stage fails if the committed registry drifts (`cmp`) and on a merge conflict (`make_replay_registry` returns 1).

### (f) `white-space: pre-line`
Only affects `.alert-message`. It collapses runs of spaces as before and only honours `\n`. The default Playwright stage (live.spec with the rules monitor, including the adversarial banner tests) passes, 19 passed and 6 skipped, and the registry-ui-v3 banner test reads the banner on screen. Not run in this review: the v2 `registry-ui` stage.

## Findings

| Severity | ID | Finding | Where | Suggested fix |
|---|---|---|---|---|
| should-fix | S1 | Docs say the stub embedder leads to `action_sim`. In fact `_fallback_registry` calls `_resolve_basic("action_sim")`, which itself falls to `rules` on the stub. Probe: `active=rules` for both v3 modes. The README line 21 already says stub implies `rules`, so the new lines contradict it. | README.md (new v3 bullet, "stub embedder all log a WARNING and run `action_sim`"); docs/registry.md ("or the embedder is the stub" in the v3 section, line ~295) | Say "`action_sim` (or `rules` when the embedder is the stub)". Optionally add a unit test for the stub case. |
| should-fix | S2 | "D9c ... scored the same": on-time is identical, but FA overall is 1.8% vs 1.6% and benign-after-denial 6.5% vs 5.9% (both criteria still met). | docs/registry.md "D9b qualified only provisionally" | "D9c scored the same on-time (73.3%) with a similar false-alarm profile (1.8% overall)". |
| should-fix | S3 | "in v3 slightly worse than `action_sim`" for silent routes rests on 0/6 vs 1/6 in a stratum the report calls insufficient data. | docs/registry.md "Missing routes are silent" | Say "no better than `action_sim` in v3 (0 of 6 traces on time against about 1 of 6; too few to conclude)". |
| should-fix | S4 | DECISIONS D10 says "7.8 ms" for D9b latency. REPORT_V3 gives a warm median of 0.08 ms (p95 42 ms) and a C9 value of 0.078. Not in the T08 diff, but D10 was cited by the ticket. Raise with the maintainer. | DECISIONS.md D10 | Correct to "median 0.08 ms, p95 42 ms" (or a unit fix). |
| should-fix | S5 | The registry.md sentence "Read the next-but-one section before relying on them" is ambiguous. The v3 section is two `##` headings later and the D9 "Honest limits" sits between. README already names the section. | docs/registry.md ~line 217 | Name the heading "What the v3 evaluation showed". |
| note | N1 | `/health` now also carries a `frozen_model` key when a D8 / D9 mode is requested (`requested in REGISTRY_MODES`), not only for the v3 modes. Additive, no test breaks, and it matches the docstring ("registry mode"). | server/live_drift.py | None; mention in the docs if desired. |
| note | N2 | A registry that lints with warnings only, or whose entries are all `internal` kinds, activates the v3 monitor. By design (warnings are not errors), but the evaluation shows these detectors do nothing useful on routes the registry does not list (C8). | server/proposal_monitor.py | Docs already say so; consider a log line at INFO naming the relay entry count. |
| note | N3 | After a fallback inside `new_session` (frozen file broke after startup), `/health.monitor` still reads the v3 mode and only `monitor_errors` increments. The session is correctly an `action_sim` session and logged loudly. The factory cache key does not include the frozen file's mtime. | server/proposal_monitor.py `get_monitor_factory` | Optional: add the frozen file's `_file_sig` to the cache key. |
| note | N4 | D9c has parity coverage in pytest only; the browser stages use D9b. Meets the ticket. | scripts/verify.sh | None. |
| note | N5 | `playwright.config.ts` forwards `SENTINEL_REGISTRY_MODEL_V3` from the caller's shell to both backends; the verify stages set it explicitly, so no leak in the gate. | frontend/playwright.config.ts | None. |

No BLOCKING items.

## Final: APPROVE
