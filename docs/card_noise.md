# Card noise: how often would the approval card fire?

Measured with `scripts/card_noise.py` (tests: `tests/test_card_noise.py`, push tier). It replays tool calls through `Policy.evaluate_call`, the
same entry the hub uses (starter rules plus the D31 confinement floors), and counts allow / ask / deny. An `ask` is a card a human must answer.
Policy under test: `builtin:starter`, digest `d4e0e03823dfb93a`. The policy was not changed; the list at the end is advice only.

    python scripts/card_noise.py --traces eval/traces eval/traces_v2 eval/traces_v3 --only-label ok
    python scripts/card_noise.py --claude-projects ~/.claude/projects      # local transcripts; prints counts, rule ids and generic tool names only

Every run is done twice: **sandboxed** (the server is confinable: path allows are kernel-confined and stay allowed) and **unsandboxed** (path allows
become the `unconfinable` ask), which is the cost of the D31 decision.

## What data exists, and how thin it is

| corpus | size | what it is | fit for this question |
|---|---|---|---|
| `eval/traces`, `traces_v2`, `traces_v3` | 121 + 80 + 60 traces; 878 + 561 + 503 proposals; label `ok` (benign): 666 + 424 + 376 | LLM-generated scripted tasks with invented MCP-style tool names (`send_email`, `query_database`, `update_task` ...), labelled `ok` / `denied_seed` / `violation` | Synthetic. The tool mix was written to exercise detectors, not drawn from real use. Treat as a stress mix, not as usage. |
| local Claude Code transcripts | 10 project folders, 113 transcript files (103 are sub-agent logs), 111 with at least one evaluable call; 4,007 evaluated calls, 453 harness-internal calls not representable | one person's real tool-call logs, mostly building this very project | Real, but one user, one kind of work (heavy shell use, sub-agent orchestration). Not a sample of "operators". |
| `tests/e2e/data`, seismograph, demo cached runs | a policy file, test fixtures, scripted scenarios | no recorded real agent sessions | not used |

There are **no recorded production or operator sessions** in the repo. The v3 replay (115 of 376 benign allowed, 0 of 127 violating) is reproduced by
the tool (sandboxed, `traces_v3`, label `ok`: allow 115, ask 261). Claude Code transcripts were read locally; nothing from them is stored in the repo.

## How Claude Code tool names were mapped (and what is not representable)

| Claude Code tool | evaluated as | fidelity |
|---|---|---|
| `Read` | `read_file {path, offset, length}` | approx: the starter's allow rule is written for the filesystem / Desktop Commander read tools; image, PDF and notebook reads are not told apart |
| `Glob`, `Grep` | `search_files {path, pattern}` (missing path = `.`) | approx: `Grep` searches file contents, `search_files` matches names; there is no content-search tool in the starter |
| `Write`, `Edit`, `NotebookEdit` | `write_file`, `edit_file` | analog: the starter has no allow rule for them, so the verdict is the default ask whatever the arguments |
| `Bash` | `start_process {command}` | analog: same (no shell is allowed by name) |
| `WebFetch`, `WebSearch` | `fetch`, `web_search` | analog: same |
| `mcp__<server>__<tool>` | server, tool, arguments as logged | direct (shown as "mcp:other" so no third-party names are printed) |
| `Agent`, `Monitor`, `SendMessage`, `ToolSearch`, `Skill`, task / plan tools, anything unknown | not evaluated | not representable: they are not calls to an MCP server; counted separately (453) |

So these numbers do **not** describe the MCP filesystem server: Claude Code's `Read` is not that server's `read_text_file`, and a real agent
connected through the proxy would see only the calls it makes to MCP servers. They say how the starter's rule set treats a coding agent's *kinds* of
action. Other limits: the tool replays a fixed policy with no alerts and no secrets (those escalate an allow to an ask, so real rates can only be
higher); it does not model "always allow" standing rules made from cards (those would lower the rate; not measured); a session is a transcript file,
and a sub-agent log counts as its own session.

## Results (aggregate)

### Eval traces, benign calls only (`ok`, all three corpora: 261 traces, 1,466 calls)

| | allow | ask | cards per 100 calls | per trace: mean / median / max |
|---|---|---|---|---|
| sandboxed | 559 | 907 | **61.9** | 3.5 / 3 / 8 |
| unsandboxed | 0 | 1,466 | **100.0** | 5.6 / 5 / 12 |

Ask causes, sandboxed: default 901, `ask-sensitive-path` 6. Unsandboxed: default 901, **unconfinable 559** (`allow-read-file` 342, `allow-read-only-fs` 114,
`allow-search` 103), `ask-sensitive-path` 6. Every trace saw at least one card. By tool (sandboxed, asks): `write_file` 265, `run_shell_command` 176,
`query_database` 103, `update_task` 92, `send_email` 78, `create_task` 72, `send_slack_message` 65; reads and listings are allowed (342/346, 114/115, 103/116).
`traces_v3` alone: 69.4 per 100 sandboxed.

### Real Claude Code transcripts (111 sessions, 4,007 evaluated calls)

| | allow | ask | cards per 100 calls | per session: mean / median / max |
|---|---|---|---|---|
| sandboxed | 228 | 3,779 | **94.3** | 34.0 / 10 / 1,005 |
| unsandboxed | 0 | 4,007 | **100.0** | 36.1 / 11 / 1,019 |

Ask causes, sandboxed: default 3,776, `ask-sensitive-path` 3. Unsandboxed adds **unconfinable 228** (`allow-read-file` 214, `allow-search` 10,
`allow-read-only-fs` 4). By tool, asks: `Bash` 3,638 (91% of all calls), `Write` 101, `mcp:other` 28, `Edit` 9, `WebSearch` 3; `Read` 203 and `Grep` 10 allowed.
Excluding `Bash`, 369 calls remain: 38% ask sandboxed, 100% unsandboxed. Every session saw a card, but the median is 10: the mean is pulled up by a few
shell-heavy sessions.

### Cost of D31

Unsandboxed servers lose every path allow: +5.7 cards per 100 calls on the real transcripts (94.3 to 100.0) and +38.1 on the benign eval mix (61.9 to 100.0).
The cost scales with how read-heavy the agent is; for a shell-heavy coding agent it is small because almost everything already asks.

## Top 5 causes of asks

Sandboxed, as (cause, tool: asks):

| | real transcripts | benign eval traces |
|---|---|---|
| 1 | default, shell (`Bash`): 3,638 | default, `write_file`: 265 |
| 2 | default, `Write`: 101 | default, `run_shell_command`: 176 |
| 3 | default, third-party MCP tools with no rule: 25 | default, `query_database`: 103 |
| 4 | default, `Edit`: 9 | default, `update_task`: 92 |
| 5 | `ask-sensitive-path`: 3 / default `WebSearch`: 3 | default, `send_email`: 78 |

Over 99% of asks are the **default ask** in both corpora: a tool no rule names. The explicit ask rules (`ask-sensitive-path`, 6 of 907 and 3 of 3,779) are
the quietest rules; the other `ask-sensitive-*` rules fired 0 times. The noisiest *allow floor* is `unconfinable` (only on unsandboxed servers); `unconfined`
fired 0 times, as the shipped starter's allow rules all carry `confine` maps.

## Recommendations (nothing was changed)

1. **Do not try to tune the default ask away.** It is the card for shell, writes, mail, chat and database calls, which is what the product is for. A
   coding agent that shells out ~90% of the time will always see a card per call under any safe policy; the lever is not a rule. The "always allow"
   standing rule from a card is the existing release valve; its effect on card counts is worth measuring in a real operator trial.
2. **Writes into the project are the next-largest noise and the only one with a principled fix**: `write_file` / `edit_file` are 2.7% of real calls but 29% of
   benign eval asks. `confine` has only `read` and `list` rights, so a write cannot be auto-allowed safely. A `write` right (Landlock write grant on the named
   file) would be a new decision (D32-sized), not a rule tweak.
3. **Keep the D31 `unconfinable` floor; reduce how often servers are unconfinable.** It is 5.7 points on real use but 38 on a read-heavy mix, and only on
   unsandboxed servers. Document or default servers to `sandbox` + `runtime` (the compose demo already does) rather than relax the floor.
4. **Third-party read-only tools** (25 of 28 `mcp:other` asks, and the eval's `query_database`) have no starter rule. Add allow rules per real server only after
   listing that server's tools and arguments, as D29 did for the filesystem, memory and time servers; do not write rules from the synthetic eval tool names.
5. **Sensitive-path needles** are cheap: 6 of 1,466 benign eval calls (0.4%) and 3 of 4,007 real calls. The two needles responsible were `.env` (3 eval, 3 real)
   and `secrets` (5 eval); both are over-broad (`.env.example`, `secrets` as a directory name) but in the safe direction. Leave them.
6. **Measure again with real operator sessions through the proxy.** The proxy event log (`eventlog_cli policy-test` replays it with the logged `confinable`)
   is the right corpus: it has real MCP calls and the real sandbox state, which no corpus here has.


### The narrow write right (D32): what it does and does not buy
The replay cannot know whether a file exists, so it treats every write as NOT confinable (the `write_unsupported` ask) and the numbers above are unchanged by D32: v3
sandboxed, label `ok`: allow 115, ask 261; 0 of 127 violating allowed. The CEILING, if every file the traces write existed and the proxy vouched for it
(`scripts/card_noise.py --assume-writes-confinable`, `policy_cli.run_replay(write_confinable=True)`): 181 benign allowed (66 more, all `.md`/`.txt` doc writes) and
**10 of the 67 `violation`-labelled proposals allowed too** (data staged into a shared `.txt`/`.md`, some base64): the extension rule cannot tell staging from notes, the
kernel bounds WHICH file, never what the text means. In production a drift-monitor alert still turns such an allow into a card; the replay has no monitor. A test pins
both numbers (tests/server/test_policy_starter_write.py). On the design's real-transcript measurement (112 Write/Edit calls of 4,007, 62% `.py`, 15% `.md`) the docs
allowlist covers about 17 calls: at most 0.4 cards per 100 calls saved, and only for files that already exist; creating files and every source-code write stay cards by
design. Treat the synthetic upper bound (about 45 asks per 100 instead of 61.9) as a ceiling, not a forecast.
