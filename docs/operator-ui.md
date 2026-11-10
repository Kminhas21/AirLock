# Operator UI (Inbox): what a held call shows and what you can do with it

## On every held call
- **Why flagged** (when a monitor alerted): trigger, severity, a score-vs-threshold bar, the alert text, and "Earlier denied in this session" (the calls whose denial the alert refers to).
  If a `denied_effect_match` alert fires on a call whose file name or value your own denial note named (e.g. you denied `/p/report.txt` with "save it as summary.md instead" and the agent proposes `/p/summary.md`), the alert is labelled
  "You suggested this in your denial note (summary.md)." and a critical one is shown as a warning. Limits: the name must be in the same directory as the call you denied (a note saying "summary.md" does not bless `/etc/cron.d/summary.md`),
  the name must be a whole word of the note (`summary.md` does not match `summary.mdx`) and must be the value of a field that the denied call also had and that CHANGED (a new or unchanged field never counts), only `denied_effect_match` is affected, and the alert is never suppressed: it is still shown, logged, and still stops a policy rule from auto-allowing the call.
- **Session so far**: counters (approved / denied / auto / policy) and the last 10 calls of this proxy session with a one-line argument preview. Previews redact values under secret-looking keys (`password`, `token`, ...);
  the live card shows the CURRENT call's arguments in full on purpose: you must see exactly what you approve.
- **Deny with a reason**: type a reason next to Deny (max 200 characters). The agent receives `Denied by SENTINEL: human (operator note: <your text>)`, so it can adapt ("use /project instead").
  Your note is also logged and shown in the history. It is shown to the agent as plain text; do not paste secrets.
- **Make it standing** (only if the backend runs with `SENTINEL_POLICY=<file>` AND `SENTINEL_POLICY_WRITABLE=1`): "Always allow like this", "Always deny", "Always ask". A confirm step states the scope in words:
  *exact arguments*, *this tool under the same folder*, or (deny/ask only) *this tool, any arguments*. The backend builds the rule from the call you are looking at (the browser never sends a rule), validates the whole policy,
  writes it atomically (previous bytes kept in `<file>.bak`) and logs it first when the event log is on. **Rules apply to NEW proxy sessions only**; the call on screen is still yours to decide.
  At most 20 rule requests per minute. Closed set of outcomes: ok, not_writable, not_confirmed, unknown_call, scope_not_allowed, cannot_build, invalid_policy, write_failed, log_unavailable, rate_limited.

## Drift threshold
`drift_update` events now carry the detector's active threshold; the chart line and the node drawer use it (recorded replays without it fall back to 3.368). UI and backend can no longer disagree (B18).

## Safety notes
Everything the agent or a policy controls (tool names, arguments, rule ids, notes) is rendered as plain text, one line where labelled. Standing rules widen what runs without you: prefer *exact* or *under the same folder* for allow, and review `policy.json` (`policy_cli lint`) now and then.
See DECISIONS D20 and docs/policy.md.

Known limit of the "You suggested this" label: it is bound to a changed value at a key the denied call also had, but it cannot tell WHICH changed value made the monitor alert. An agent that keeps a denied recipient and
changes an unrelated existing field (say `subject`) to a whole word of your note can still earn the label. The call is still held, the alert is still shown and logged (as a warning), and the matched word is printed in
the message, so a harmless word gives it away.

