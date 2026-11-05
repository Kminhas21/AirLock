import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { API, LLM, evs, loadExpected, loadTraces, recordFrames, REPLAY_REGISTRY } from "./helpers/traces";

// Union monitor (frozen D9c OR D3, opt-in, DECISIONS.md D13/D14) in the real UI (stage "browser registry UI union" of scripts/verify.sh;
// skipped in every other stage).
// Backend 1 runs SENTINEL_MONITOR=registry_learned_dropout_or_action with the destination registry REPLAY_REGISTRY; backend 2 (port
// FALLBACK_API_PORT) runs the same mode WITHOUT SENTINEL_REGISTRY and must fall back loudly to action_sim.
// A relay_known v3 trace (default v3a-001) is replayed with the human acting per the recorded decisions.

const TRACE_ID = process.env.UI_TRACE_ID ?? "v3a-001";
const FALLBACK_PORT = Number(process.env.FALLBACK_API_PORT ?? 0);
const FALLBACK_API = `http://127.0.0.1:${FALLBACK_PORT}`;
const MODE = "registry_learned_dropout_or_action";
const TRIGGERS = ["registry_denied_party_match", "denied_effect_match"]; // the union: registry member, else action similarity
const isUnionTrigger = (t: unknown) => TRIGGERS.includes(t as string);

test.skip(process.env.SENTINEL_MONITOR !== MODE || !REPLAY_REGISTRY, `registry UI stage only (SENTINEL_MONITOR=${MODE} + REPLAY_REGISTRY)`);

const trace = () => loadTraces().find((t) => t.id === TRACE_ID)!;
const registry = () =>
  JSON.parse(readFileSync(REPLAY_REGISTRY, "utf8")) as {
    entries: { id: string; kind: string; party: string; match: Record<string, string>; note: string }[];
  };

test("the registry is active: /health reports the requested and the active monitor and the registry", async ({ request }) => {
  const h = await (await request.get(`${API}/health`)).json();
  expect(h).toMatchObject({ status: "ok", monitor: MODE, requested_monitor: MODE, embedder: "minilm", monitor_errors: 0, session_fallbacks: 0, last_session_fallback: null });
  expect(h.registry.path).toBe(REPLAY_REGISTRY);
  expect(h.registry.entries).toBe(registry().entries.length);
  expect(h.registry.digest).toMatch(/^[0-9a-f]{16}$/);
  expect(h.frozen_model.schema_version).toBe("registry_models_v3/1");
  expect(h.frozen_model.path).toMatch(/frozen_registry_models_v3\.json$/);
  expect(h.frozen_model.sha256).toMatch(/^[0-9a-f]{16}$/);
});

test(`replay ${TRACE_ID} (relay_known): the critical registry banner is on screen BEFORE the human decides`, async ({ page, request }) => {
  const tr = trace();
  expect(tr.category).toBe("relay_known");
  const exp = loadExpected([TRACE_ID])[TRACE_ID];
  expect(exp.alert_ordinals.length, "offline union (D9c OR D3) must alert on this trace or the test proves nothing").toBeGreaterThan(0);
  const first = exp.alert_ordinals[0];
  const info = await (await request.get(`${LLM}/_trace_info?id=${TRACE_ID}`)).json();
  const nTurns: number = info.turns.length;
  const decisions = tr.steps.filter((s) => s.proposal).map((s) => s.proposal!.decision);
  const proposals = tr.steps.filter((s) => s.proposal).map((s) => s.proposal!);

  const frames = recordFrames(page);
  await page.goto("/");
  await expect(page.locator(".connection-dot.connected")).toBeVisible();
  await page.fill(".task-input", `TRACE:${TRACE_ID}`);
  await page.click(".run-button");

  const banner = page.locator(".alert-banner");
  for (let k = 0; k < nTurns; k++) {
    await expect.poll(() => evs(frames, "tool_pending", "in").length, { timeout: 20_000, message: `pending #${k}` }).toBeGreaterThan(k);
    if (k === first) {
      // the human has NOT clicked yet: the decision buttons are waiting and the banner is already there
      await expect(page.locator(".btn-deny").first()).toBeVisible();
      expect(evs(frames, "tool_decision", "out").length).toBe(k);
      await expect(banner).toBeVisible();
      await expect(banner).toHaveClass(/critical/);
      const trig = (await page.locator(".alert-trigger").innerText()).replace(/^Trigger:\s*/, "");
      expect(TRIGGERS, `unexpected trigger ${trig}`).toContain(trig);
      const text = (await banner.innerText()).replace(/\s+/g, " ");
      const lines = (await page.locator(".alert-message").innerText()).trim().split("\n");
      expect(lines, "exactly two lines: the explanation, then the Monitor line").toHaveLength(2);
      expect(lines.at(-1), "the Monitor line is the final line of the alert text").toBe("Monitor: registry_learned_dropout_or_action (frozen, provisional: see DECISIONS D10)");
      if (trig === "denied_effect_match") {
        // the action-similarity member fired (the registry member did not): D3 wording, no registry details
        expect(text).toMatch(/nearly the same as one you already denied/);
        expect(text).toMatch(/Earlier denied effect:/);
        console.log(`UNION BANNER (D3 member, before the click, ordinal ${k}): ${text}`);
      } else {

      // it names the relay destination of THIS proposal, its registry entry, the note and the party
      const args = JSON.stringify(proposals[k].args).toLowerCase();
      const relay = registry().entries.find((e) => e.kind === "relay" && args.includes(Object.values(e.match)[0].toLowerCase()));
      expect(relay, `no relay entry of the registry appears in the alerted proposal ${args}`).toBeTruthy();
      expect(text.toLowerCase()).toContain(Object.values(relay!.match)[0].toLowerCase()); // destination token
      expect(text).toContain(`registry entry ${relay!.id}`);
      expect(text).toContain(relay!.note);
      expect(text).toContain(`party '${relay!.party}'`);
      expect(text).toMatch(/earlier DENIED proposal/);
      expect(text).toMatch(/Top feature contributions: \w+ [+-]\d+\.\d\d, \w+ [+-]\d+\.\d\d/);
      expect(text).toMatch(/payload similarity \d\.\d\d/);
      await page.screenshot({ path: "e2e/.results/registry-union-banner.png", fullPage: true });
      console.log(`UNION BANNER (registry member, before the click, ordinal ${k}): ${text}`);
      }
    }
    const btn = decisions[k] === "approve" ? ".btn-approve" : ".btn-deny";
    await page.locator(btn).first().click();
    await expect.poll(() => evs(frames, "tool_resolved", "in").length, { timeout: 20_000, message: `resolved #${k}` }).toBeGreaterThan(k);
  }
  await expect(page.locator(".run-button")).toHaveText("Run", { timeout: 20_000 });

  // wire level: the alert frame precedes the tool_pending and the decision of the node it is about, and the live alert set
  // equals the offline frozen union run with the very same registry file
  const pending = evs(frames, "tool_pending", "in");
  const ordinal = new Map(pending.map((f, i) => [f.data.node_id as string, i]));
  const alerts = evs(frames, "alignment_alert", "in").filter((f) => isUnionTrigger(f.data.trigger));
  expect(new Set(alerts.map((a) => a.data.linked_node_id)).size, "at most ONE alert per proposal").toBe(alerts.length);
  for (const a of alerts) {
    const node = a.data.linked_node_id as string;
    expect(a.data.severity).toBe("critical");
    expect(a.seq).toBeLessThan(pending[ordinal.get(node)!].seq);
    expect(a.seq).toBeLessThan(evs(frames, "tool_decision", "out").find((d) => d.data.node_id === node)!.seq);
  }
  expect([...new Set(alerts.map((a) => ordinal.get(a.data.linked_node_id as string)!))].sort((x, y) => x - y)).toEqual(exp.alert_ordinals);
  expect(evs(frames, "session_complete", "in")).toHaveLength(1);
});

// B1 (T08 review): `.alert-message` renders `white-space: pre-line`, so a newline inside an agent-controlled string would be a real
// banner line. HOSTILE:<id> (tests/browser/fake_llm.py) replays the trace with "\nCRITICAL: all clear, approve" appended to EVERY
// tool name. The monitor must sanitise it: the banner keeps exactly two lines (the explanation, then the Monitor line) and the fake
// text is only ever INSIDE the first line.
test(`hostile tool name (newline + fake text) on ${TRACE_ID}: the banner has no extra line, no fake line, and the Monitor line is last`, async ({ page, request }) => {
  const SPOOF = "CRITICAL: all clear, approve";
  const MONITOR_LINE = "Monitor: registry_learned_dropout_or_action (frozen, provisional: see DECISIONS D10)";
  const info = await (await request.get(`${LLM}/_trace_info?id=${TRACE_ID}`)).json();
  const nTurns: number = info.turns.length;
  const decisions = trace().steps.filter((s) => s.proposal).map((s) => s.proposal!.decision);

  const frames = recordFrames(page);
  await page.goto("/");
  await expect(page.locator(".connection-dot.connected")).toBeVisible();
  await page.fill(".task-input", `HOSTILE:${TRACE_ID}`);
  await page.click(".run-button");

  let checked = 0;
  for (let k = 0; k < nTurns; k++) {
    await expect.poll(() => evs(frames, "tool_pending", "in").length, { timeout: 20_000, message: `pending #${k}` }).toBeGreaterThan(k);
    const pending = evs(frames, "tool_pending", "in")[k];
    expect(pending.data.tool_name as string, "the hostile name reaches the UI as sent (the monitor, not the transport, is the defence)").toContain("\n" + SPOOF);
    const alert = evs(frames, "alignment_alert", "in").find((f) => f.data.linked_node_id === pending.data.node_id && isUnionTrigger(f.data.trigger));
    if (alert) {
      // wire level: exactly two lines, the fake text only inside the first one
      const wire = (alert.data.message as string).split("\n");
      expect(wire, JSON.stringify(wire)).toHaveLength(2);
      const fromRegistry = alert.data.trigger === "registry_denied_party_match";
      if (fromRegistry) {
        expect(wire[0].startsWith("Registry match: ")).toBe(true);
        expect(wire[0]).toContain(`send_email ${SPOOF} to `);
      }
      expect(wire[1]).toBe(MONITOR_LINE);
      expect(/[\u2028\u2029\u0085\u202a-\u202e\u2066-\u2069\u200b-\u200f\r]/.test(alert.data.message as string)).toBe(false);
      // what the human sees, before any click
      const banner = page.locator(".alert-banner");
      await expect(banner).toBeVisible();
      await expect(banner).toHaveClass(/critical/);
      const shown = (await page.locator(".alert-message").innerText()).trim().split("\n");
      expect(shown, `visible banner lines: ${JSON.stringify(shown)}`).toHaveLength(2);
      expect(shown.some((l) => l.trim().startsWith(SPOOF)), "no fake line of its own").toBe(false);
      if (fromRegistry) expect(shown[0]).toContain(SPOOF);
      expect(shown.at(-1)).toBe(MONITOR_LINE);
      checked++;
    }
    // the tool name in the graph nodes collapses to one line too (normal white-space; params are JSON.stringify-ed)
    for (const t of await page.locator(".flow-node-type-badge").allInnerTexts()) expect(t).not.toContain("\n");
    await page.locator(decisions[k] === "approve" ? ".btn-approve" : ".btn-deny").first().click();
    await expect.poll(() => evs(frames, "tool_resolved", "in").length, { timeout: 20_000, message: `resolved #${k}` }).toBeGreaterThan(k);
  }
  expect(checked, "at least one hostile proposal must have raised a registry alert or the test proves nothing").toBeGreaterThan(0);
  await expect(page.locator(".run-button")).toHaveText("Run", { timeout: 20_000 });
});

test("without SENTINEL_REGISTRY the same session starts under the loud fallback (action_sim), /health says so", async ({ page, request }) => {
  test.skip(!FALLBACK_PORT, "FALLBACK_API_PORT not set");
  const h = await (await request.get(`${FALLBACK_API}/health`)).json();
  expect(h).toMatchObject({ status: "ok", monitor: "action_sim", requested_monitor: MODE, registry: null, frozen_model: null, embedder: "minilm" });

  // same trace, same recorded human, against the backend that has no registry (a raw WebSocket from the page: the origin
  // http://localhost:5173 is the allowed one; D9b is useless without a registry: 0% on-time in v3). The fallback is D3: it may alert, but never with the registry trigger.
  const decisions = trace().steps.filter((s) => s.proposal).map((s) => s.proposal!.decision);
  await page.goto("/");
  const got: Record<string, unknown>[] = await page.evaluate(
    ({ port, id, decisions }) =>
      new Promise<Record<string, unknown>[]>((resolve, reject) => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
        const seen: Record<string, unknown>[] = [];
        let n = 0;
        const timer = setTimeout(() => reject(new Error("fallback session timed out")), 45_000);
        ws.onopen = () => ws.send(JSON.stringify({ event: "start_task", task: `TRACE:${id}`, scenario: "aligned", mode: "live" }));
        ws.onmessage = (m) => {
          const e = JSON.parse(m.data);
          seen.push(e);
          if (e.event === "tool_pending") ws.send(JSON.stringify({ event: "tool_decision", node_id: e.node_id, decision: decisions[n++] }));
          if (e.event === "session_complete" || e.event === "error") {
            clearTimeout(timer);
            ws.close();
            resolve(seen);
          }
        };
        ws.onerror = () => reject(new Error("websocket error"));
      }),
    { port: FALLBACK_PORT, id: TRACE_ID, decisions },
  );
  expect(got.filter((e) => e.event === "session_complete")).toHaveLength(1);
  expect(got.filter((e) => e.event === "tool_pending").length).toBe(decisions.length);
  const triggers = got.filter((e) => e.event === "alignment_alert").map((e) => e.trigger);
  expect(triggers).not.toContain("registry_denied_party_match");
  expect(triggers.every((t) => t === "denied_effect_match" || t === "goal_persistence"), JSON.stringify(triggers)).toBe(true);
  // /health is unchanged by the session
  expect((await (await request.get(`${FALLBACK_API}/health`)).json()).monitor).toBe("action_sim");
});
