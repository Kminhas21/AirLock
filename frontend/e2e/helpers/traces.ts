import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type { Page } from "@playwright/test";

/** Shared helpers for the trace-replay spec: trace loading, id selection, expectations, frame recording. */

export const REPO_ROOT = path.resolve(process.cwd(), ".."); // playwright runs from frontend/
export const LLM_PORT = Number(process.env.LLM_PORT ?? 9101);
export const API_PORT = Number(process.env.API_PORT ?? 8081);
export const LLM = `http://127.0.0.1:${LLM_PORT}`;
export const API = `http://127.0.0.1:${API_PORT}`;

export interface TraceStep {
  i: number;
  agent_text: string;
  proposal: null | { tool: string; args: Record<string, unknown>; decision: "approve" | "deny"; label: string };
}
export interface Trace {
  id: string;
  category: string;
  steps: TraceStep[];
}
export interface Expected {
  alert_steps: number[];
  alert_ordinals: number[];
  proposal_steps: number[];
  step_to_ordinal: Record<string, number>;
  decisions: ("approve" | "deny")[];
}

/** Same lookup rule as tests/browser/fake_llm.py: FAKE_LLM_TRACES (colon-separated) or eval/final/traces.json. */
export function loadTraces(): Trace[] {
  const spec = process.env.FAKE_LLM_TRACES || path.join(REPO_ROOT, "eval", "final", "traces.json");
  const byId = new Map<string, Trace>();
  for (const f of spec.split(":").filter(Boolean)) {
    const data = JSON.parse(readFileSync(f, "utf8"));
    for (const t of Array.isArray(data) ? data : [data]) byId.set(t.id, t);
  }
  return [...byId.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
}

/** Default: REPLAY_IDS (comma separated) or 10 traces spanning every category present (one per category,
 *  then extra traces from different generators in the categories with the most traces until there are 10). */
export function replayIds(traces: Trace[] = loadTraces()): string[] {
  const env = (process.env.REPLAY_IDS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (env.length) return env;
  const cats = [...new Set(traces.map((t) => t.category))];
  const picked: Trace[] = cats.map((c) => traces.find((t) => t.category === c)!);
  const bySize = [...cats].sort((a, b) => traces.filter((t) => t.category === b).length - traces.filter((t) => t.category === a).length);
  for (const c of bySize) {
    if (picked.length >= 10) break;
    const gens = new Set(picked.filter((t) => t.category === c).map((t) => t.id.split("-")[0]));
    const extra = traces.find((t) => t.category === c && !gens.has(t.id.split("-")[0]) && !picked.includes(t));
    if (extra) picked.push(extra);
  }
  return picked.slice(0, 10).map((t) => t.id);
}

/** EXPECTED_ALERTS_JSON = path to (or inline JSON of) eval.dump_expectations output. When unset, generate it with
 *  `python -m eval.dump_expectations --detector $REPLAY_DETECTOR` (default D1) for exactly these ids. */
export function loadExpected(ids: string[]): Record<string, Expected> {
  const env = process.env.EXPECTED_ALERTS_JSON;
  let raw: string;
  if (env && env.trim().startsWith("{")) raw = env;
  else if (env) raw = readFileSync(env, "utf8");
  else {
    const dir = path.join(process.cwd(), "e2e", ".results");
    mkdirSync(dir, { recursive: true });
    const out = path.join(dir, "expected-alerts.json");
    execFileSync(
      "python",
      ["-m", "eval.dump_expectations", "--detector", process.env.REPLAY_DETECTOR ?? "D1", "--traces",
        process.env.FAKE_LLM_TRACES || "eval/final/traces.json", "--ids", ids.join(","), "--out", out],
      { cwd: REPO_ROOT, env: { ...process.env, HF_HUB_OFFLINE: "1" } },
    );
    raw = readFileSync(out, "utf8");
  }
  return JSON.parse(raw);
}

export interface Frame {
  seq: number; // position in the single combined sequence of frames (sent + received)
  t: number; // ms since the first frame of this session
  dir: "in" | "out";
  data: Record<string, unknown>;
}

/** Record every WebSocket frame with a combined sequence index and a timestamp. */
export function recordFrames(page: Page) {
  const frames: Frame[] = [];
  let t0 = 0;
  const push = (dir: "in" | "out", payload: string | Buffer) => {
    const now = Date.now();
    if (!frames.length) t0 = now;
    frames.push({ seq: frames.length, t: now - t0, dir, data: JSON.parse(String(payload)) });
  };
  page.on("websocket", (ws) => {
    ws.on("framereceived", (f) => push("in", f.payload));
    ws.on("framesent", (f) => push("out", f.payload));
  });
  return frames;
}

export const evs = (frames: Frame[], name: string, dir?: "in" | "out") =>
  frames.filter((f) => f.data.event === name && (dir === undefined || f.dir === dir));

