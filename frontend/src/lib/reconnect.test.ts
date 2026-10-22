import { describe, expect, it } from "vitest";
import { planReconnect } from "./reconnect";
import { createBackoff } from "./backoff";

describe("planReconnect", () => {
  it("reconnects immediately and shows 'reconnecting' (not 'disconnected') after the server ended the session", () => {
    const backoff = createBackoff({ rng: () => 0 });
    expect(planReconnect({ sessionEnded: true, backoff })).toEqual({ delayMs: 0, status: "reconnecting" });
  });

  it("uses backoff and shows 'disconnected' after an unexpected drop", () => {
    const backoff = createBackoff({ baseMs: 500, jitter: 0, rng: () => 0 });
    expect(planReconnect({ sessionEnded: false, backoff })).toEqual({ delayMs: 500, status: "disconnected" });
    expect(planReconnect({ sessionEnded: false, backoff }).delayMs).toBe(1000);
  });

  it("an expected reconnect does not consume backoff attempts", () => {
    const backoff = createBackoff({ baseMs: 500, jitter: 0, rng: () => 0 });
    planReconnect({ sessionEnded: true, backoff });
    expect(planReconnect({ sessionEnded: false, backoff }).delayMs).toBe(500);
  });
});
