import { describe, expect, it } from "vitest";
import { createBackoff } from "./backoff";

describe("createBackoff", () => {
  it("grows exponentially without jitter (rng=0 => full delay)", () => {
    const b = createBackoff({ baseMs: 500, maxMs: 10000, jitter: 0, rng: () => 0 });
    expect([b.next(), b.next(), b.next(), b.next()]).toEqual([500, 1000, 2000, 4000]);
  });
  it("caps at maxMs", () => {
    const b = createBackoff({ baseMs: 500, maxMs: 3000, jitter: 0, rng: () => 0 });
    const delays = Array.from({ length: 8 }, () => b.next());
    expect(delays.slice(-3)).toEqual([3000, 3000, 3000]);
  });
  it("applies jitter deterministically via injected rng", () => {
    // delay = raw * (1 - jitter * rng())
    const lo = createBackoff({ baseMs: 1000, maxMs: 10000, jitter: 0.5, rng: () => 0 });
    const hi = createBackoff({ baseMs: 1000, maxMs: 10000, jitter: 0.5, rng: () => 1 });
    expect(lo.next()).toBe(1000);
    expect(hi.next()).toBe(500);
  });
  it("reset returns to the base delay", () => {
    const b = createBackoff({ baseMs: 500, maxMs: 10000, jitter: 0, rng: () => 0 });
    b.next();
    b.next();
    b.reset();
    expect(b.next()).toBe(500);
  });
});
