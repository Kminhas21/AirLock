import { describe, expect, it } from "vitest";
import { formatAge, pendingAge } from "./inboxAge";

describe("pendingAge", () => {
  it("adds local elapsed time to the reported age", () => {
    expect(pendingAge(10, 1000, 6500)).toBe(15);
    expect(pendingAge(0, 1000, 1000)).toBe(0);
  });
  it("null when the hub sent no age; a clock that went backwards does not shrink it", () => {
    for (const bad of [null, undefined, NaN, Infinity] as const) expect(pendingAge(bad as never, 0, 5000)).toBeNull();
    expect(pendingAge(20, 5000, 1000)).toBe(20);
  });
});

describe("formatAge", () => {
  it("formats seconds, minutes and hours", () => {
    expect(formatAge(0)).toBe("0s");
    expect(formatAge(59)).toBe("59s");
    expect(formatAge(65)).toBe("1m 05s");
    expect(formatAge(3600 + 120)).toBe("1h 02m");
    expect(formatAge(-5)).toBe("0s");
  });
});
