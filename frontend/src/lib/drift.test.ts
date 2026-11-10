import { describe, expect, it } from "vitest";
import { DRIFT_THRESHOLD, latestThreshold, pointThreshold } from "./drift";

describe("drift threshold fallback", () => {
  it("uses a finite positive threshold", () => expect(pointThreshold(2.5)).toBe(2.5));
  it("falls back to the constant for missing or invalid values", () => {
    for (const bad of [undefined, null, 0, -1, NaN, Infinity, -Infinity, "3", {}, []]) expect(pointThreshold(bad), String(bad)).toBe(DRIFT_THRESHOLD);
  });
  it("latestThreshold uses the last point only", () => {
    expect(latestThreshold([{ threshold: 1 }, { threshold: 4 }])).toBe(4);
    expect(latestThreshold([{ threshold: 4 }, {}])).toBe(DRIFT_THRESHOLD);
    expect(latestThreshold([])).toBe(DRIFT_THRESHOLD);
  });
});
