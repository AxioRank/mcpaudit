import { describe, expect, it } from "vitest";
import { runProbe } from "../src/probe";

describe("runProbe", () => {
  it("runs the free-tier corpus through the default posture", () => {
    const report = runProbe(false);
    expect(report.outcomes.length).toBeGreaterThan(0);
    expect(report.attacks).toBeGreaterThan(0);
    expect(report.catchRate).toBeGreaterThan(0);
    expect(report.catchRate).toBeLessThanOrEqual(1);
    // Benign controls must not be blocked by the default posture.
    expect(report.falsePositives).toBe(0);
  });

  it("runs the full corpus when asked", () => {
    const free = runProbe(false);
    const full = runProbe(true);
    expect(full.outcomes.length).toBeGreaterThanOrEqual(free.outcomes.length);
  });
});
