/** Severity ranking and the CI fail-gate. */

import type { RiskSignal, Severity } from "@axiorank/detectors";
import type { ScanResult } from "./types";

export const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type FailOn = "none" | Severity;

/** The highest severity present across the signals, or null when there are none. */
export function worstSeverity(signals: RiskSignal[]): Severity | null {
  let worst: Severity | null = null;
  for (const s of signals) {
    if (!worst || SEVERITY_RANK[s.severity] > SEVERITY_RANK[worst]) worst = s.severity;
  }
  return worst;
}

/** Count signals by severity. */
export function severityCounts(signals: RiskSignal[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const s of signals) counts[s.severity]++;
  return counts;
}

/**
 * Should the run fail the build? True when any result carries a signal at or
 * above the `failOn` threshold. `failOn: "none"` never fails.
 */
export function shouldFail(results: ScanResult[], failOn: FailOn): boolean {
  if (failOn === "none") return false;
  const threshold = SEVERITY_RANK[failOn];
  return results.some((r) =>
    r.signals.some((s) => SEVERITY_RANK[s.severity] >= threshold),
  );
}
