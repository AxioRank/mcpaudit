import type { RiskSignal } from "@axiorank/detectors";
import { describe, expect, it } from "vitest";
import { shouldFail, worstSeverity } from "../src/gate";
import { buildJson } from "../src/report/json";
import { buildSarif } from "../src/report/sarif";
import type { ScanResult } from "../src/types";

function signal(severity: RiskSignal["severity"], detector: string): RiskSignal {
  return {
    detector,
    category: "supply_chain",
    severity,
    label: "x",
    points: 10,
    location: "tools.0",
    evidence: "e",
  };
}

const result: ScanResult = {
  server: { kind: "stdio", label: "srv", command: ["x"] },
  surface: { via: "stdio", tools: [], resources: [], prompts: [], notes: [] },
  signals: [signal("critical", "secret.aws_access_key"), signal("medium", "supply_chain.x")],
  risk: 90,
  decision: "deny",
  decisionReason: "secret",
};

describe("gate", () => {
  it("computes the worst severity", () => {
    expect(worstSeverity(result.signals)).toBe("critical");
    expect(worstSeverity([])).toBeNull();
  });

  it("fails on a threshold that is met", () => {
    expect(shouldFail([result], "high")).toBe(true);
    expect(shouldFail([result], "critical")).toBe(true);
    expect(shouldFail([result], "none")).toBe(false);
  });

  it("does not fail when no signal meets the threshold", () => {
    const low: ScanResult = { ...result, signals: [signal("low", "supply_chain.y")] };
    expect(shouldFail([low], "high")).toBe(false);
  });
});

describe("buildSarif", () => {
  it("produces a valid 2.1.0 log with rules and results", () => {
    const sarif = buildSarif([result]) as any;
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("mcpaudit");
    expect(run.tool.driver.rules.length).toBe(2);
    expect(run.results.length).toBe(2);
    const critical = run.results.find((r: any) => r.ruleId === "secret.aws_access_key");
    expect(critical.level).toBe("error");
    expect(critical.locations[0].physicalLocation.artifactLocation.uri).toContain("mcpaudit/");
  });
});

describe("buildJson", () => {
  it("serializes the result", () => {
    const json = buildJson([result], "2026-06-14T00:00:00.000Z") as any;
    expect(json.tool).toBe("mcpaudit");
    expect(json.servers[0].decision).toBe("deny");
    expect(json.servers[0].signals.length).toBe(2);
  });
});
