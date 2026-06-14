import type { RiskSignal } from "@axiorank/detectors";
import { describe, expect, it } from "vitest";
import { aggregate, renderReportMarkdown } from "../src/report/aggregate";
import type { ScanResult } from "../src/types";

function sig(severity: RiskSignal["severity"], detector: string, category: RiskSignal["category"]): RiskSignal {
  return { detector, category, severity, label: detector, points: 10, location: "tools[0]", evidence: "e" };
}

const results: ScanResult[] = [
  {
    server: { kind: "url", label: "risky-server", url: "https://a/mcp" },
    surface: { via: "streamable-http", tools: [], resources: [], prompts: [], notes: [] },
    signals: [sig("critical", "secret.aws_access_key", "secret"), sig("high", "injection.prompt", "injection")],
    risk: 95,
    decision: "deny",
    decisionReason: "secret",
  },
  {
    server: { kind: "url", label: "clean-server", url: "https://b/mcp" },
    surface: { via: "streamable-http", tools: [], resources: [], prompts: [], notes: [] },
    signals: [],
    risk: 0,
    decision: "allow",
    decisionReason: "ok",
  },
  {
    server: { kind: "stdio", label: "dead-server", command: ["x"] },
    signals: [],
    risk: 0,
    decision: "allow",
    decisionReason: "unreachable",
    error: "server process exited",
  },
];

describe("aggregate", () => {
  const rep = aggregate(results, "2026-06-14T00:00:00.000Z");

  it("counts scanned, clean, unscannable, and findings", () => {
    expect(rep.total).toBe(3);
    expect(rep.scanned).toBe(2);
    expect(rep.unscannable).toBe(1);
    expect(rep.clean).toBe(1);
    expect(rep.withFindings).toBe(1);
    expect(rep.decisions.deny).toBe(1);
    expect(rep.findingsBySeverity.critical).toBe(1);
    expect(rep.byCategory.secret).toBe(1);
  });

  it("ranks the leaderboard by risk", () => {
    expect(rep.leaderboard[0]!.label).toBe("risky-server");
    expect(rep.leaderboard[0]!.worst).toBe("critical");
  });

  it("withholds names by default and reveals them with nameServers", () => {
    expect(renderReportMarkdown(rep)).not.toContain("risky-server");
    expect(renderReportMarkdown(rep)).toContain("Server names are withheld");
    const named = renderReportMarkdown(rep, { nameServers: true });
    expect(named).toContain("risky-server");
    expect(named).toContain("Highest-risk servers");
  });

  it("includes summary stats and methodology", () => {
    const md = renderReportMarkdown(rep);
    expect(md).toContain("The State of MCP Security");
    expect(md).toContain("**2** MCP servers scanned");
    expect(md).toContain("read-only");
  });
});
