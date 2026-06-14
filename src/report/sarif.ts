/**
 * SARIF 2.1.0 output, so `mcpaudit scan --format sarif` can be uploaded to
 * GitHub code scanning (the github/codeql-action/upload-sarif action) and surface
 * findings as PR annotations and Security-tab alerts.
 */

import type { RiskSignal, Severity } from "@axiorank/detectors";
import type { ScanResult, ServerSpec } from "../types";
import { VERSION } from "../version";

type SarifLevel = "error" | "warning" | "note";

function levelFor(severity: Severity): SarifLevel {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

/** A stable, relative artifact path so GitHub can group findings per server. */
function artifactUri(server: ServerSpec): string {
  if (server.kind === "url") return server.url;
  const safe = server.label.replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 80) || "server";
  return `mcpaudit/${safe}.json`;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  properties: { tags: string[] };
}

export function buildSarif(results: ScanResult[]): Record<string, unknown> {
  const rules = new Map<string, SarifRule>();
  const sarifResults: Record<string, unknown>[] = [];

  for (const r of results) {
    for (const sig of r.signals) {
      if (!rules.has(sig.detector)) {
        rules.set(sig.detector, {
          id: sig.detector,
          name: sig.detector.replace(/[^a-zA-Z0-9]+/g, "_"),
          shortDescription: { text: sig.label },
          defaultConfiguration: { level: levelFor(sig.severity) },
          properties: { tags: ["security", "mcp", sig.category] },
        });
      }
      sarifResults.push(resultFor(r.server, sig, r.risk));
    }
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcpaudit",
            informationUri: "https://github.com/AxioRank/mcpaudit",
            version: VERSION,
            rules: [...rules.values()],
          },
        },
        results: sarifResults,
      },
    ],
  };
}

function resultFor(
  server: ServerSpec,
  sig: RiskSignal,
  risk: number,
): Record<string, unknown> {
  return {
    ruleId: sig.detector,
    level: levelFor(sig.severity),
    message: { text: `${sig.label}: ${sig.evidence}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: artifactUri(server) },
          region: { startLine: 1 },
        },
        logicalLocations: [{ name: sig.location, kind: "member" }],
      },
    ],
    partialFingerprints: {
      mcpaudit: `${server.label}|${sig.detector}|${sig.location}`,
    },
    properties: {
      severity: sig.severity,
      category: sig.category,
      serverRisk: risk,
      server: server.label,
    },
  };
}

export function renderSarif(results: ScanResult[]): string {
  return JSON.stringify(buildSarif(results), null, 2);
}
