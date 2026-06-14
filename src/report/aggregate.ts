/**
 * Aggregate many scan results into the "State of MCP Security" report. The
 * default rendering is anonymized (counts and rates, no server names) so it is
 * safe to publish before maintainers are contacted; `--name-servers` adds the
 * named leaderboard for your own use after responsible disclosure.
 */

import type { RiskSignal, Severity } from "@axiorank/detectors";
import { severityCounts, worstSeverity } from "../gate";
import type { ScanResult } from "../types";
import { VERSION } from "../version";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export interface DetectorStat {
  detector: string;
  label: string;
  servers: number;
  occurrences: number;
}

export interface LeaderboardEntry {
  label: string;
  kind: string;
  risk: number;
  decision: ScanResult["decision"];
  worst: Severity | null;
  topFinding: string | null;
}

export interface AggregateReport {
  scannedAt: string;
  total: number;
  scanned: number;
  unscannable: number;
  clean: number;
  withFindings: number;
  decisions: { allow: number; hold: number; deny: number };
  findingsBySeverity: Record<Severity, number>;
  serversBySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  topDetectors: DetectorStat[];
  leaderboard: LeaderboardEntry[];
}

export function aggregate(results: ScanResult[], scannedAt: string): AggregateReport {
  const scannedResults = results.filter((r) => !r.error);
  const unscannable = results.length - scannedResults.length;

  const findingsBySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const serversBySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const byCategory: Record<string, number> = {};
  const decisions = { allow: 0, hold: 0, deny: 0 };

  const detectorServers = new Map<string, { label: string; servers: Set<string>; count: number }>();

  for (const r of scannedResults) {
    decisions[r.decision]++;
    const counts = severityCounts(r.signals);
    for (const s of SEVERITIES) {
      findingsBySeverity[s] += counts[s];
      if (counts[s] > 0) serversBySeverity[s]++;
    }
    for (const sig of r.signals) {
      byCategory[sig.category] = (byCategory[sig.category] ?? 0) + 1;
      const d = detectorServers.get(sig.detector) ?? {
        label: sig.label,
        servers: new Set<string>(),
        count: 0,
      };
      d.servers.add(r.server.label);
      d.count++;
      detectorServers.set(sig.detector, d);
    }
  }

  const topDetectors: DetectorStat[] = [...detectorServers.entries()]
    .map(([detector, d]) => ({
      detector,
      label: d.label,
      servers: d.servers.size,
      occurrences: d.count,
    }))
    .sort((a, b) => b.servers - a.servers || b.occurrences - a.occurrences)
    .slice(0, 12);

  const leaderboard: LeaderboardEntry[] = scannedResults
    .filter((r) => r.signals.length > 0)
    .sort((a, b) => b.risk - a.risk)
    .map((r) => ({
      label: r.server.label,
      kind: r.server.kind,
      risk: r.risk,
      decision: r.decision,
      worst: worstSeverity(r.signals),
      topFinding: topFinding(r.signals),
    }));

  const withFindings = scannedResults.filter((r) => r.signals.length > 0).length;

  return {
    scannedAt,
    total: results.length,
    scanned: scannedResults.length,
    unscannable,
    clean: scannedResults.length - withFindings,
    withFindings,
    decisions,
    findingsBySeverity,
    serversBySeverity,
    byCategory,
    topDetectors,
    leaderboard,
  };
}

/** The label of the highest-severity finding for a server. */
function topFinding(signals: RiskSignal[]): string | null {
  return signals[0]?.label ?? null;
}

function pct(n: number, total: number): string {
  if (total === 0) return "0%";
  return `${Math.round((n / total) * 100)}%`;
}

export function renderReportMarkdown(
  rep: AggregateReport,
  opts: { nameServers?: boolean } = {},
): string {
  const date = rep.scannedAt.slice(0, 10);
  const L: string[] = [];
  L.push(`# The State of MCP Security`);
  L.push("");
  L.push(
    `_Generated ${date} by [mcpaudit](https://github.com/AxioRank/mcpaudit) v${VERSION}. ` +
      `Reproduce with \`npx @axiorank/mcpaudit registry-scan\`._`,
  );
  L.push("");

  L.push(`## Summary`);
  L.push("");
  L.push(`- **${rep.scanned}** MCP servers scanned from the public registry.`);
  L.push(
    `- **${rep.withFindings}** (${pct(rep.withFindings, rep.scanned)}) had at least one security finding.`,
  );
  L.push(
    `- **${rep.decisions.deny}** would be blocked and **${rep.decisions.hold}** held for review by the default posture.`,
  );
  L.push(`- **${rep.clean}** were clean.`);
  if (rep.unscannable > 0) {
    L.push(`- ${rep.unscannable} could not be reached (offline, auth required, or no usable transport).`);
  }
  L.push("");

  L.push(`## Findings by severity`);
  L.push("");
  L.push(`| Severity | Findings | Servers affected |`);
  L.push(`| --- | ---: | ---: |`);
  for (const s of SEVERITIES) {
    L.push(`| ${s} | ${rep.findingsBySeverity[s]} | ${rep.serversBySeverity[s]} |`);
  }
  L.push("");

  if (rep.topDetectors.length > 0) {
    L.push(`## Most common issues`);
    L.push("");
    L.push(`| Issue | Detector | Servers |`);
    L.push(`| --- | --- | ---: |`);
    for (const d of rep.topDetectors) {
      L.push(`| ${d.label} | \`${d.detector}\` | ${d.servers} |`);
    }
    L.push("");
  }

  const categories = Object.entries(rep.byCategory).sort((a, b) => b[1] - a[1]);
  if (categories.length > 0) {
    L.push(`## Findings by category`);
    L.push("");
    L.push(`| Category | Findings |`);
    L.push(`| --- | ---: |`);
    for (const [cat, n] of categories) L.push(`| ${cat} | ${n} |`);
    L.push("");
  }

  if (opts.nameServers && rep.leaderboard.length > 0) {
    L.push(`## Highest-risk servers`);
    L.push("");
    L.push(`| Server | Risk | Verdict | Top finding |`);
    L.push(`| --- | ---: | --- | --- |`);
    for (const e of rep.leaderboard.slice(0, 25)) {
      L.push(`| ${e.label} | ${e.risk}/100 | ${e.decision.toUpperCase()} | ${e.topFinding ?? ""} |`);
    }
    L.push("");
  } else {
    L.push(`## Highest-risk servers`);
    L.push("");
    L.push(
      `Server names are withheld. Affected maintainers are contacted before any named ` +
        `findings are published. Run with \`--name-servers\` to produce the named leaderboard ` +
        `for private triage.`,
    );
    L.push("");
  }

  L.push(`## Methodology`);
  L.push("");
  L.push(
    `mcpaudit connects to each server, runs the MCP handshake, and inspects the tools, ` +
      `resources, and prompts it exposes. Enumeration is **read-only**: no tool is ever called. ` +
      `Risk is scored by the open-source \`@axiorank/detectors\` engine plus MCP-specific ` +
      `heuristics (tool shadowing, credential-soliciting schemas, dangerous capabilities). ` +
      `A finding is a heuristic signal, not proof of a vulnerability.`,
  );
  L.push("");
  return L.join("\n");
}

export function renderReportJson(rep: AggregateReport): string {
  return JSON.stringify(rep, null, 2);
}
