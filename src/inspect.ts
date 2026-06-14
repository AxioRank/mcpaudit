/**
 * Score an enumerated MCP surface through the AxioRank engine.
 *
 * Two sources of signal, the same split the hosted /verify card scorer uses:
 *   1. Content: every tool / resource / prompt is flattened into a synthetic
 *      payload and run through CARD_DETECTORS, so a leaked key, an injected
 *      "ignore previous instructions" in a description (tool poisoning), PII, or
 *      destructive language all surface.
 *   2. Structure: shadowing, credential-soliciting schemas, and
 *      dangerous-by-name capabilities (see heuristics.ts).
 *
 * Base risk is 0: a surface is a description, not an action. Only what it
 * declares carries risk.
 */

import {
  CARD_DETECTORS,
  combine,
  inspectContent,
  localDecision,
  type RiskSignal,
} from "@axiorank/detectors";
import { structuralSignals } from "./heuristics";
import type { McpSurface, ScanResult, ServerSpec } from "./types";

const CATEGORY_RANK: Record<string, number> = {
  secret: 0,
  supply_chain: 1,
  destructive: 2,
  injection: 3,
  pii: 4,
  egress: 5,
  bot_spoof: 6,
  rate_abuse: 7,
};

/** Dedupe by (detector, location) and sort high-impact first. */
function finalize(signals: RiskSignal[]): RiskSignal[] {
  const seen = new Set<string>();
  const out: RiskSignal[] = [];
  for (const s of signals) {
    const key = `${s.detector}|${s.location}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  out.sort(
    (a, b) =>
      b.points - a.points ||
      (CATEGORY_RANK[a.category] ?? 9) - (CATEGORY_RANK[b.category] ?? 9) ||
      a.location.localeCompare(b.location),
  );
  return out;
}

/** Build the synthetic payload the content engine inspects. */
function surfacePayload(surface: McpSurface): Record<string, unknown> {
  return {
    tools: surface.tools.map((t) => ({
      name: t.name,
      description: t.description ?? "",
      schema: t.inputSchema ? JSON.stringify(t.inputSchema) : "",
    })),
    resources: surface.resources.map((r) => ({
      name: r.name ?? "",
      uri: r.uri ?? "",
      description: r.description ?? "",
    })),
    prompts: surface.prompts.map((p) => ({ name: p.name, description: p.description ?? "" })),
  };
}

/** Score a successfully-enumerated surface. */
export function scoreSurface(server: ServerSpec, surface: McpSurface): ScanResult {
  const { signals: content } = inspectContent(
    `mcp.${server.label}`,
    surfacePayload(surface),
    CARD_DETECTORS,
  );
  const signals = finalize([...structuralSignals(surface), ...content]);
  const risk = combine(0, signals);
  const verdict = localDecision(risk, signals);
  return {
    server,
    surface,
    signals,
    risk,
    decision: verdict.decision,
    decisionReason: verdict.reason,
  };
}

/** A result for a server that could not be reached or enumerated. */
export function errorResult(server: ServerSpec, error: string): ScanResult {
  return {
    server,
    signals: [],
    risk: 0,
    decision: "allow",
    decisionReason: "Server could not be scanned.",
    error,
  };
}
