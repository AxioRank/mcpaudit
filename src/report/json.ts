/** Machine-readable JSON report. */

import type { ScanResult } from "../types";
import { VERSION } from "../version";

export function buildJson(results: ScanResult[], scannedAt: string): Record<string, unknown> {
  return {
    tool: "mcpaudit",
    version: VERSION,
    scannedAt,
    servers: results.map((r) => ({
      label: r.server.label,
      kind: r.server.kind,
      risk: r.risk,
      decision: r.decision,
      decisionReason: r.decisionReason,
      ...(r.error ? { error: r.error } : {}),
      surface: r.surface
        ? {
            serverInfo: r.surface.serverInfo,
            via: r.surface.via,
            counts: {
              tools: r.surface.tools.length,
              resources: r.surface.resources.length,
              prompts: r.surface.prompts.length,
            },
            notes: r.surface.notes,
          }
        : null,
      signals: r.signals,
    })),
  };
}

export function renderJson(results: ScanResult[], scannedAt: string): string {
  return JSON.stringify(buildJson(results, scannedAt), null, 2);
}
