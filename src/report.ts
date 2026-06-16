/**
 * `--report <url>` posts the scan's JSON report to an AxioRank discovery ingest
 * endpoint (e.g. /api/discovery/mcp-scan) with a per-workspace ingest token, so a
 * developer or a cron can push the MCP servers wired into their AI client
 * straight into Shadow AI discovery - no curl pipe. The endpoint recomputes
 * everything from the report; it never trusts a client-sent verdict.
 */

import { buildJson } from "./report/json";
import type { ScanResult } from "./types";

export interface ReportResult {
  recorded: number;
  servers: number;
}

export async function postReport(
  url: string,
  token: string,
  results: ScanResult[],
  scannedAt: string,
  timeoutMs = 15_000,
): Promise<ReportResult> {
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(buildJson(results, scannedAt)),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} from ${url}`);
  const data = (await resp.json().catch(() => ({}))) as Partial<ReportResult>;
  return {
    recorded: Number(data.recorded ?? 0),
    servers: Number(data.servers ?? 0),
  };
}
