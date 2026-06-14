/**
 * `--share` posts a scan to AxioRank's public scorecard endpoint and returns a
 * shareable link. The endpoint RECOMPUTES the verdict server-side from the
 * payload (it never trusts a client-sent score), so the public scorecard is its
 * own source of truth. Best effort: a network failure never fails the scan.
 */

import type { ScanResult } from "./types";

export interface ShareResult {
  url: string;
  id: string;
  decision: string;
  risk: number;
}

const MAX_ARGS_BYTES = 18_000; // endpoint caps args at 20KB; stay under it.

/** A size-bounded copy of the surface to post (tool names + descriptions). */
function compactPayload(result: ScanResult): Record<string, unknown> {
  const s = result.surface;
  if (!s) return {};
  const tools = s.tools.map((t) => ({
    name: t.name.slice(0, 120),
    description: (t.description ?? "").slice(0, 600),
  }));
  let payload: Record<string, unknown> = {
    server: result.server.label.slice(0, 120),
    via: s.via,
    tools,
  };
  // Trim tools until the JSON fits the endpoint's cap.
  while (JSON.stringify(payload).length > MAX_ARGS_BYTES && tools.length > 1) {
    tools.length = Math.floor(tools.length / 2);
    payload = { ...payload, tools, truncated: true };
  }
  return payload;
}

export async function shareScan(
  result: ScanResult,
  baseUrl: string,
  timeoutMs = 15_000,
): Promise<ShareResult> {
  if (!result.surface) throw new Error("nothing to share for a server that could not be scanned");
  const body = {
    tool: `mcp.${result.server.label}`.slice(0, 200),
    args: compactPayload(result),
    source: "cli",
  };
  const resp = await fetch(`${baseUrl.replace(/\/$/, "")}/api/scorecard`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} from the scorecard endpoint`);
  const data = (await resp.json()) as Partial<ShareResult>;
  if (!data.url || !data.id) throw new Error("scorecard endpoint returned an unexpected response");
  return { url: data.url, id: data.id, decision: String(data.decision), risk: Number(data.risk) };
}
