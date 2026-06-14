/**
 * Static fallback for HTTP servers: fetch the well-known MCP server card
 * (SEP-2127, `/.well-known/mcp.json`) and turn it into a surface we can score.
 * Used when a live streamable-HTTP handshake is not available. Mirrors the parse
 * in apps/web/lib/protocols/adapters/mcp.ts.
 */

import type { McpSurface, McpTool } from "./types";

const MAX_BYTES = 512 * 1024;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

/** Resolve the `/.well-known/mcp.json` URL for a given server URL. */
export function wellKnownUrl(serverUrl: string): string {
  const u = new URL(serverUrl);
  return `${u.protocol}//${u.host}/.well-known/mcp.json`;
}

export async function fetchWellKnownCard(
  serverUrl: string,
  headers: Record<string, string> = {},
  timeoutMs = 15_000,
): Promise<McpSurface> {
  const target = wellKnownUrl(serverUrl);
  const resp = await fetch(target, {
    headers: { accept: "application/json", ...headers },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} fetching ${target}`);
  const text = (await resp.text()).slice(0, MAX_BYTES);
  const doc: unknown = JSON.parse(text);
  if (!isObject(doc)) throw new Error("well-known card is not a JSON object");

  const toolsRaw = Array.isArray(doc.tools) ? doc.tools : [];
  if (toolsRaw.length === 0) throw new Error("well-known card declares no tools");

  const tools: McpTool[] = toolsRaw.map((t) => {
    const r = isObject(t) ? t : {};
    return { name: asString(r.name) ?? "unnamed", description: asString(r.description) };
  });

  const serverInfo = {
    name: asString(doc.name) ?? asString(doc.resource_name),
    version: asString(doc.version),
  };

  return {
    serverInfo,
    via: "well-known-card",
    tools,
    resources: [],
    prompts: [],
    notes: ["enumerated from the static well-known card; a live handshake would reveal more"],
  };
}
