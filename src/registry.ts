/**
 * Read the official MCP Registry (registry.modelcontextprotocol.io) and turn its
 * entries into scannable server specs. Remote (streamable-HTTP / SSE) servers are
 * scanned live; npm stdio servers can be scanned via `npx` when opted in. pypi /
 * oci packages are skipped (not runnable through this CLI).
 */

import type { ServerSpec } from "./types";

const DEFAULT_REGISTRY = "https://registry.modelcontextprotocol.io";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

export interface RegistryParse {
  servers: Record<string, unknown>[];
  nextCursor: string | null;
}

/** Parse one page of the `/v0/servers` response into server objects + cursor. */
export function parseRegistry(doc: unknown): RegistryParse {
  if (!isObject(doc)) return { servers: [], nextCursor: null };
  const servers = asArray(doc.servers)
    .map((e) => (isObject(e) && isObject(e.server) ? e.server : null))
    .filter((s): s is Record<string, unknown> => s !== null);
  const meta = isObject(doc.metadata) ? doc.metadata : {};
  const nextCursor = asString(meta.nextCursor) ?? null;
  return { servers, nextCursor };
}

/** True for a remote transport mcpaudit can speak (streamable-HTTP or SSE). */
function remoteUrl(server: Record<string, unknown>): string | undefined {
  for (const r of asArray(server.remotes)) {
    if (!isObject(r)) continue;
    const type = asString(r.type);
    const url = asString(r.url);
    if (url && (type === "streamable-http" || type === "sse" || type === "http")) return url;
  }
  return undefined;
}

/** An npm package that runs over stdio, as `npx -y <identifier>[@<version>]`. */
function npmStdioCommand(server: Record<string, unknown>): string[] | undefined {
  for (const p of asArray(server.packages)) {
    if (!isObject(p)) continue;
    const registry = asString(p.registryType) ?? asString(p.registry_type);
    if (registry !== "npm") continue;
    const id = asString(p.identifier);
    if (!id) continue;
    const transport = isObject(p.transport) ? asString(p.transport.type) : undefined;
    // Treat a missing transport as stdio (the npm default for MCP servers).
    if (transport && transport !== "stdio") continue;
    const version = asString(p.version);
    return ["npx", "-y", version ? `${id}@${version}` : id];
  }
  return undefined;
}

/** Derive a scannable spec from a registry server, or null if not runnable here. */
export function specFromRegistryServer(
  server: Record<string, unknown>,
  opts: { includeNpm?: boolean } = {},
): ServerSpec | null {
  const label = asString(server.name) ?? asString(server.title) ?? "unknown";
  const url = remoteUrl(server);
  if (url) return { kind: "url", label, url };
  if (opts.includeNpm) {
    const command = npmStdioCommand(server);
    if (command) return { kind: "stdio", label, command };
  }
  return null;
}

/**
 * Build specs from a provided document: either a registry `/v0/servers` response
 * or a plain array of `{ kind, label, url | command }` specs. Used by `--input`
 * (custom lists, offline runs, tests).
 */
export function specsFromInput(doc: unknown, opts: { includeNpm?: boolean } = {}): ServerSpec[] {
  if (isObject(doc) && Array.isArray(doc.servers)) {
    return parseRegistry(doc)
      .servers.map((s) => specFromRegistryServer(s, { includeNpm: opts.includeNpm ?? true }))
      .filter((s): s is ServerSpec => s !== null);
  }
  if (Array.isArray(doc)) {
    const out: ServerSpec[] = [];
    for (const raw of doc) {
      if (!isObject(raw)) continue;
      const label = asString(raw.label) ?? asString(raw.name) ?? "unknown";
      const url = asString(raw.url);
      const command = asArray(raw.command).filter((x): x is string => typeof x === "string");
      if (raw.kind === "url" && url) out.push({ kind: "url", label, url });
      else if (raw.kind === "stdio" && command.length) out.push({ kind: "stdio", label, command });
      else if (url) out.push({ kind: "url", label, url });
      else if (command.length) out.push({ kind: "stdio", label, command });
    }
    return out;
  }
  throw new Error("input must be a registry response or an array of server specs");
}

export interface FetchOptions {
  baseUrl?: string;
  limit?: number;
  includeNpm?: boolean;
  timeoutMs?: number;
}

export interface FetchResult {
  specs: ServerSpec[];
  /** Distinct server names seen across the pages we read. */
  seen: number;
  /** Servers we saw but could not turn into a scannable spec. */
  skipped: number;
}

/** Page through the registry, dedupe by name, and return up to `limit` specs. */
export async function fetchRegistrySpecs(opts: FetchOptions = {}): Promise<FetchResult> {
  const base = (opts.baseUrl ?? DEFAULT_REGISTRY).replace(/\/$/, "");
  const limit = opts.limit ?? 50;
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const specs: ServerSpec[] = [];
  const namesSeen = new Set<string>();
  let skipped = 0;
  let cursor: string | null = null;

  // Cap pages so a huge registry can't loop forever.
  for (let page = 0; page < 100 && specs.length < limit; page++) {
    const u = new URL(`${base}/v0/servers`);
    u.searchParams.set("limit", "100");
    if (cursor) u.searchParams.set("cursor", cursor);
    const resp = await fetch(u, { signal: AbortSignal.timeout(timeoutMs) });
    if (!resp.ok) throw new Error(`registry HTTP ${resp.status} at ${u}`);
    const { servers, nextCursor } = parseRegistry(await resp.json());

    for (const server of servers) {
      const name = asString(server.name);
      if (!name || namesSeen.has(name)) continue;
      namesSeen.add(name);
      const spec = specFromRegistryServer(server, { includeNpm: opts.includeNpm });
      if (spec) {
        specs.push(spec);
        if (specs.length >= limit) break;
      } else {
        skipped++;
      }
    }

    if (!nextCursor) break;
    cursor = nextCursor;
  }

  return { specs, seen: namesSeen.size, skipped };
}
