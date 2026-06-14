/** Orchestrate a scan: pick a transport, enumerate, score. */

import { fetchWellKnownCard } from "./card";
import { enumerateServer, HttpTransport, StdioTransport } from "./mcp-client";
import { errorResult, scoreSurface } from "./inspect";
import type { ScanResult, ServerSpec } from "./types";

export interface ScanOptions {
  timeoutMs?: number;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Scan a single server end to end, never throwing (errors land in the result). */
export async function scanServer(spec: ServerSpec, opts: ScanOptions = {}): Promise<ScanResult> {
  const timeoutMs = opts.timeoutMs ?? 15_000;

  if (spec.kind === "stdio") {
    let transport: StdioTransport;
    try {
      transport = new StdioTransport(spec.command, spec.env, timeoutMs);
    } catch (err) {
      return errorResult(spec, message(err));
    }
    try {
      const surface = await enumerateServer(transport, "stdio");
      return scoreSurface(spec, surface);
    } catch (err) {
      return errorResult(spec, message(err));
    } finally {
      await transport.close();
    }
  }

  // url: try a live streamable-HTTP handshake, fall back to the static card.
  let liveErr: string | null = null;
  const transport = new HttpTransport(spec.url, spec.headers, timeoutMs);
  try {
    const surface = await enumerateServer(transport, "streamable-http");
    return scoreSurface(spec, surface);
  } catch (err) {
    liveErr = message(err);
  } finally {
    await transport.close();
  }

  try {
    const surface = await fetchWellKnownCard(spec.url, spec.headers, timeoutMs);
    return scoreSurface(spec, surface);
  } catch (cardErr) {
    return errorResult(
      spec,
      `live handshake failed (${liveErr}); no usable well-known card (${message(cardErr)})`,
    );
  }
}

/** Scan many servers, bounded concurrency, preserving order. */
export async function scanServers(
  specs: ServerSpec[],
  opts: ScanOptions & { concurrency?: number } = {},
): Promise<ScanResult[]> {
  const concurrency = Math.max(1, opts.concurrency ?? 4);
  const results: ScanResult[] = new Array(specs.length);
  let next = 0;
  async function worker() {
    while (next < specs.length) {
      const i = next++;
      const spec = specs[i];
      if (!spec) continue;
      results[i] = await scanServer(spec, opts);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, specs.length) }, worker));
  return results;
}
