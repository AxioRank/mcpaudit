/**
 * Parse an MCP client config into a list of servers to scan. Handles the shapes
 * used by Claude Desktop, Cursor, and Windsurf (`mcpServers`) and VS Code
 * (`servers`), with either a `command` (stdio) or a `url` (remote) per entry.
 */

import { readFileSync } from "node:fs";
import type { ServerSpec } from "./types";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function asStringArray(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}
function asStringRecord(v: unknown): Record<string, string> | undefined {
  if (!isObject(v)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v)) if (typeof val === "string") out[k] = val;
  return out;
}

/** Turn a parsed config object into server specs. Pure (for testing). */
export function parseConfig(doc: unknown): ServerSpec[] {
  if (!isObject(doc)) return [];
  const block = isObject(doc.mcpServers)
    ? doc.mcpServers
    : isObject(doc.servers)
      ? doc.servers
      : doc;
  const specs: ServerSpec[] = [];
  for (const [label, raw] of Object.entries(block)) {
    if (!isObject(raw)) continue;
    const url = asString(raw.url);
    const command = asString(raw.command);
    if (command) {
      specs.push({
        kind: "stdio",
        label,
        command: [command, ...asStringArray(raw.args)],
        env: asStringRecord(raw.env),
      });
    } else if (url) {
      specs.push({
        kind: "url",
        label,
        url,
        headers: asStringRecord(raw.headers),
      });
    }
  }
  return specs;
}

/** Read and parse a config file from disk. */
export function loadConfig(path: string): ServerSpec[] {
  const text = readFileSync(path, "utf8");
  return parseConfig(JSON.parse(text));
}

/**
 * Build a server spec from a positional CLI target. A target that looks like a
 * URL becomes a remote server; anything else is treated as a stdio command, with
 * everything after a `--` (or all remaining args) passed through verbatim.
 */
export function specFromArgs(target: string, rest: string[]): ServerSpec {
  if (/^https?:\/\//i.test(target)) {
    return { kind: "url", label: target, url: target };
  }
  const command = [target, ...rest];
  return { kind: "stdio", label: command.join(" "), command };
}
