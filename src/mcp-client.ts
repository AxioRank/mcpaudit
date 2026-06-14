/**
 * A minimal live MCP client. mcpaudit connects to a server, runs the MCP
 * handshake, and lists the tools / resources / prompts it exposes so they can be
 * inspected. It never CALLS a tool: enumeration is read-only and side-effect
 * free, which is what makes scanning an unfamiliar third-party server safe.
 *
 * Two transports:
 *   - stdio: spawn a local server command, exchange newline-delimited JSON.
 *   - streamable-http: POST JSON-RPC to a URL, read JSON or an SSE response.
 */

import { spawn } from "node:child_process";
import type { McpResource, McpSurface, McpTool, McpPrompt } from "./types";
import { PROTOCOL_VERSION, VERSION } from "./version";

/** A JSON-RPC error returned by the server (so callers can match on `code`). */
export class JsonRpcError extends Error {
  constructor(
    message: string,
    readonly code: number,
  ) {
    super(message);
    this.name = "JsonRpcError";
  }
}

export interface Transport {
  /** Send a request and resolve its `result` (throws {@link JsonRpcError}). */
  request(method: string, params?: unknown): Promise<unknown>;
  /** Send a notification (no id, no response expected). */
  notify(method: string, params?: unknown): Promise<void>;
  /** Tear down the connection / child process. */
  close(): Promise<void>;
}

const DEFAULT_TIMEOUT_MS = 15_000;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function lastLine(s: string): string {
  const lines = s.trim().split(/\r?\n/);
  return lines[lines.length - 1] ?? "";
}

/** Spawn a local server and speak newline-delimited JSON over stdio. */
export class StdioTransport implements Transport {
  private child;
  private nextId = 1;
  private buf = "";
  private stderr = "";
  private exited = false;
  private readonly pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }
  >();

  constructor(
    command: string[],
    env: Record<string, string> | undefined,
    private readonly timeoutMs = DEFAULT_TIMEOUT_MS,
  ) {
    const [cmd, ...args] = command;
    if (!cmd) throw new Error("empty server command");
    this.child = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, ...env },
    });
    const { stdout, stderr } = this.child;
    if (!stdout || !this.child.stdin || !stderr) {
      throw new Error("server did not expose stdio pipes");
    }
    stdout.setEncoding("utf8");
    stdout.on("data", (chunk: string) => this.onData(chunk));
    stderr.setEncoding("utf8");
    stderr.on("data", (chunk: string) => {
      this.stderr = (this.stderr + chunk).slice(-8192);
    });
    this.child.on("error", (err) => this.failAll(err));
    this.child.on("exit", (code, signal) => {
      this.exited = true;
      const detail = this.stderr ? `: ${lastLine(this.stderr)}` : "";
      this.failAll(new Error(`server process exited (${signal ?? code})${detail}`));
    });
  }

  private failAll(err: Error) {
    for (const { reject, timer } of this.pending.values()) {
      clearTimeout(timer);
      reject(err);
    }
    this.pending.clear();
  }

  private onData(chunk: string) {
    this.buf += chunk;
    let nl: number;
    while ((nl = this.buf.indexOf("\n")) !== -1) {
      const line = this.buf.slice(0, nl).trim();
      this.buf = this.buf.slice(nl + 1);
      if (!line) continue;
      let msg: unknown;
      try {
        msg = JSON.parse(line);
      } catch {
        continue; // not a JSON-RPC line (some servers print banners)
      }
      this.route(msg);
    }
  }

  private route(msg: unknown) {
    if (!isObject(msg) || !("id" in msg) || typeof msg.id !== "number") return;
    const entry = this.pending.get(msg.id);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.pending.delete(msg.id);
    if (isObject(msg.error)) {
      const e = msg.error as { message?: unknown; code?: unknown };
      entry.reject(
        new JsonRpcError(
          typeof e.message === "string" ? e.message : "JSON-RPC error",
          typeof e.code === "number" ? e.code : 0,
        ),
      );
    } else {
      entry.resolve(msg.result);
    }
  }

  request(method: string, params?: unknown): Promise<unknown> {
    if (this.exited) return Promise.reject(new Error("server is not running"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timed out after ${this.timeoutMs}ms waiting for ${method}`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.write({ jsonrpc: "2.0", id, method, params });
    });
  }

  notify(method: string, params?: unknown): Promise<void> {
    this.write({ jsonrpc: "2.0", method, params });
    return Promise.resolve();
  }

  private write(msg: unknown) {
    this.child.stdin?.write(JSON.stringify(msg) + "\n");
  }

  async close(): Promise<void> {
    this.child.stdin?.end();
    if (!this.exited) {
      this.child.kill();
      // Give it a moment, then force-kill so the CLI never hangs.
      await new Promise((r) => setTimeout(r, 200));
      if (!this.exited) this.child.kill("SIGKILL");
    }
  }
}

/** Pull JSON-RPC messages out of an SSE body and return the one matching `id`. */
function parseSse(text: string, wantId: number): Record<string, unknown> | null {
  let fallback: Record<string, unknown> | null = null;
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim())
      .join("");
    if (!data) continue;
    try {
      const msg = JSON.parse(data);
      if (isObject(msg)) {
        if (msg.id === wantId) return msg;
        if (!fallback && ("result" in msg || "error" in msg)) fallback = msg;
      }
    } catch {
      // skip a non-JSON data frame
    }
  }
  return fallback;
}

/** Speak streamable-HTTP MCP: POST JSON-RPC, accept JSON or an SSE reply. */
export class HttpTransport implements Transport {
  private nextId = 1;
  private sessionId?: string;

  constructor(
    private readonly url: string,
    private readonly headers: Record<string, string> = {},
    private readonly timeoutMs = DEFAULT_TIMEOUT_MS,
  ) {}

  private async post(body: Record<string, unknown>): Promise<Response> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...this.headers,
    };
    if (this.sessionId) headers["mcp-session-id"] = this.sessionId;
    const resp = await fetch(this.url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const sid = resp.headers.get("mcp-session-id");
    if (sid) this.sessionId = sid;
    return resp;
  }

  async request(method: string, params?: unknown): Promise<unknown> {
    const id = this.nextId++;
    const resp = await this.post({ jsonrpc: "2.0", id, method, params });
    if (!resp.ok && resp.status >= 400) {
      throw new Error(`HTTP ${resp.status} ${resp.statusText} from ${this.url}`);
    }
    const ct = resp.headers.get("content-type") ?? "";
    const text = await resp.text();
    const msg = ct.includes("text/event-stream")
      ? parseSse(text, id)
      : text
        ? (JSON.parse(text) as Record<string, unknown>)
        : null;
    if (!msg) throw new Error(`empty response to ${method}`);
    if (isObject(msg.error)) {
      const e = msg.error as { message?: unknown; code?: unknown };
      throw new JsonRpcError(
        typeof e.message === "string" ? e.message : "JSON-RPC error",
        typeof e.code === "number" ? e.code : 0,
      );
    }
    return msg.result;
  }

  async notify(method: string, params?: unknown): Promise<void> {
    await this.post({ jsonrpc: "2.0", method, params });
  }

  async close(): Promise<void> {
    if (!this.sessionId) return;
    try {
      await fetch(this.url, {
        method: "DELETE",
        headers: { "mcp-session-id": this.sessionId, ...this.headers },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch {
      // best effort: the session expires server-side anyway
    }
  }
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function asRecord(v: unknown): Record<string, unknown> | undefined {
  return isObject(v) ? v : undefined;
}

/** Call a list method (tools/resources/prompts), tolerating servers that lack it. */
async function listSafe(
  t: Transport,
  method: string,
  key: string,
  notes: string[],
): Promise<unknown[]> {
  try {
    const result = await t.request(method);
    const items = asRecord(result)?.[key];
    return asArray(items);
  } catch (err) {
    if (err instanceof JsonRpcError && (err.code === -32601 || err.code === -32600)) {
      notes.push(`server does not implement ${method}`);
      return [];
    }
    notes.push(`${method} failed: ${(err as Error).message}`);
    return [];
  }
}

/** Run the handshake and enumerate the full surface of a connected server. */
export async function enumerateServer(
  t: Transport,
  via: McpSurface["via"],
): Promise<McpSurface> {
  const notes: string[] = [];
  const init = await t.request("initialize", {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "mcpaudit", version: VERSION },
  });
  await t.notify("notifications/initialized");

  const serverInfoRaw = asRecord(asRecord(init)?.serverInfo);
  const serverInfo = serverInfoRaw
    ? { name: asString(serverInfoRaw.name), version: asString(serverInfoRaw.version) }
    : undefined;

  const tools: McpTool[] = (await listSafe(t, "tools/list", "tools", notes)).map((raw) => {
    const r = asRecord(raw) ?? {};
    return {
      name: asString(r.name) ?? "unnamed",
      description: asString(r.description),
      inputSchema: asRecord(r.inputSchema),
    };
  });

  const resources: McpResource[] = (await listSafe(t, "resources/list", "resources", notes)).map(
    (raw) => {
      const r = asRecord(raw) ?? {};
      return {
        uri: asString(r.uri),
        name: asString(r.name),
        description: asString(r.description),
        mimeType: asString(r.mimeType),
      };
    },
  );

  const prompts: McpPrompt[] = (await listSafe(t, "prompts/list", "prompts", notes)).map((raw) => {
    const r = asRecord(raw) ?? {};
    return { name: asString(r.name) ?? "unnamed", description: asString(r.description) };
  });

  return { serverInfo, via, tools, resources, prompts, notes };
}
