import type { LocalDecision, RiskSignal } from "@axiorank/detectors";

/** How to reach an MCP server. */
export type ServerSpec =
  | {
      kind: "stdio";
      /** Display label, e.g. the config key or the command. */
      label: string;
      /** argv[0] + args, e.g. ["npx", "-y", "@modelcontextprotocol/server-github"]. */
      command: string[];
      env?: Record<string, string>;
    }
  | {
      kind: "url";
      label: string;
      url: string;
      headers?: Record<string, string>;
    };

/** One tool a server exposes (the surface an agent can be told to call). */
export interface McpTool {
  name: string;
  description?: string;
  /** JSON Schema for the tool's arguments, as declared by the server. */
  inputSchema?: Record<string, unknown>;
}

/** One resource a server exposes (untrusted content an agent may read). */
export interface McpResource {
  uri?: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/** One prompt template a server exposes. */
export interface McpPrompt {
  name: string;
  description?: string;
}

/** The full surface enumerated from a live server (or a static card). */
export interface McpSurface {
  serverInfo?: { name?: string; version?: string };
  /** How the surface was obtained, for the report. */
  via: "stdio" | "streamable-http" | "well-known-card";
  tools: McpTool[];
  resources: McpResource[];
  prompts: McpPrompt[];
  /** Non-fatal notes gathered while enumerating (e.g. a method the server lacks). */
  notes: string[];
}

/** The result of scanning one server. */
export interface ScanResult {
  server: ServerSpec;
  surface?: McpSurface;
  signals: RiskSignal[];
  /** 0 to 100, combined risk across the surface. */
  risk: number;
  decision: LocalDecision;
  decisionReason: string;
  /** Set when the server could not be reached or enumerated. */
  error?: string;
}
