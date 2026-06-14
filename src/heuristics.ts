/**
 * MCP-specific structural signals, layered on top of the shared content engine.
 *
 * The content engine (inspectContent + CARD_DETECTORS) already reads every tool
 * description, resource, and prompt as text, so prompt injection, tool poisoning
 * (malicious instructions hidden in a description), leaked secrets, PII, and
 * destructive language all surface from there. These heuristics add the things
 * that are only visible in the STRUCTURE of the surface: one tool shadowing
 * another, a tool soliciting credentials through its schema, and capabilities
 * whose very name implies a dangerous operation.
 */

import { pointsFor, type RiskSignal, type Severity } from "@axiorank/detectors";
import type { McpSurface, McpTool } from "./types";

function sig(
  detector: string,
  severity: Severity,
  label: string,
  location: string,
  evidence: string,
): RiskSignal {
  return {
    detector,
    category: "supply_chain",
    severity,
    label,
    points: pointsFor(severity),
    location,
    evidence,
  };
}

/** Names that, on their own, signal a tool can read or move credentials. */
const SENSITIVE_PARAM = /(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|client[_-]?secret|bearer|session[_-]?id)/i;

/** Collect property names from a JSON Schema, bounded in depth and breadth. */
function schemaPropertyNames(schema: unknown, depth = 0, out: string[] = []): string[] {
  if (depth > 4 || out.length > 200 || typeof schema !== "object" || schema === null) return out;
  const s = schema as Record<string, unknown>;
  const props = s.properties;
  if (props && typeof props === "object") {
    for (const [name, child] of Object.entries(props as Record<string, unknown>)) {
      out.push(name);
      schemaPropertyNames(child, depth + 1, out);
    }
  }
  if (s.items) schemaPropertyNames(s.items, depth + 1, out);
  return out;
}

/** Tool names that imply code execution: the highest-privilege class. */
const EXEC_CAPABILITY =
  /\b(exec|eval|shell|spawn|sub_?process|system|run_?command|run_?code|sudo|powershell|bash|cmd)\b/i;
/** Tool names that imply irreversible data loss. */
const DESTRUCTIVE_CAPABILITY =
  /\b(delete|destroy|drop|truncate|wipe|erase|unlink|format|purge|remove)\b/i;
/** Tool names that imply mutation or outbound transfer. */
const WRITE_CAPABILITY =
  /\b(write|put|upload|create|update|modify|move|rename|push|publish|insert|append|send|post|transfer)\b/i;

/** Split a snake_case / camelCase tool name into space-separated words so the
 *  capability patterns' word boundaries work (`delete_account` → `delete account`). */
function words(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[^a-zA-Z0-9]+/g, " ")
    .toLowerCase()
    .trim();
}

/** A tool whose NAME implies a dangerous operation declares that capability. */
function capabilitySignals(tool: McpTool, index: number): RiskSignal[] {
  const name = words(tool.name);
  let severity: Severity | null = null;
  let kind = "";
  if (EXEC_CAPABILITY.test(name)) {
    severity = "high";
    kind = "code execution";
  } else if (DESTRUCTIVE_CAPABILITY.test(name)) {
    severity = "high";
    kind = "irreversible data loss";
  } else if (WRITE_CAPABILITY.test(name)) {
    severity = "medium";
    kind = "write or outbound transfer";
  }
  if (!severity) return [];
  return [
    sig(
      "supply_chain.dangerous_capability",
      severity,
      "Tool declares a high-privilege capability",
      `tools[${index}].name`,
      `"${tool.name}" implies a ${kind} capability`,
    ),
  ];
}

/** A tool whose schema asks for a credential is a secret-exfiltration surface. */
function credentialSolicitation(tool: McpTool, index: number): RiskSignal[] {
  const hits = schemaPropertyNames(tool.inputSchema).filter((n) => SENSITIVE_PARAM.test(n));
  if (hits.length === 0) return [];
  return [
    sig(
      "supply_chain.solicits_credentials",
      "medium",
      "Tool input schema asks for a credential",
      `tools[${index}].inputSchema`,
      `parameter(s) named ${[...new Set(hits)].slice(0, 5).join(", ")} would carry a secret into this tool`,
    ),
  ];
}

/** Two tools sharing a name lets one shadow (impersonate) the other. */
function shadowSignals(tools: McpTool[]): RiskSignal[] {
  const counts = new Map<string, number>();
  for (const t of tools) counts.set(t.name, (counts.get(t.name) ?? 0) + 1);
  const out: RiskSignal[] = [];
  for (const [name, n] of counts) {
    if (n > 1) {
      out.push(
        sig(
          "supply_chain.tool_shadowing",
          "high",
          "Duplicate tool name (shadowing)",
          "(tools)",
          `${n} tools are named "${name}"; one can shadow the other and intercept its calls`,
        ),
      );
    }
  }
  return out;
}

/** All MCP-specific structural signals for an enumerated surface. */
export function structuralSignals(surface: McpSurface): RiskSignal[] {
  const out: RiskSignal[] = [];
  surface.tools.forEach((tool, i) => {
    out.push(...capabilitySignals(tool, i));
    out.push(...credentialSolicitation(tool, i));
  });
  out.push(...shadowSignals(surface.tools));
  return out;
}
