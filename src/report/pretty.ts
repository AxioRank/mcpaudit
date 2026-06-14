/** Human-readable terminal report. Colorized when stdout is a TTY. */

import type { Severity } from "@axiorank/detectors";
import { severityCounts } from "../gate";
import type { ScanResult } from "../types";

const ESC = String.fromCharCode(27);

const useColor =
  process.env.NO_COLOR === undefined &&
  process.env.FORCE_COLOR !== "0" &&
  (process.stdout.isTTY || process.env.FORCE_COLOR === "1");

function c(code: number, s: string): string {
  return useColor ? `${ESC}[${code}m${s}${ESC}[0m` : s;
}
const bold = (s: string) => c(1, s);
const dim = (s: string) => c(2, s);
const red = (s: string) => c(31, s);
const yellow = (s: string) => c(33, s);
const blue = (s: string) => c(34, s);
const green = (s: string) => c(32, s);

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => bold(red(s)),
  high: red,
  medium: yellow,
  low: blue,
};

function decisionBadge(decision: ScanResult["decision"]): string {
  if (decision === "deny") return bold(red(" DENY "));
  if (decision === "hold") return bold(yellow(" HOLD "));
  return bold(green(" PASS "));
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function renderResult(r: ScanResult): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`${bold("●")} ${bold(r.server.label)} ${dim(`(${r.server.kind})`)}`);

  if (r.error) {
    lines.push(`  ${red("could not scan:")} ${r.error}`);
    return lines.join("\n");
  }

  const s = r.surface;
  if (s) {
    const name = s.serverInfo?.name ?? "unknown";
    const version = s.serverInfo?.version ? ` v${s.serverInfo.version}` : "";
    lines.push(
      dim(
        `  ${name}${version}  ·  via ${s.via}  ·  ` +
          `${s.tools.length} tools, ${s.resources.length} resources, ${s.prompts.length} prompts`,
      ),
    );
  }

  lines.push(`  ${bold(`RISK ${r.risk}/100`)}   ${decisionBadge(r.decision)}`);

  if (r.signals.length === 0) {
    lines.push(`  ${green("no findings")}`);
  } else {
    lines.push("");
    for (const sig of r.signals.slice(0, 50)) {
      const mark = SEVERITY_COLOR[sig.severity]("●");
      const sev = SEVERITY_COLOR[sig.severity](pad(sig.severity, 9));
      lines.push(
        `  ${mark} ${sev} ${pad(sig.detector, 34)} ${dim(pad(sig.location, 24))} ${sig.label}`,
      );
      if (sig.evidence) lines.push(`      ${dim(sig.evidence)}`);
    }
    if (r.signals.length > 50) lines.push(dim(`  ... and ${r.signals.length - 50} more`));

    const counts = severityCounts(r.signals);
    const parts = (["critical", "high", "medium", "low"] as Severity[])
      .filter((k) => counts[k] > 0)
      .map((k) => SEVERITY_COLOR[k](`${counts[k]} ${k}`));
    lines.push("");
    lines.push(`  ${r.signals.length} findings (${parts.join(", ")})`);
  }

  for (const note of r.surface?.notes ?? []) lines.push(dim(`  note: ${note}`));
  return lines.join("\n");
}

export function renderPretty(results: ScanResult[]): string {
  const header = `${bold("mcpaudit")} ${dim("·")} scanned ${results.length} server${
    results.length === 1 ? "" : "s"
  }`;
  return [header, ...results.map(renderResult), ""].join("\n");
}
