/**
 * mcpaudit CLI.
 *
 *   mcpaudit scan -- npx -y @modelcontextprotocol/server-everything
 *   mcpaudit scan https://example.com/mcp
 *   mcpaudit scan --config ~/.cursor/mcp.json --format sarif
 *   mcpaudit probe --full
 *
 * Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage/operational error.
 */

import { loadConfig, specFromArgs } from "./config";
import { type FailOn, SEVERITY_RANK, shouldFail } from "./gate";
import { renderJson } from "./report/json";
import { renderPretty } from "./report/pretty";
import { renderSarif } from "./report/sarif";
import { runProbe, type ProbeReport } from "./probe";
import { scanServers } from "./scan";
import { shareScan } from "./share";
import type { ScanResult, ServerSpec } from "./types";
import { VERSION } from "./version";

type Format = "pretty" | "json" | "sarif";

const DEFAULT_BASE_URL = process.env.AXIORANK_BASE_URL ?? "https://www.axiorank.com";

function fail(message: string): never {
  process.stderr.write(`mcpaudit: ${message}\n`);
  process.exit(2);
}

function isFailOn(v: string): v is FailOn {
  return v === "none" || v in SEVERITY_RANK;
}

interface ScanArgs {
  specs: ServerSpec[];
  format: Format;
  failOn: FailOn;
  share: boolean;
  timeoutMs: number;
  baseUrl: string;
}

function parseScanArgs(args: string[]): ScanArgs {
  let format: Format = "pretty";
  let failOn: FailOn = "high";
  let share = false;
  let timeoutMs = 15_000;
  let baseUrl = DEFAULT_BASE_URL;
  let configPath: string | undefined;

  const dd = args.indexOf("--");
  const head = dd === -1 ? args : args.slice(0, dd);
  const tail = dd === -1 ? [] : args.slice(dd + 1);

  let target: string | undefined;
  let targetArgs: string[] = [];

  for (let i = 0; i < head.length; i++) {
    const a = head[i];
    if (a === undefined) continue;
    const value = () => {
      const v = head[++i];
      if (v === undefined) fail(`flag ${a} needs a value`);
      return v;
    };
    if (a === "--config") configPath = value();
    else if (a === "--format") {
      const f = value();
      if (f !== "pretty" && f !== "json" && f !== "sarif") fail(`unknown format "${f}"`);
      format = f;
    } else if (a === "--fail-on") {
      const f = value();
      if (!isFailOn(f)) fail(`unknown --fail-on "${f}" (none|low|medium|high|critical)`);
      failOn = f;
    } else if (a === "--share") share = true;
    else if (a === "--timeout") timeoutMs = Number(value());
    else if (a === "--base-url") baseUrl = value();
    else if (a.startsWith("--")) fail(`unknown flag ${a}`);
    else {
      target = a;
      targetArgs = head.slice(i + 1);
      break;
    }
  }

  let specs: ServerSpec[];
  if (configPath) {
    try {
      specs = loadConfig(configPath);
    } catch (err) {
      fail(`could not read config ${configPath}: ${(err as Error).message}`);
    }
    if (specs.length === 0) fail(`no MCP servers found in ${configPath}`);
  } else if (tail.length > 0) {
    const [cmd, ...rest] = tail;
    specs = [specFromArgs(cmd as string, rest)];
  } else if (target) {
    specs = [specFromArgs(target, targetArgs)];
  } else {
    fail("nothing to scan. Pass a URL, `-- <server command>`, or --config <file>.");
  }

  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) fail("--timeout must be a positive number");
  return { specs, format, failOn, share, timeoutMs, baseUrl };
}

async function runScanCommand(args: string[]): Promise<number> {
  const opts = parseScanArgs(args);
  const results = await scanServers(opts.specs, { timeoutMs: opts.timeoutMs });

  if (opts.share) await runShare(results, opts.baseUrl);

  const scannedAt = new Date().toISOString();
  if (opts.format === "json") process.stdout.write(renderJson(results, scannedAt) + "\n");
  else if (opts.format === "sarif") process.stdout.write(renderSarif(results) + "\n");
  else process.stdout.write(renderPretty(results) + "\n");

  const allErrored = results.length > 0 && results.every((r) => r.error);
  if (allErrored) {
    process.stderr.write("mcpaudit: every server failed to scan.\n");
    return 2;
  }
  return shouldFail(results, opts.failOn) ? 1 : 0;
}

async function runShare(results: ScanResult[], baseUrl: string): Promise<void> {
  for (const r of results) {
    if (!r.surface) continue;
    try {
      const shared = await shareScan(r, baseUrl);
      process.stderr.write(`shared ${r.server.label}: ${shared.url}\n`);
    } catch (err) {
      process.stderr.write(`could not share ${r.server.label}: ${(err as Error).message}\n`);
    }
  }
}

function renderProbePretty(report: ProbeReport): string {
  const lines: string[] = [];
  lines.push(`mcpaudit probe · ${report.outcomes.length} scenarios from the red-team corpus\n`);
  for (const o of report.outcomes) {
    const status = o.caught ? "PASS" : o.attack ? "MISS" : "FALSE POSITIVE";
    lines.push(`  [${status}] ${o.id}  (${o.category}, expect ${o.expected} → ${o.decision})`);
  }
  const pct = Math.round(report.catchRate * 100);
  lines.push("");
  lines.push(
    `  caught ${report.caughtAttacks}/${report.attacks} attacks (${pct}%), ` +
      `${report.falsePositives} false positives on ${report.benign} benign controls`,
  );
  return lines.join("\n");
}

function runProbeCommand(args: string[]): number {
  const full = args.includes("--full");
  const json = args.includes("--format") && args[args.indexOf("--format") + 1] === "json";
  const report = runProbe(full);
  if (json) process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  else process.stdout.write(renderProbePretty(report) + "\n");
  return 0;
}

function printHelp(): void {
  process.stdout.write(
    `mcpaudit ${VERSION} · scan MCP servers for prompt injection, tool poisoning, and leaked secrets\n\n` +
      `Usage:\n` +
      `  mcpaudit scan -- <server command>     scan a local stdio MCP server\n` +
      `  mcpaudit scan <url>                    scan a remote MCP server\n` +
      `  mcpaudit scan --config <file>          scan every server in an MCP client config\n` +
      `  mcpaudit probe [--full]                run the red-team corpus through the engine\n\n` +
      `Scan options:\n` +
      `  --format pretty|json|sarif   output format (default pretty)\n` +
      `  --fail-on none|low|medium|high|critical   exit 1 at or above this severity (default high)\n` +
      `  --share                      post the result to a public AxioRank scorecard\n` +
      `  --timeout <ms>               per-request timeout (default 15000)\n` +
      `  --base-url <url>             AxioRank base URL for --share\n\n` +
      `Examples:\n` +
      `  npx mcpaudit scan -- npx -y @modelcontextprotocol/server-everything\n` +
      `  npx mcpaudit scan --config ~/.cursor/mcp.json --format sarif > mcpaudit.sarif\n` +
      `  npx mcpaudit probe --full\n\n` +
      `Runs locally with no key and no signup. The only network call a scan makes is to the server you point it at.\n`,
  );
}

async function main(): Promise<number> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case undefined:
    case "help":
    case "-h":
    case "--help":
      printHelp();
      return 0;
    case "version":
    case "-v":
    case "--version":
      process.stdout.write(VERSION + "\n");
      return 0;
    case "scan":
      return runScanCommand(rest);
    case "probe":
      return runProbeCommand(rest);
    default:
      process.stderr.write(`mcpaudit: unknown command "${cmd}"\n\n`);
      printHelp();
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`mcpaudit: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
  });
