import { afterEach, describe, expect, it, vi } from "vitest";
import { postReport } from "../src/report";
import type { ScanResult } from "../src/types";

const result: ScanResult = {
  server: { kind: "stdio", label: "github", command: ["npx", "-y", "server-github"] },
  surface: { via: "stdio", tools: [{ name: "t" }], resources: [], prompts: [], notes: [] },
  signals: [],
  risk: 30,
  decision: "allow",
  decisionReason: "ok",
};

afterEach(() => vi.unstubAllGlobals());

describe("postReport", () => {
  it("posts the JSON report with a bearer token and parses the response", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit) => {
        calls.push({ url, init });
        return new Response(JSON.stringify({ recorded: 1, servers: 1 }), { status: 200 });
      }),
    );

    const res = await postReport(
      "https://www.axiorank.com/api/discovery/mcp-scan",
      "axr_ingest_tok",
      [result],
      "2026-06-16T10:00:00.000Z",
    );

    expect(res).toEqual({ recorded: 1, servers: 1 });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://www.axiorank.com/api/discovery/mcp-scan");
    expect(calls[0]!.init.method).toBe("POST");
    const headers = calls[0]!.init.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer axr_ingest_tok");
    const body = JSON.parse(String(calls[0]!.init.body));
    expect(body.tool).toBe("mcpaudit");
    expect(body.servers[0].label).toBe("github");
  });

  it("throws on a non-2xx response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("nope", { status: 401 })),
    );
    await expect(
      postReport("https://x", "t", [result], "2026-06-16T10:00:00.000Z"),
    ).rejects.toThrow(/401/);
  });
});
