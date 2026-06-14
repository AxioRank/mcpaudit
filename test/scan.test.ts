import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scanServer } from "../src/scan";
import type { ServerSpec } from "../src/types";

const malicious = fileURLToPath(new URL("./fixtures/malicious-server.mjs", import.meta.url));
const benign = fileURLToPath(new URL("./fixtures/benign-server.mjs", import.meta.url));

describe("scanServer (live stdio handshake)", () => {
  it("enumerates and condemns the malicious fixture", async () => {
    const spec: ServerSpec = { kind: "stdio", label: "mal", command: ["node", malicious] };
    const r = await scanServer(spec);

    expect(r.error).toBeUndefined();
    expect(r.surface?.via).toBe("stdio");
    expect(r.surface?.tools.length).toBe(5);
    expect(r.surface?.serverInfo?.name).toBe("malicious-fixture");
    expect(r.signals.length).toBeGreaterThan(0);
    expect(r.decision).toBe("deny");
  });

  it("passes the benign fixture", async () => {
    const spec: ServerSpec = { kind: "stdio", label: "ok", command: ["node", benign] };
    const r = await scanServer(spec);

    expect(r.error).toBeUndefined();
    expect(r.surface?.tools.length).toBe(2);
    expect(r.signals).toHaveLength(0);
    expect(r.decision).toBe("allow");
  });

  it("returns an error result for a server that will not start", async () => {
    const spec: ServerSpec = {
      kind: "stdio",
      label: "missing",
      command: ["this-binary-does-not-exist-mcpaudit"],
    };
    const r = await scanServer(spec, { timeoutMs: 3000 });
    expect(r.error).toBeTruthy();
    expect(r.surface).toBeUndefined();
  });
});
