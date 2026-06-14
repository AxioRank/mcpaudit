import { describe, expect, it } from "vitest";
import { parseConfig, specFromArgs } from "../src/config";

describe("parseConfig", () => {
  it("reads the mcpServers shape (Claude/Cursor)", () => {
    const specs = parseConfig({
      mcpServers: {
        github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { T: "x" } },
        remote: { url: "https://example.com/mcp", headers: { Authorization: "Bearer x" } },
      },
    });
    expect(specs).toHaveLength(2);
    const github = specs.find((s) => s.label === "github");
    expect(github).toMatchObject({
      kind: "stdio",
      command: ["npx", "-y", "@modelcontextprotocol/server-github"],
    });
    const remote = specs.find((s) => s.label === "remote");
    expect(remote).toMatchObject({ kind: "url", url: "https://example.com/mcp" });
  });

  it("reads the servers shape (VS Code)", () => {
    const specs = parseConfig({ servers: { fs: { command: "node", args: ["server.js"] } } });
    expect(specs).toHaveLength(1);
    expect(specs[0]).toMatchObject({ kind: "stdio", label: "fs" });
  });

  it("ignores entries with neither command nor url", () => {
    const specs = parseConfig({ mcpServers: { broken: { foo: "bar" } } });
    expect(specs).toHaveLength(0);
  });
});

describe("specFromArgs", () => {
  it("treats an http target as a remote server", () => {
    expect(specFromArgs("https://a.com/mcp", [])).toMatchObject({
      kind: "url",
      url: "https://a.com/mcp",
    });
  });

  it("treats anything else as a stdio command", () => {
    expect(specFromArgs("npx", ["-y", "server"])).toMatchObject({
      kind: "stdio",
      command: ["npx", "-y", "server"],
    });
  });
});
