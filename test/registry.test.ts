import { describe, expect, it } from "vitest";
import { parseRegistry, specFromRegistryServer, specsFromInput } from "../src/registry";

const REGISTRY_DOC = {
  servers: [
    {
      server: {
        name: "ac.inference.sh/mcp",
        description: "Run AI apps.",
        remotes: [{ type: "streamable-http", url: "https://api.inference.sh/mcp" }],
      },
      _meta: { "io.modelcontextprotocol.registry/official": { status: "active", isLatest: true } },
    },
    {
      server: {
        name: "ai.adeu/adeu",
        packages: [
          { registryType: "pypi", identifier: "adeu", version: "1.5.2", transport: { type: "stdio" } },
          { registryType: "npm", identifier: "@adeu/mcp-server", version: "1.7.1", transport: { type: "stdio" } },
        ],
      },
    },
    { server: { name: "only.pypi/x", packages: [{ registryType: "pypi", identifier: "x" }] } },
  ],
  metadata: { nextCursor: "ac.tandem/docs-mcp:0.3.0", count: 3 },
};

describe("parseRegistry", () => {
  it("extracts server objects and the cursor", () => {
    const { servers, nextCursor } = parseRegistry(REGISTRY_DOC);
    expect(servers).toHaveLength(3);
    expect(servers[0]!.name).toBe("ac.inference.sh/mcp");
    expect(nextCursor).toBe("ac.tandem/docs-mcp:0.3.0");
  });

  it("is tolerant of junk", () => {
    expect(parseRegistry(null).servers).toHaveLength(0);
    expect(parseRegistry({}).nextCursor).toBeNull();
  });
});

describe("specFromRegistryServer", () => {
  const [remote, npm, pypi] = parseRegistry(REGISTRY_DOC).servers;

  it("prefers a remote URL", () => {
    expect(specFromRegistryServer(remote!)).toMatchObject({
      kind: "url",
      label: "ac.inference.sh/mcp",
      url: "https://api.inference.sh/mcp",
    });
  });

  it("uses an npm package only when includeNpm is set", () => {
    expect(specFromRegistryServer(npm!)).toBeNull();
    expect(specFromRegistryServer(npm!, { includeNpm: true })).toMatchObject({
      kind: "stdio",
      command: ["npx", "-y", "@adeu/mcp-server@1.7.1"],
    });
  });

  it("skips pypi/oci-only servers", () => {
    expect(specFromRegistryServer(pypi!, { includeNpm: true })).toBeNull();
  });
});

describe("specsFromInput", () => {
  it("accepts a registry document", () => {
    const specs = specsFromInput(REGISTRY_DOC, { includeNpm: true });
    expect(specs.map((s) => s.kind).sort()).toEqual(["stdio", "url"]);
  });

  it("accepts a plain array of specs", () => {
    const specs = specsFromInput([
      { kind: "url", label: "a", url: "https://a.com/mcp" },
      { label: "b", command: ["node", "b.js"] },
    ]);
    expect(specs).toHaveLength(2);
    expect(specs[1]).toMatchObject({ kind: "stdio", command: ["node", "b.js"] });
  });

  it("rejects unusable input", () => {
    expect(() => specsFromInput(42 as unknown)).toThrow();
  });
});
