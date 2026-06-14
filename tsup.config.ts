import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/cli.ts"],
  format: ["esm"],
  // Bundle the shared detection engine and red-team corpus into the CLI so
  // `npx mcpaudit` is a single self-contained install with no runtime deps to
  // resolve. Same approach the @axiorank/sdk uses.
  noExternal: ["@axiorank/detectors", "@axiorank/redteam-corpus"],
  clean: true,
  target: "node20",
  sourcemap: true,
  // Make the built file directly executable as the `bin`.
  banner: { js: "#!/usr/bin/env node" },
});
