import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Integration tests spawn a Node fixture MCP server over stdio.
    testTimeout: 20_000,
  },
});
