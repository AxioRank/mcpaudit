# Changelog

## 0.1.0

First release.

- `mcpaudit scan` connects to a local (stdio) or remote (streamable-HTTP) MCP
  server, enumerates its tools, resources, and prompts, and inspects them for
  prompt injection, tool poisoning, leaked secrets, PII, destructive language,
  tool shadowing, credential-soliciting schemas, and dangerous capabilities.
- `--config` scans every server in a Claude, Cursor, Windsurf, or VS Code config.
- Output as a readable report, JSON, or SARIF 2.1.0 for GitHub code scanning.
- `--fail-on` gates CI on a severity threshold; `--share` posts a public scorecard.
- `mcpaudit probe` runs the bundled red-team corpus through the engine to show its
  catch rate.
- A composite GitHub Action runs the scan and uploads SARIF.

Detection is powered by the open-source `@axiorank/detectors` engine and
`@axiorank/redteam-corpus`. Runs locally with no key and no signup. Enumeration
is read-only: mcpaudit never calls a scanned server's tools.
