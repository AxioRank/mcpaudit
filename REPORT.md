# The State of MCP Security

_Generated 2026-06-14 by [mcpaudit](https://github.com/AxioRank/mcpaudit) v0.2.0. Reproduce with `npx @axiorank/mcpaudit registry-scan`._

## Summary

- **98** MCP servers scanned from the public registry.
- **70** (71%) had at least one security finding.
- **45** would be blocked and **9** held for review by the default posture.
- **28** were clean.
- 102 could not be reached (offline, auth required, or no usable transport).

## Findings by severity

| Severity | Findings | Servers affected |
| --- | ---: | ---: |
| critical | 0 | 0 |
| high | 668 | 63 |
| medium | 230 | 43 |
| low | 3 | 1 |

## Most common issues

| Issue | Detector | Servers |
| --- | --- | ---: |
| Tool declares a high-privilege capability | `supply_chain.dangerous_capability` | 31 |
| Shell/command injection | `injection.shell` | 29 |
| Credential / secret access capability | `supply_chain.credential_access` | 24 |
| Payment / fund-movement capability | `supply_chain.fund_movement` | 21 |
| Code-execution capability | `supply_chain.code_execution` | 20 |
| Tool input schema asks for a credential | `supply_chain.solicits_credentials` | 18 |
| SQL injection | `injection.sql` | 13 |
| SQL DELETE/UPDATE without WHERE | `destructive.sql_no_where` | 12 |
| Administrative capability | `supply_chain.admin_reach` | 4 |
| Obfuscated content | `obfuscation.encoded_payload` | 4 |
| Credit card number | `pii.credit_card` | 3 |
| No-restrictions jailbreak | `injection.jailbreak.no_restrictions` | 3 |

## Findings by category

| Category | Findings |
| --- | ---: |
| supply_chain | 648 |
| injection | 200 |
| destructive | 23 |
| pii | 22 |
| secret | 5 |
| egress | 3 |

## Highest-risk servers

Server names are withheld. Affected maintainers are contacted before any named findings are published. Run with `--name-servers` to produce the named leaderboard for private triage.

## Methodology

mcpaudit connects to each server, runs the MCP handshake, and inspects the tools, resources, and prompts it exposes. Enumeration is **read-only**: no tool is ever called. Risk is scored by the open-source `@axiorank/detectors` engine plus MCP-specific heuristics (tool shadowing, credential-soliciting schemas, dangerous capabilities). A finding is a heuristic signal, not proof of a vulnerability.

