# Responsible disclosure

mcpaudit can scan public MCP servers and aggregate the results into a report. We
hold ourselves, and ask contributors, to these rules.

## Scanning is read-only

`mcpaudit scan` runs the MCP handshake and lists a server's tools, resources, and
prompts. It never calls a tool. Do not add active exploitation or tool invocation
to the default scan path.

## Findings are signals, not verdicts

A finding is a heuristic signal (a suspicious description, a credential-soliciting
schema, a duplicate tool name). It is not proof of a vulnerability or of intent.
Reports say so plainly.

## Aggregate first, name later

`registry-scan` produces an anonymized report by default: counts and rates, no
server names. The named leaderboard (`--name-servers`) is for private triage.

Before publishing any report that names a server:

1. Contact the maintainer privately with the specific finding and how to reproduce.
2. Give them reasonable time to respond and remediate.
3. Prefer aggregate framing. Name a server publicly only when it is in the public
   interest and the maintainer has been given the chance to respond.

## Reporting an issue in mcpaudit itself

Email security@axiorank.com. Do not open a public issue for a vulnerability in the
scanner.
