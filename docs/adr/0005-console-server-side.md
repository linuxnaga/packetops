# 0005: Server-side Command Deck

**Status:** accepted

## Context
The gamified console must run real analysis, not a simulation, and must not become a shell.

## Decision
The browser sends a command line. The server tokenises it with a small parser, matches it against a registry of typed commands, checks the command's permission, prompts for missing arguments, and returns structured blocks (lines, key/value lists, tables, actions). Commands call the same services as the REST API. No command executes anything on a host. Verification commands in findings are text for the analyst to run.

## Consequences
- The same RBAC, tenant isolation and audit rules apply in the console and the UI.
- Completion and prompts are context-aware (captures, flows, findings of the selected capture).
- The command reference is generated from the registry ([console.md](../console.md)).
