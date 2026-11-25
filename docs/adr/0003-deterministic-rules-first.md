# 0003: Deterministic rules first, AI as a validated summariser

**Status:** accepted

## Context
Analysts act on findings, so a fabricated IP, frame or command is worse than no answer. LLMs can invent all three.

## Decision
All findings come from versioned, deterministic rules that record their evidence, limitations, alternatives and missing evidence. The AI copilot may only connect existing findings into ranked hypotheses. Its output must follow a JSON schema, and a validator checks every IP, frame, finding ID and placeholder it mentions against the evidence and rejects shell syntax. If validation fails, a deterministic synthesis is shown instead, and the failed attempt is stored. Addresses are redacted with reversible tokens before any external call, and payloads are never sent.

## Consequences
- The product is fully useful with `PKO_LLM_PROVIDER=none`.
- Copilot output is narrower than free-form chat. That is intentional.
- Rule changes bump the rule version, which is stored on every finding.
