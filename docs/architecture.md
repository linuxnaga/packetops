# Architecture

## Components

```
Browser (React SPA)
   │  HTTPS
   ▼
nginx (frontend container) ── static SPA, CSP, /api proxy, unbuffered uploads and SSE
   │
   ▼
FastAPI (api) ──────────────┬── MongoDB      metadata, findings, flows, users, audit
   │  enqueue               ├── Redis        Celery broker / results
   ▼                        └── Evidence store (shared volume or S3): original captures, Parquet packet tables, reports
Celery worker (no egress) ── tshark (fixed arguments) → aggregator → rules → MongoDB + Parquet
Celery beat ── hourly retention sweep
```

| Container | Networks | Notes |
|---|---|---|
| frontend | edge | Only published port. Unprivileged nginx, read-only root. |
| api | edge, backend | Edge is needed only for OIDC JWKS and an external AI provider. |
| worker | backend (internal) | Parses untrusted captures. No route to the internet. |
| beat | backend | Schedules maintenance tasks. |
| mongo, redis | backend | Not published. |

All application containers run read-only with `cap_drop: ALL`, `no-new-privileges`, tmpfs scratch space and CPU/memory/PID limits.

## Analysis pipeline

1. **Upload.** The API streams the raw request body to scratch space while computing SHA-256 and enforcing the size limit and the tenant quota. It checks the pcap/pcapng structure (magic, block lengths, link types, packet count) before the file is stored. Archives and other files are rejected. The original is written once under `tenants/<tenant>/captures/<capture>/original.<ext>` and never modified.
2. **Queue.** A job document records stage and progress. The Celery task runs on the `analysis` queue, with at most N concurrent analyses per tenant.
3. **Extract.** tshark runs with a fixed argument list (`-r <file> -T fields -e …`), never through a shell. Name resolution is off. Memory and time limits apply, and cancellation is checked between batches.
4. **Aggregate.** A streaming aggregator builds per-packet rows (written as Parquet in batches), TCP/UDP conversations, handshake timing, retransmission/RST/zero-window state, TLS handshakes and alerts, DNS transactions, HTTP request/response pairs, and F5 Ethernet trailer data (flow IDs, peer IDs, virtual server names, reset causes).
5. **Rules.** 28 deterministic rules (TCP, TLS, DNS, HTTP, BIG-IP-observable) produce findings. Each finding has evidence references (frames, flows, tuples), metrics, alternatives, verification commands and missing evidence. Rules never infer a BIG-IP from addressing alone.
6. **Publish.** Flows, findings and evidence references go to MongoDB, packet rows to Parquet, and stats and limitations to the capture document. The SSE endpoint reports progress to the browser.

Packet queries (`/packets?filter=…`) compile a safe display-filter subset into Arrow expressions over the Parquet table. Arbitrary tshark filters are never passed through. A single frame's full dissection tree and bytes come from one tshark call bounded to that frame.

## BIG-IP correlation

`POST /f5/correlations` pairs client-side and server-side connections in three tiers:

| Method | Evidence | Confidence |
|---|---|---|
| `f5-trailer` | Flow ID on one side equals peer ID on the other (capture taken with `tcpdump -i 0.0:nnnp`) | high |
| `config+timing` | Client → configured VIP, server side → configured pool member from SNAT/self IP, starts within a window | medium, high when byte counts agree |
| `timing` | Start-time proximity only | low |

Every pair records method, confidence and notes. The result lists unmatched flows and limitations. BIG-IP configuration is operator-supplied context: `parse_tmsh` reads `tmsh list` and `bigip.conf` text and keeps only virtual servers, pools, SNAT, self IPs, VLANs and routes.

## AI copilot

The copilot is optional (`PKO_LLM_PROVIDER=none|anthropic|openai_compatible`).

1. The context sent to the model contains only finding facts: observations, metrics, frames and rule text. Packet payloads are never sent.
2. With `PKO_LLM_REDACT_ADDRESSES=true` (the default), IPs, hostnames, URL paths and MACs are replaced with reversible tokens (`IP_1`, `HOST_2` …) before the request. They are restored afterwards.
3. The model must return JSON matching a fixed schema: hypotheses with cited finding IDs and frames, plus a verification order.
4. A validator rejects output that cites unknown IPs, frames or finding IDs, contains shell command syntax, or leaves placeholders unmapped. Rejected output is replaced by a deterministic synthesis. The failed attempt is stored for review, and the UI says which one is shown.

## Data model (MongoDB)

Every document carries `tenant_id`. All access goes through `TenantDB`, which injects the tenant filter into every query and update, so cross-tenant reads are impossible by construction (tested in `tests/test_api_security.py`).

| Collection | Purpose | Key fields / indexes |
|---|---|---|
| `tenants`, `users` | Tenancy and identity | `slug` unique; `(tenant_id, email)` unique; roles |
| `captures` | Evidence metadata | sha256, size, format, status, stats, limitations, retention `retain_until`, `legal_hold`, `training` |
| `analysis_jobs` | Job state | status, stage, progress, stages[], attempts |
| `packet_summaries` | Pointer to the Parquet table and its schema version | unique per capture |
| `flows` | Conversations | local_id (`t3`, `u1`), tuple, state, handshake, tls, http[], f5{}, timeline, issue_score |
| `findings` | Rule output | rule_id + version, severity, confidence, status, observations, alternatives, notes (append-only) |
| `evidence_references` | Frame/flow evidence per finding | finding_id, kind, refs |
| `f5_configuration_metadata` | Imported BIG-IP metadata | `(tenant_id, name)` unique |
| `correlations` | Correlation results | client/server capture, config, pairs[], observations |
| `investigations` | Case tracking | captures, findings, append-only notes, status |
| `user_progress`, `xp_ledger`, `mission_runs` | Gamification | ledger `event_key` unique per user, so XP cannot be double-awarded |
| `ai_syntheses` | Copilot output | provider, validation result, fallback flag, failed attempt |
| `reports` | Generated reports | format, sha256, storage key |
| `console_sessions` | Command Deck state | selected capture, history, pending prompt |
| `audit_events` | Audit log | ts, actor, action, resource, outcome, request_id |
| `bookmarks` | Reserved (index only; feature not built yet) | |

Bulk packet rows are stored in Parquet next to the capture, not in MongoDB, so a 20-million-packet capture does not become 20 million documents.

## Gamification

XP comes from verifiable events: an analysed capture, a confirmed finding with a written note, a report that cites evidence, a completed correlation, mission objectives. The ledger key makes each award idempotent. Training XP is labelled as training. Levels are learning milestones and the UI says they are not certification.

## Decisions

See [adr/](adr/):

- [0001](adr/0001-tshark-as-dissector.md) tshark as the dissector
- [0002](adr/0002-parquet-packet-store.md) Parquet for packet rows, MongoDB for metadata
- [0003](adr/0003-deterministic-rules-first.md) Deterministic rules first, AI as a validated summariser
- [0004](adr/0004-tenant-scoped-db-wrapper.md) Tenant isolation in a DB wrapper
- [0005](adr/0005-console-server-side.md) Server-side Command Deck
- [0006](adr/0006-local-volume-default-storage.md) Shared volume as the default evidence store, S3 optional
