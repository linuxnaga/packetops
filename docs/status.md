# Project status

_Last updated: 2026-10-24_

## Acceptance criteria

| Criterion | Status | How it was verified |
|---|---|---|
| Upload a real PCAPNG | Done | Browser e2e uploads a PCAPNG captured live on loopback (70 packets, real HTTP and refused connections) through the hardened nginx container |
| Inspect packets and flows | Done | e2e: packet table, display filter `tcp.flags.reset == 1`, frame dissection tree, Flow Explorer |
| Run real console commands | Done | e2e: `pcap inspect`, `tcp handshakes`, `findings list`, tab completion. All 3 BIG-IP missions were also completed end to end through the console. |
| Evidence-backed findings | Done | The real capture produced TCP-002 "Connections to 127.0.0.1:9 refused with TCP reset", citing the SYN and RST frames. 28 rules, with golden-file tests on synthetic captures. |
| Correlate using BIG-IP metadata | Done | Tests and console missions cover trailer-based, config+timing and timing-only pairing on synthetic BIG-IP captures |
| Complete a training mission | Done | e2e completes `tcp-handshake` using answers read from the analysed capture's findings |
| Generate a report | Done | e2e generates HTML. PDF and JSON are covered by tests, and the PDF was checked visually. |
| Nothing fabricated | Done | Findings cite frames. Copilot output is validated and falls back to a deterministic synthesis. Training data is labelled SYNTHETIC. |

## Implemented

**Backend (FastAPI, Celery, MongoDB, Redis, local or S3 storage)**

- Streaming upload with SHA-256, size, quota and packet limits, structural pcap/pcapng validation, duplicate detection, write-once originals
- tshark extraction with fixed arguments and rlimits, Parquet packet store, a safe display-filter language, single-frame dissection and hex dump
- Flow aggregation: TCP state, handshakes, retransmissions, resets, zero window, TLS (versions, SNI, certificates, alerts), DNS, HTTP, F5 Ethernet trailers
- 28 detection rules (TCP, TLS, DNS, HTTP, BIG-IP observable). Each records evidence, alternatives, verification commands, remediation, missing evidence and limitations.
- BIG-IP: `tmsh`/`bigip.conf` and JSON import, three-tier client/server correlation, persistence cookie decoding, reset-cause decoding
- AI copilot: Anthropic or OpenAI-compatible (local models), reversible redaction, schema-constrained output, validator, deterministic fallback
- Command Deck: 31 commands with prompts, completion and RBAC
- Training: 10 missions on synthetic captures, XP ledger (idempotent), 7 levels, 9 achievements
- Reports in HTML, PDF and JSON. Findings export to JSON and CSV (formula-safe). Packet CSV export.
- Multi-tenant isolation, 5 roles, dev auth and OIDC token validation, audit log, retention sweep with legal hold, health/readiness/metrics
- 72 backend tests (including S3 against moto), ruff clean

**Frontend (React, TypeScript, Vite, Tailwind)**

- 11 screens: sign-in, overview, workbench, flows, findings, Command Deck, training, BIG-IP, reports, audit, help/rules
- Light and dark themes, keyboard support in the console, live progress over SSE
- Typecheck, production build, 9 unit tests, Playwright e2e smoke test

**Delivery**

- Docker Compose with network isolation (no-egress worker) and hardened containers
- nginx with CSP, unbuffered uploads and SSE
- CI workflow: backend tests on real MongoDB and tshark, lint, docs drift check, frontend checks, image builds
- Docs: architecture, 6 ADRs, security, operations, API, generated rule/command/mission references

## Not yet implemented

| Item | Impact | Suggested next step |
|---|---|---|
| Browser OIDC sign-in (authorization code + PKCE) | Production SSO needs a front-door proxy (for example oauth2-proxy) until built. The API already validates OIDC tokens. | Add a PKCE flow in the SPA |
| API rate limiting | Relies on a WAF or proxy in front | Add Redis-backed limits for login, upload and console |
| Short-lived SSE stream ticket | The access token travels in the SSE URL. It is redacted from logs. | Issue a 60 s capture-scoped ticket |
| Bookmarks and packet annotations | Index exists, no API or UI | Add CRUD and a Workbench column |
| Legal hold API | Hold is set in the database by an operator | Admin endpoint and UI toggle |
| Tenant and user administration UI | Users come from OIDC claims or the dev seed | Admin screens |
| Azure Blob storage backend | Local and S3 only | Add a backend behind the `Storage` interface |
| Worker metrics, throughput benchmarks | Sizing guidance is empirical | Prometheus metrics from Celery, benchmark on 1M/10M-packet captures |
| Docker image build verified in CI only | This development environment cannot reach Debian or npm from inside a container build. The nginx stage was verified with a local build. | First CI run confirms both images |

## Known limitations

- Detection is only as good as the capture point. Rules state when one capture cannot locate a fault, for example where packets were lost.
- Encrypted payloads (TLS) are not decrypted. Key-log import is not supported.
- Correlation without F5 trailers relies on metadata and timing, and can mis-pair concurrent connections. Each pair states its method and confidence.
