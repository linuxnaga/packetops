# F5 PacketOps

PCAP forensics and network troubleshooting for teams that run F5 BIG-IP. Upload a capture, inspect packets and conversations, get findings that cite the frames they rest on, correlate client-side and server-side connections through a BIG-IP, and practise on guided training missions in a terminal-style Command Deck.

Everything shown comes from the capture. Findings come from deterministic, versioned rules. The optional AI copilot only summarises those findings, and its output is checked against the evidence before anyone sees it.

| Screen | What it does |
|---|---|
| Overview | Analysed captures, open findings by severity, protocol mix, top endpoints, running jobs |
| PCAP Workbench | Streaming upload with SHA-256, live analysis progress, packet table with display filters, full dissection tree and hex dump |
| Flow Explorer | Host graph, conversations ranked by issues, per-flow sequence chart and timeline |
| Findings | Facts with frame links, interpretation, alternatives, confidence, verification commands, remediation, missing evidence, triage, copilot synthesis, JSON/CSV export |
| Command Deck | A terminal for real commands (`tcp handshakes`, `flow inspect t3`, `f5 correlate`, `report generate` …) with completion, history and prompts |
| Training | 10 missions on synthetic captures, XP, 7 levels, 9 achievements |
| BIG-IP | Import `tmsh`/`bigip.conf` metadata, pair client-side and server-side flows (F5 trailer, config + timing, or timing only) |
| Reports | HTML, PDF and JSON reports with methodology, limitations, evidence and reproducible filters |
| Audit log | Append-only record of security-relevant actions (admins and auditors) |

## Quick start (Docker Compose)

Requirements: Docker 24+ with Compose v2, 4 CPU cores and 8 GB RAM for the worker.

```bash
cp .env.example .env
# Set PKO_DEV_JWT_SECRET to a random value of at least 32 bytes:
sed -i "s/^PKO_DEV_JWT_SECRET=.*/PKO_DEV_JWT_SECRET=$(openssl rand -hex 32)/" .env
docker compose up --build -d
```

Open http://localhost:8080 and sign in as `analyst@acme.example`. In development mode the `migrate` service seeds two tenants (`acme`, `globex`) with one user per role: `admin@`, `analyst@`, `investigator@`, `auditor@`, `read-only@` (for example `auditor@acme.example`). API docs are at http://localhost:8080/api/docs.

Development sign-in is refused when `PKO_APP_ENV=production`. Production uses OIDC; see [docs/operations.md](docs/operations.md).

## Local development

Backend (Python 3.12+, tshark 4.x on `PATH`, MongoDB 7 and Redis 7 reachable):

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m app.db.migrations && python -m app.seed
PKO_CELERY_EAGER=true uvicorn app.main:app --reload --port 8000   # eager mode runs analysis in-process
# or, with a real worker:
celery -A app.worker.celery_app:celery_app worker -Q analysis,maintenance -l INFO
```

Frontend (Node 22):

```bash
cd frontend
npm ci
PKO_API_URL=http://localhost:8000 npm run dev    # http://localhost:5173, proxies /api
```

## Tests

```bash
# Backend: unit, golden-file rule tests on real captures, API security (RBAC, tenant isolation), reports, copilot validation
cd backend && python -m pytest -q && ruff check app tests

# Frontend: typecheck, unit tests, production build
cd frontend && npm run typecheck && npm test && npm run build

# Browser end-to-end: sign in, upload, packets, flows, findings, console, a training mission, a report.
# Needs the API and the web app running and Playwright's Chromium installed.
PKO_WEB_URL=http://localhost:5173 PKO_E2E_PCAP=/path/to/capture.pcapng node frontend/e2e/smoke.mjs
```

Integration tests skip themselves when MongoDB or tshark is not available.

## Repository layout

```
backend/
  app/analysis/     capture validation, tshark extraction, flow aggregation, detection rules
  app/console/      Command Deck parser, registry and command handlers
  app/ai/           copilot: providers, redaction, output validation
  app/services/     captures, findings, F5 correlation, missions, gamification, reports, retention
  app/api/v1/       REST API (FastAPI)
  app/worker/       Celery app and tasks
  fixtures/training synthetic mission captures (labelled SYNTHETIC)
  tests/            pytest suite
frontend/           React + TypeScript + Vite + Tailwind SPA, nginx config, e2e smoke test
docs/               architecture, ADRs, security, operations, API, generated references
```

## Documentation

- [Architecture and data model](docs/architecture.md), with [ADRs](docs/adr/)
- [Security: threat model and hardening checklist](docs/security.md)
- [Operations: deployment, configuration, retention, backup, monitoring](docs/operations.md)
- [API overview](docs/api.md)
- Generated from code: [detection rules](docs/rules.md), [Command Deck commands](docs/console.md), [training missions](docs/missions.md)
- [Project status: what is implemented and what is not yet](docs/status.md)

## Licence

Proprietary; all rights reserved unless a licence file says otherwise. F5 and BIG-IP are trademarks of F5, Inc. This project is not affiliated with or endorsed by F5, Inc.
