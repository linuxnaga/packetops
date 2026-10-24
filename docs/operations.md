# Operations

## Deployment

`docker-compose.yml` is a complete single-host deployment: nginx frontend, API, worker, beat, MongoDB, Redis and a one-shot `migrate` service. Migrations are idempotent and tracked in the `schema_migrations` collection. In development auth mode, `migrate` also seeds demo tenants and users.

For multi-host or Kubernetes deployments:

- Run the backend image three ways: `uvicorn` (API), `celery … worker -Q analysis,maintenance` and `celery … beat` (exactly one).
- Use S3 storage (`PKO_STORAGE_BACKEND=s3`) so API and workers share evidence.
- Give workers a network policy with no egress except MongoDB, Redis and the object store.
- The API needs egress only to the OIDC JWKS URL and, if enabled, the AI provider.

## Configuration

All settings are environment variables with the `PKO_` prefix (see `backend/app/core/config.py` and `.env.example`).

| Variable | Default | Notes |
|---|---|---|
| `PKO_APP_ENV` | development | `production` enforces OIDC and disables eager mode |
| `PKO_MONGO_URI`, `PKO_MONGO_DB` | localhost / packetops | |
| `PKO_REDIS_URL` | redis://localhost:6379/0 | Celery broker and results |
| `PKO_STORAGE_BACKEND` | local | `local` or `s3` |
| `PKO_STORAGE_LOCAL_ROOT` | ./var/storage | Shared volume in Compose |
| `PKO_S3_ENDPOINT_URL`, `PKO_S3_BUCKET`, `PKO_S3_REGION`, `PKO_S3_ACCESS_KEY`, `PKO_S3_SECRET_KEY`, `PKO_S3_SERVER_SIDE_ENCRYPTION` | – / packetops-evidence / us-east-1 / – / – / AES256 | Omit keys to use the instance role |
| `PKO_WORK_DIR`, `PKO_CACHE_DIR` | ./var/work, ./var/cache | Scratch space and Parquet cache; size for the largest capture |
| `PKO_AUTH_MODE` | dev | `dev` or `oidc` |
| `PKO_OIDC_ISSUER`, `PKO_OIDC_AUDIENCE`, `PKO_OIDC_JWKS_URL`, `PKO_OIDC_CLIENT_ID` | – | |
| `PKO_OIDC_TENANT_CLAIM`, `PKO_OIDC_ROLES_CLAIM`, `PKO_OIDC_EMAIL_CLAIM` | tenant / roles / email | Roles must be one of admin, analyst, investigator, auditor, read_only |
| `PKO_MAX_UPLOAD_BYTES` | 2 GiB | Keep nginx `client_max_body_size` in step |
| `PKO_TENANT_STORAGE_QUOTA_BYTES` | 50 GiB | |
| `PKO_MAX_PACKETS_PER_CAPTURE` | 20,000,000 | Larger captures are rejected with 413 |
| `PKO_MAX_CONCURRENT_ANALYSES_PER_TENANT` | 3 | |
| `PKO_ANALYSIS_TIMEOUT_S` | 3600 | Also bounds tshark CPU time |
| `PKO_TSHARK_MEMORY_LIMIT_BYTES` | 6 GiB | Address-space limit for tshark |
| `PKO_RETENTION_DAYS_DEFAULT` | 90 | Overridden by a tenant's `retention_days` |
| `PKO_REDACT_QUERY_STRINGS` | true | HTTP query strings in flows and findings |
| `PKO_LLM_PROVIDER` | none | `none`, `anthropic` or `openai_compatible` |
| `PKO_LLM_MODEL`, `PKO_LLM_API_KEY`, `PKO_LLM_BASE_URL`, `PKO_LLM_TIMEOUT_S`, `PKO_LLM_REDACT_ADDRESSES` | – / – / – / 60 / true | `anthropic` defaults to `claude-opus-5-5`; `openai_compatible` needs a base URL (vLLM, Ollama, LM Studio) |
| `PKO_CORS_ORIGINS` | localhost:5173, localhost:8080 | Comma-separated |

## Sizing

- Throughput has not been benchmarked yet. Size worker memory from a test run with your largest capture: watch peak RSS of the worker and tshark, and set `PKO_TSHARK_MEMORY_LIMIT_BYTES` and the container limit above it.
- Each analysis needs scratch space in `PKO_WORK_DIR` of about 1.5× the capture size.
- Scale workers horizontally. Concurrency per worker is set with `--concurrency`.

## Retention and deletion

- Each capture gets `retain_until = upload time + retention days`. Beat runs `packetops.retention_sweep` hourly. The sweep deletes expired captures (original, Parquet, flows, findings, evidence references, reports) unless `legal_hold` is true. It writes an audit event per capture.
- Users with `capture:delete` can delete a capture at any time. Deletion is audited.
- Audit events are kept indefinitely. Archive them to WORM storage if your policy requires it.

## Backup and restore

| Data | Backup | Notes |
|---|---|---|
| MongoDB | `mongodump --gzip --archive` nightly, or a managed snapshot | Contains metadata, findings and audit. Encrypt backups. |
| Evidence store | S3 versioning + replication, or a volume snapshot of `evidence` | Originals are the source of truth. Parquet and reports can be regenerated (re-analyse). |
| Redis | Not required | Queue state only. In-flight jobs are retried or can be restarted with "Re-analyse". |

Restore: restore MongoDB, restore the evidence store, then run `migrate`. Captures whose Parquet file is missing can be re-analysed from the original.

## Monitoring

- `GET /healthz` (process alive) and `GET /readyz` (MongoDB and Redis reachable).
- `GET /metrics`: Prometheus metrics (`packetops_http_requests_total`, `packetops_http_request_seconds` by route). Expose it only on an internal network. Analysis outcomes are visible in job documents and logs; there are no worker metrics yet.
- Logs are JSON on stdout with `request_id`, `tenant_id` and `job_id`. Tokens and payloads are never logged.
- Alert on worker health-check failures, a growing `analysis` queue, failed analyses, `readyz` failures and 5xx rates.

## Upgrades

1. Rebuild images (`docker compose build --pull`).
2. `docker compose up -d`. `migrate` runs first and applies new migrations.
3. A tshark upgrade can change dissection. Run the golden-file tests (`tests/test_golden_rules.py`) before rolling out. Re-analyse a capture to apply new rule versions to it.

## Building images behind a restricted network

The backend image installs `tshark` from Debian (`deb.debian.org`) and Python packages from PyPI. The frontend image needs the npm registry. In networks without direct access, point apt, pip and npm at internal mirrors with build arguments or a custom base image.
