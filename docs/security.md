# Security

## Assets

- **Evidence captures.** These may contain credentials, personal data, internal addressing and application payloads.
- **Derived data.** Flows, findings, reports and decoded BIG-IP persistence cookies, which reveal pool members.
- **BIG-IP configuration metadata.**
- **Identities and tokens.**
- **The audit log.**

## Trust boundaries

1. The browser and the API, across the internet or the corporate network.
2. The API and the worker. The worker parses attacker-controlled bytes.
3. The platform and an external AI provider, when one is configured.
4. One tenant and another.

## Threats and mitigations

| Threat | Mitigation | Where |
|---|---|---|
| Malicious capture exploits a dissector bug | tshark runs only with fixed arguments, without a shell, with rlimits (CPU, address space, no file writes, no core). It runs in a worker that is read-only, non-root, has `cap_drop: ALL`, a PID limit and **no network egress** (internal-only network). Wireshark releases are tracked. | `app/analysis/tshark.py`, `docker-compose.yml` |
| Non-capture or bomb uploads | Streaming size limit and tenant quota. Structural pcap/pcapng validation before storage. Packet-count limit rejects with 413. Archives rejected. | `app/analysis/pcapfile.py`, `app/services/captures.py` |
| Command injection through filters or console | The display-filter subset is compiled to Arrow expressions and is never passed to tshark. The console parser matches typed commands from a registry, and no command executes on a host. | `app/services/filters.py`, `app/console/` |
| Cross-tenant data access | `TenantDB` injects the tenant into every operation and rejects cross-tenant inserts. Storage keys are validated per segment. Another tenant's resources return 404. Tested per resource type. | `app/db/__init__.py`, `tests/test_api_security.py` |
| Privilege escalation | Permissions are declared per endpoint and per console command. Five roles. OIDC role claims are filtered to known roles, and anything unknown falls back to read-only. | `app/core/security.py` |
| Payload exposure | Payload bytes are never stored in MongoDB, never logged, never sent to an LLM and never put in reports or finding exports. Viewing stream payload requires `export:data` and is audited. Query strings are redacted by default. | `app/services/packets.py`, `app/services/reports.py` |
| AI fabricates facts or commands | Schema-constrained output. The validator rejects unknown IPs, frames and finding IDs, shell syntax and unmapped placeholders, and falls back to a deterministic synthesis. | `app/ai/copilot.py` |
| Data sent to an AI provider | Disabled by default. Reversible redaction of IPs, hostnames, paths and MACs. Context contains findings only. | `app/ai/redaction.py` |
| Token leakage | Tokens are never logged by application code. A redacting log filter masks bearer tokens and `token=` query parameters, including in uvicorn's access log, which is routed through it. The nginx access log is off for the SSE path. | `app/core/logging.py`, `frontend/nginx.conf` |
| XSS / clickjacking | React escaping. Strict CSP (`script-src 'self'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`, no-referrer. Reports are rendered with Jinja autoescape and carry their own CSP. | `frontend/nginx.conf`, `app/main.py`, `app/templates/report.html` |
| CSV formula injection in exports | Cells starting with `= + - @`, tab or CR are prefixed with a quote (packet and finding exports). | `app/services/packets.py` |
| Repudiation | Append-only audit log for uploads, access, analysis, payload views, exports, triage, F5 config, correlations, reports, missions and dev sign-in, with request IDs. | `audit_events` |
| Evidence tampering | SHA-256 recorded at upload. Originals are write-once. Reports state the capture hash. | `app/services/captures.py` |
| Over-retention | Per-tenant retention (`retain_until`) and an hourly sweep that skips `legal_hold`. | `app/services/retention.py` |

## Known gaps

These are tracked in [status.md](status.md):

- No request rate limiting in the API. Put a rate-limiting proxy or WAF in front for internet-facing deployments.
- The SSE endpoint accepts the access token as a query parameter, because `EventSource` cannot send headers. It is redacted from logs. A short-lived, capture-scoped stream ticket would be better.
- The browser OIDC sign-in flow (authorization code + PKCE) is not built. The API validates OIDC tokens.
- No API to set or clear `legal_hold`. It is set in the database by an operator.
- No malware scanning of uploads. Captures are parsed only in the isolated worker and are never executed.

## Hardening checklist (production)

- [ ] `PKO_APP_ENV=production`, `PKO_AUTH_MODE=oidc` (startup refuses dev auth and eager Celery in production)
- [ ] OIDC issuer, audience and JWKS URL set. Tenant and role claims mapped (`PKO_OIDC_TENANT_CLAIM`, `PKO_OIDC_ROLES_CLAIM`).
- [ ] TLS terminated in front of nginx, with HSTS at that proxy
- [ ] Rate limiting / WAF in front of `/api`
- [ ] `PKO_CORS_ORIGINS` limited to the real UI origin
- [ ] Evidence on S3 with SSE-KMS, bucket versioning and Object Lock if required. Public access blocked.
- [ ] MongoDB with authentication, TLS and encrypted volumes. Redis with a password, never published.
- [ ] Worker on a network with no egress (default Compose layout). Verify with `docker compose exec worker python -c "import urllib.request; urllib.request.urlopen('https://example.com', timeout=3)"`, which must fail.
- [ ] Resource limits sized for the largest expected capture (`PKO_TSHARK_MEMORY_LIMIT_BYTES`, worker memory, tmpfs size)
- [ ] `PKO_LLM_PROVIDER=none` unless approved. If enabled, keep `PKO_LLM_REDACT_ADDRESSES=true` and prefer a self-hosted model.
- [ ] Retention days set per tenant. Backups encrypted, with restores tested (see [operations.md](operations.md)).
- [ ] Logs shipped to a SIEM. Alerts on `capture.payload_view`, `export.*` and repeated 403s.
- [ ] Images rebuilt on Wireshark and base-image security releases
