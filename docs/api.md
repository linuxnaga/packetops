# API overview

The REST API is served under `/api/v1`. Interactive OpenAPI docs are at `/api/docs` and the schema at `/api/openapi.json`.

## Conventions

- **Auth.** `Authorization: Bearer <token>`. The token is an OIDC access token in production, or a dev token from `POST /auth/dev-login` in development. `GET /captures/{id}/events` (SSE) also accepts `?access_token=`, because `EventSource` cannot set headers.
- **Errors.** `{"error": {"code", "message", "details", "request_id"}}` with a matching HTTP status. Resources of another tenant return 404.
- **IDs.** Prefixed and opaque: `cap_…`, `f5c_…`, `cor_…`, `rep_…`, `run_…`. Flows are addressed by local ID (`t3`, `u1`) within a capture. Findings have a short ID (`F2`) within a capture.
- **Paging.** `limit` and `offset`. Responses are `{items, total}`.
- **Uploads.** `POST /captures` takes the raw file as the request body (`Content-Type: application/octet-stream`, `X-Filename` header). Multipart is rejected with 415. Optional query: `capture_point`, `description`.

## Endpoints

| Area | Method and path | Permission |
|---|---|---|
| Auth | `POST /auth/dev-login`, `GET /auth/config`, `GET /auth/me` | none / none / any |
| Captures | `POST /captures`, `GET /captures`, `GET/DELETE /captures/{id}` | capture:upload / capture:read / capture:delete |
| Analysis | `POST /captures/{id}/analyze`, `POST /captures/{id}/cancel`, `GET /captures/{id}/status`, `GET /captures/{id}/events`, `GET /captures/{id}/jobs` | analysis:run / capture:read |
| Packets | `GET /captures/{id}/packets?filter=`, `GET /captures/{id}/packets/{frame}`, `GET /captures/{id}/packets/export` | capture:read / export:data |
| Flows | `GET /captures/{id}/flows`, `GET /captures/{id}/graph`, `GET /captures/{id}/flows/{flow}`, `…/sequence`, `…/payload` | capture:read / payload: export:data (audited) |
| Summary | `GET /captures/{id}/summary`, `GET /overview` | capture:read |
| Findings | `GET /captures/{id}/findings`, `GET /captures/{id}/findings/export?format=json\|csv`, `GET /findings`, `GET/PATCH /findings/{id}`, `GET /findings/{id}/evidence` | finding:read / export:data / finding:update |
| Rules | `GET /rules`, `GET /rules/{rule_id}` | any |
| Copilot | `POST/GET /captures/{id}/copilot` | finding:read |
| BIG-IP | `GET/POST /f5/configs`, `GET/DELETE /f5/configs/{id}`, `POST/GET /f5/correlations`, `GET /f5/correlations/{id}` | f5config:read / f5config:write / correlation:run |
| Console | `POST /console/execute`, `POST /console/complete`, `GET /console/commands` | console:use, plus the command's own permission |
| Training | `GET /missions`, `POST /missions/{id}/start`, `GET /missions/active`, `POST /missions/active/submit`, `GET /me/progress`, `GET /gamification/catalog` | mission:read / mission:play / profile:read |
| Reports | `POST /reports`, `GET /reports`, `GET /reports/{id}/download` | report:create / report:read |
| Investigations | `GET/POST /investigations`, `GET/PATCH /investigations/{id}` | investigation:read / investigation:write |
| Audit | `GET /audit?action=&actor_id=&days=` | audit:read |

## Roles

| Role | Adds to read access |
|---|---|
| read_only | none (capture, finding, report, investigation, F5 config and mission read; console; profile) |
| auditor | audit:read |
| investigator | upload, analyse, triage findings, reports, correlation, investigations, missions |
| analyst | investigator + delete captures, export data, write F5 config |
| admin | analyst + audit, tenant and user administration |

## Example

```bash
TOKEN=$(curl -s -X POST localhost:8080/api/v1/auth/dev-login -H 'content-type: application/json' \
  -d '{"email":"analyst@acme.example"}' | jq -r .access_token)
curl -s -X POST "localhost:8080/api/v1/captures?capture_point=client-side" \
  -H "Authorization: Bearer $TOKEN" -H "X-Filename: incident.pcapng" \
  -H 'content-type: application/octet-stream' --data-binary @incident.pcapng | jq '.capture.id, .job.status'
curl -s "localhost:8080/api/v1/captures/$CAP/packets?filter=tcp.flags.reset%20%3D%3D%201&limit=20" -H "Authorization: Bearer $TOKEN"
curl -s -X POST localhost:8080/api/v1/console/execute -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"line":"tcp handshakes"}'
```
