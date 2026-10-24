"""FastAPI application: middleware, health/readiness, metrics and the versioned API."""

from __future__ import annotations

import logging
import shutil
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app.api.v1 import api_router
from app.core.config import get_settings
from app.core.errors import install_error_handlers
from app.core.logging import configure_logging, request_id_var, tenant_id_var
from app.db import get_db

settings = get_settings()
configure_logging(settings.log_level)
log = logging.getLogger("packetops.http")

REQUESTS = Counter("packetops_http_requests_total", "HTTP requests", ["method", "route", "status"])
LATENCY = Histogram("packetops_http_request_seconds", "HTTP request latency", ["method", "route"],
                    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30))

app = FastAPI(title=settings.api_title, version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
install_error_handlers(app)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type", "X-Filename",
                                                                                  "X-Request-ID"])

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


@app.middleware("http")
async def request_context(request: Request, call_next):
    rid = request.headers.get("x-request-id", "")
    rid = rid if rid.replace("-", "").isalnum() and len(rid) <= 64 else uuid.uuid4().hex
    token = request_id_var.set(rid)
    tenant_id_var.set(None)
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
    finally:
        route = request.scope.get("route")
        template = getattr(route, "path", "unmatched")
        elapsed = time.perf_counter() - start
        REQUESTS.labels(request.method, template, str(status)).inc()
        LATENCY.labels(request.method, template).observe(elapsed)
        if template not in ("/healthz", "/metrics"):
            log.info("request", extra={"method": request.method, "route": template, "status": status,
                                       "duration_ms": round(elapsed * 1000, 1)})
        request_id_var.reset(token)
    response.headers["X-Request-ID"] = rid
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


@app.get("/readyz", include_in_schema=False)
def readyz():
    checks: dict[str, str] = {}
    try:
        get_db().command("ping")
        checks["mongodb"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["mongodb"] = f"error: {type(exc).__name__}"
    if not settings.celery_eager:
        try:
            import redis

            redis.Redis.from_url(settings.redis_url, socket_timeout=2).ping()
            checks["redis"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["redis"] = f"error: {type(exc).__name__}"
    checks["tshark"] = "ok" if shutil.which("tshark") else "missing"
    ok = all(v == "ok" for v in checks.values())
    return JSONResponse({"status": "ready" if ok else "not_ready", "checks": checks}, status_code=200 if ok else 503)


@app.get("/metrics", include_in_schema=False)
def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


app.include_router(api_router)
