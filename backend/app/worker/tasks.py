"""Background tasks."""

from __future__ import annotations

import logging

from pymongo.errors import AutoReconnect, NetworkTimeout

from app.analysis.pcapfile import MalformedCaptureError
from app.analysis.tshark import AnalysisCancelled
from app.core.logging import job_id_var, tenant_id_var
from app.worker.celery_app import celery_app
from app.worker.dispatch import run_analysis_job

log = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="packetops.analyze_capture",
    autoretry_for=(AutoReconnect, NetworkTimeout, ConnectionError),
    retry_backoff=True,
    retry_backoff_max=300,
    max_retries=3,
)
def analyze_capture_task(self, tenant_id: str, capture_id: str, job_id: str, user_id: str) -> dict:
    tenant_id_var.set(tenant_id)
    job_id_var.set(job_id)
    log.info("analysis task started", extra={"capture_id": capture_id, "attempt": self.request.retries + 1})
    try:
        return run_analysis_job(tenant_id, capture_id, job_id, user_id)
    except (AnalysisCancelled, MalformedCaptureError) as exc:
        log.info("analysis ended without result: %s", type(exc).__name__)
        return {"status": "not_completed", "reason": type(exc).__name__}


@celery_app.task(name="packetops.retention_sweep")
def retention_sweep_task() -> dict:
    from app.services.retention import purge_expired

    return purge_expired()
