"""Hand analysis jobs to Celery (or run inline in eager mode) and apply post-analysis hooks."""

from __future__ import annotations

import logging

from app.core.config import get_settings
from app.db import TenantDB, utcnow

log = logging.getLogger(__name__)


def run_analysis_job(tenant_id: str, capture_id: str, job_id: str, user_id: str) -> dict:
    from app.analysis.pipeline import analyze_capture
    from app.services import gamification

    tdb = TenantDB(tenant_id)
    job = tdb.analysis_jobs.find_one({"_id": job_id})
    if not job or job.get("status") in ("completed", "cancelled"):
        return {"status": job.get("status") if job else "missing"}  # duplicate delivery: nothing to do
    if job.get("cancel_requested"):
        tdb.analysis_jobs.update_one({"_id": job_id}, {"$set": {"status": "cancelled", "finished_at": utcnow()}})
        return {"status": "cancelled"}
    summary = analyze_capture(tenant_id, capture_id, job_id)
    try:
        gamification.on_capture_analyzed(tenant_id, user_id, capture_id)
    except Exception:  # noqa: BLE001 - gamification must never fail an analysis
        log.exception("gamification hook failed")
    return {"status": "completed", **summary}


def dispatch_analysis(tenant_id: str, capture_id: str, job_id: str, user_id: str) -> None:
    if get_settings().celery_eager:
        try:
            run_analysis_job(tenant_id, capture_id, job_id, user_id)
        except Exception:  # noqa: BLE001 - failure is recorded on the job document
            log.info("inline analysis did not complete", extra={"job_id": job_id})
        return
    from app.worker.tasks import analyze_capture_task

    result = analyze_capture_task.apply_async(args=[tenant_id, capture_id, job_id, user_id], task_id=job_id)
    TenantDB(tenant_id).analysis_jobs.update_one({"_id": job_id}, {"$set": {"celery_task_id": result.id}})


def revoke(task_id: str | None) -> None:
    if not task_id or get_settings().celery_eager:
        return
    from app.worker.celery_app import celery_app

    # The worker also polls the job's cancel flag and kills tshark; revoke stops queued tasks.
    celery_app.control.revoke(task_id)
