"""Celery application (Redis broker and result backend)."""

from __future__ import annotations

from celery import Celery
from celery.signals import setup_logging

from app.core.config import get_settings
from app.core.logging import configure_logging

settings = get_settings()

celery_app = Celery("packetops", broker=settings.redis_url, backend=settings.redis_url, include=["app.worker.tasks"])
celery_app.conf.update(
    task_acks_late=True,  # a crashed worker's job is redelivered; analysis is idempotent
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_time_limit=settings.analysis_timeout_s + 300,
    task_soft_time_limit=settings.analysis_timeout_s,
    task_default_queue="analysis",
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=86400,
    broker_connection_retry_on_startup=True,
    worker_send_task_events=True,
    task_send_sent_event=True,
    beat_schedule={"retention-sweep": {"task": "packetops.retention_sweep", "schedule": 3600.0, "options": {"queue": "maintenance"}}},
)


@setup_logging.connect
def _logging(**_kwargs) -> None:
    configure_logging(settings.log_level)
