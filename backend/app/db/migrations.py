"""Versioned MongoDB migrations (indexes and seed data).

Run with ``python -m app.db.migrations``. Each migration runs once and is
recorded in ``schema_migrations``; all index operations are idempotent.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from pymongo import ASCENDING as ASC
from pymongo import DESCENDING as DESC
from pymongo import IndexModel
from pymongo.database import Database

from app.db import get_db, utcnow

log = logging.getLogger(__name__)


def m001_core_indexes(db: Database) -> None:
    db.tenants.create_indexes([IndexModel([("slug", ASC)], unique=True)])
    db.users.create_indexes([
        IndexModel([("tenant_id", ASC), ("email", ASC)], unique=True),
        IndexModel([("oidc_issuer", ASC), ("oidc_subject", ASC)], unique=True,
                   partialFilterExpression={"oidc_subject": {"$type": "string"}}),
    ])
    db.captures.create_indexes([
        IndexModel([("tenant_id", ASC), ("created_at", DESC)]),
        IndexModel([("tenant_id", ASC), ("sha256", ASC)]),
        IndexModel([("tenant_id", ASC), ("status", ASC)]),
        IndexModel([("tenant_id", ASC), ("training", ASC), ("created_at", DESC)]),
        IndexModel([("tenant_id", ASC), ("retain_until", ASC)]),
    ])
    db.analysis_jobs.create_indexes([
        IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("created_at", DESC)]),
        IndexModel([("status", ASC), ("updated_at", ASC)]),
        IndexModel([("tenant_id", ASC), ("idempotency_key", ASC)], unique=True),
    ])
    db.packet_summaries.create_indexes([IndexModel([("tenant_id", ASC), ("capture_id", ASC)], unique=True)])
    db.flows.create_indexes([
        IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("local_id", ASC)], unique=True),
        IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("server_ip", ASC), ("server_port", ASC)]),
        IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("client_ip", ASC)]),
        IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("state", ASC)]),
        IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("issue_score", DESC)]),
    ])
    db.findings.create_indexes([
        IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("seq", ASC)], unique=True),
        IndexModel([("tenant_id", ASC), ("status", ASC), ("created_at", DESC)]),
        IndexModel([("tenant_id", ASC), ("rule_id", ASC)]),
        IndexModel([("tenant_id", ASC), ("severity", ASC), ("created_at", DESC)]),
        IndexModel([("tenant_id", ASC), ("assignee", ASC)]),
    ])
    db.evidence_references.create_indexes([
        IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("kind", ASC), ("ref", ASC)]),
        IndexModel([("tenant_id", ASC), ("finding_id", ASC)]),
    ])
    db.f5_configuration_metadata.create_indexes([IndexModel([("tenant_id", ASC), ("name", ASC)], unique=True)])
    db.investigations.create_indexes([
        IndexModel([("tenant_id", ASC), ("created_at", DESC)]),
        IndexModel([("tenant_id", ASC), ("status", ASC)]),
    ])
    db.correlations.create_indexes([IndexModel([("tenant_id", ASC), ("created_at", DESC)])])
    db.user_progress.create_indexes([IndexModel([("tenant_id", ASC), ("user_id", ASC)], unique=True)])
    db.xp_ledger.create_indexes([
        IndexModel([("tenant_id", ASC), ("user_id", ASC), ("event_key", ASC)], unique=True),
        IndexModel([("tenant_id", ASC), ("user_id", ASC), ("created_at", DESC)]),
    ])
    db.mission_runs.create_indexes([IndexModel([("tenant_id", ASC), ("user_id", ASC), ("mission_id", ASC), ("started_at", DESC)])])
    db.audit_events.create_indexes([
        IndexModel([("tenant_id", ASC), ("ts", DESC)]),
        IndexModel([("tenant_id", ASC), ("actor_id", ASC), ("ts", DESC)]),
        IndexModel([("tenant_id", ASC), ("action", ASC), ("ts", DESC)]),
    ])
    db.reports.create_indexes([IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("created_at", DESC)])])
    db.bookmarks.create_indexes([IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("frame", ASC), ("user_id", ASC)])])
    # Console sessions are explicitly temporary: a TTL index expires them.
    db.console_sessions.create_indexes([
        IndexModel([("tenant_id", ASC), ("user_id", ASC)], unique=True),
        IndexModel([("expires_at", ASC)], expireAfterSeconds=0),
    ])


def m002_copilot_and_reports(db: Database) -> None:
    db.ai_syntheses.create_indexes([IndexModel([("tenant_id", ASC), ("capture_id", ASC), ("created_at", DESC)])])
    db.correlations.create_indexes([IndexModel([("tenant_id", ASC), ("server_capture_id", ASC)]),
                                    IndexModel([("tenant_id", ASC), ("created_by", ASC), ("created_at", DESC)])])
    db.reports.create_indexes([IndexModel([("tenant_id", ASC), ("created_by", ASC), ("created_at", DESC)])])


MIGRATIONS: list[tuple[str, Callable[[Database], None]]] = [
    ("001_core_indexes", m001_core_indexes),
    ("002_copilot_and_reports", m002_copilot_and_reports),
]


def migrate(db: Database | None = None) -> list[str]:
    db = db if db is not None else get_db()
    applied = []
    done = {d["_id"] for d in db.schema_migrations.find({}, {"_id": 1})}
    for name, fn in MIGRATIONS:
        if name in done:
            continue
        log.info("applying migration %s", name)
        fn(db)
        db.schema_migrations.insert_one({"_id": name, "applied_at": utcnow()})
        applied.append(name)
    return applied


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("applied:", migrate() or "nothing (up to date)")
