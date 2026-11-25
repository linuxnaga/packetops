"""Retention: purge captures whose retain_until has passed (evidence, derived data and reports for that capture)."""

from __future__ import annotations

import logging

from app.core.security import Principal
from app.db import TenantDB, get_db, utcnow
from app.services.captures import delete_capture
from app.storage import get_storage, tenant_key

log = logging.getLogger(__name__)


def purge_expired(limit: int = 500) -> dict:
    db = get_db()
    purged = 0
    for tenant in db.tenants.find({"disabled": {"$ne": True}}, {"_id": 1}):
        tid = tenant["_id"]
        system = Principal(user_id="system:retention", tenant_id=tid, email="retention@system", display_name="Retention job",
                           roles=["admin"])
        tdb = TenantDB(tid)
        for cap in tdb.captures.find({"deleted_at": None, "retain_until": {"$lt": utcnow()}, "legal_hold": {"$ne": True}},
                                     {"_id": 1}).limit(limit):
            try:
                delete_capture(system, cap["_id"])
            except Exception:  # noqa: BLE001 - one bad capture must not stop the sweep
                log.exception("retention purge failed", extra={"capture_id": cap["_id"]})
                continue
            for rep in tdb.reports.find({"capture_id": cap["_id"]}, {"_id": 1}):
                get_storage().delete_prefix(tenant_key(tid, "reports", rep["_id"]))
            tdb.reports.delete_many({"capture_id": cap["_id"]})
            purged += 1
    log.info("retention sweep finished", extra={"purged": purged})
    return {"purged": purged}
