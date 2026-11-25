"""Audit trail for security-relevant actions (uploads, exports, access, deletion, configuration)."""

from __future__ import annotations

import logging

from app.core.logging import request_id_var
from app.core.security import Principal
from app.db import TenantDB, new_id, utcnow

log = logging.getLogger("packetops.audit")


def audit(principal: Principal | None, action: str, resource_type: str, resource_id: str | None = None,
          details: dict | None = None, tenant_id: str | None = None, outcome: str = "success") -> None:
    tid = principal.tenant_id if principal else tenant_id
    if not tid:
        return
    doc = {
        "_id": new_id("aud"),
        "ts": utcnow(),
        "actor_id": principal.user_id if principal else "system",
        "actor_email": principal.email if principal else "system",
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "details": details or {},
        "request_id": request_id_var.get(),
    }
    TenantDB(tid).audit_events.insert_one(doc)
    log.info("audit", extra={"action": action, "resource_type": resource_type, "resource_id": resource_id, "outcome": outcome})
