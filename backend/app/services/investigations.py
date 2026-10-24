"""Investigations: a case that groups captures and findings, with a status, owner and an append-only notes log."""

from __future__ import annotations

from app.core.errors import ApiError, not_found
from app.core.security import Principal
from app.db import TenantDB, clean, new_id, utcnow
from app.services import gamification
from app.services.audit import audit

STATUSES = ("open", "in_progress", "resolved", "closed")


def _get(tdb: TenantDB, inv_id: str) -> dict:
    doc = tdb.investigations.find_one({"_id": inv_id})
    if not doc:
        raise not_found("Investigation")
    return doc


def _check_refs(tdb: TenantDB, capture_ids: list[str], finding_ids: list[str]) -> None:
    if capture_ids and tdb.captures.count_documents({"_id": {"$in": capture_ids}, "deleted_at": None}) != len(set(capture_ids)):
        raise ApiError(400, "invalid_reference", "One or more captures do not exist in your tenant")
    if finding_ids and tdb.findings.count_documents({"_id": {"$in": finding_ids}}) != len(set(finding_ids)):
        raise ApiError(400, "invalid_reference", "One or more findings do not exist in your tenant")


def create_investigation(principal: Principal, title: str, description: str = "", capture_ids: list[str] | None = None,
                         finding_ids: list[str] | None = None, severity: str | None = None) -> dict:
    principal.require("investigation:write")
    tdb = TenantDB(principal.tenant_id)
    capture_ids, finding_ids = list(dict.fromkeys(capture_ids or [])), list(dict.fromkeys(finding_ids or []))
    _check_refs(tdb, capture_ids, finding_ids)
    title = title.strip()
    if not 3 <= len(title) <= 200:
        raise ApiError(400, "invalid_title", "Title must be 3-200 characters")
    doc = {"_id": new_id("inv"), "title": title, "description": description[:5000], "status": "open", "severity": severity,
           "capture_ids": capture_ids, "finding_ids": finding_ids, "owner_id": principal.user_id, "notes": [],
           "created_by": principal.user_id, "created_at": utcnow(), "updated_at": utcnow()}
    tdb.investigations.insert_one(doc)
    audit(principal, "investigation.create", "investigation", doc["_id"])
    return clean(doc)


def list_investigations(principal: Principal, status: str | None = None, limit: int = 50) -> list[dict]:
    principal.require("investigation:read")
    flt = {"status": status} if status else {}
    return [clean(d, ("tenant_id", "notes")) for d in TenantDB(principal.tenant_id).investigations.find(flt).sort("updated_at", -1).limit(limit)]


def get_investigation(principal: Principal, inv_id: str) -> dict:
    principal.require("investigation:read")
    return clean(_get(TenantDB(principal.tenant_id), inv_id))


def update_investigation(principal: Principal, inv_id: str, *, status: str | None = None, title: str | None = None,
                         add_capture_ids: list[str] | None = None, add_finding_ids: list[str] | None = None,
                         note: str | None = None) -> dict:
    principal.require("investigation:write")
    tdb = TenantDB(principal.tenant_id)
    inv = _get(tdb, inv_id)
    upd: dict = {"$set": {"updated_at": utcnow()}}
    if status:
        if status not in STATUSES:
            raise ApiError(400, "invalid_status", f"status must be one of {', '.join(STATUSES)}")
        upd["$set"]["status"] = status
    if title:
        upd["$set"]["title"] = title.strip()[:200]
    _check_refs(tdb, add_capture_ids or [], add_finding_ids or [])
    add = {}
    if add_capture_ids:
        add["capture_ids"] = {"$each": add_capture_ids}
    if add_finding_ids:
        add["finding_ids"] = {"$each": add_finding_ids}
    if add:
        upd["$addToSet"] = add
    if note:
        upd["$push"] = {"notes": {"at": utcnow(), "author_id": principal.user_id, "author_email": principal.email, "text": note[:5000]}}
    tdb.investigations.update_one({"_id": inv_id}, upd)
    doc = _get(tdb, inv_id)
    audit(principal, "investigation.update", "investigation", inv_id, {"status": status, "note": bool(note)})
    if status in ("resolved", "closed") and inv["status"] not in ("resolved", "closed"):
        gamification.on_investigation_completed(principal.tenant_id, principal.user_id, doc)
    return clean(doc)
