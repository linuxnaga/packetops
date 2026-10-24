"""Findings: listing, triage workflow (status, assignment, notes) and evidence resolution."""

from __future__ import annotations

import re

from app.analysis.rules import get_rule
from app.core.errors import ApiError, not_found
from app.core.security import Principal
from app.db import TenantDB, clean, new_id, utcnow
from app.services import gamification
from app.services.audit import audit
from app.services.captures import get_capture
from app.services.packets import query_packets

STATUSES = ("open", "investigating", "confirmed", "dismissed", "resolved")
SHORT_ID = re.compile(r"^F\d{1,6}$", re.I)
GLOBAL_ID = re.compile(r"^(cap_[0-9a-f]{20})-(F\d{1,6})$")
LIST_PROJECTION = {"timeline": 0, "packets": 0, "tuples": 0, "verification": 0, "remediation": 0}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def resolve_finding_id(capture_id: str | None, finding_id: str) -> str:
    if SHORT_ID.match(finding_id):
        if not capture_id:
            raise ApiError(400, "capture_required", "Select a capture to use short finding ids like F3")
        return f"{capture_id}-{finding_id.upper()}"
    if GLOBAL_ID.match(finding_id):
        return finding_id
    raise ApiError(400, "invalid_finding_id", "Finding ids look like F3 or cap_<id>-F3")


def list_findings(principal: Principal, *, capture_id: str | None = None, severity: str | None = None, status: str | None = None,
                  rule_id: str | None = None, category: str | None = None, confidence: str | None = None,
                  assignee: str | None = None, training: bool | None = None, limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
    flt: dict = {}
    if capture_id:
        get_capture(principal, capture_id)
        flt["capture_id"] = capture_id
    for key, val in (("severity", severity), ("status", status), ("category", category), ("confidence.level", confidence),
                     ("assignee", assignee)):
        if val:
            flt[key] = val
    if rule_id:
        flt["rule_id"] = rule_id.upper()
    if training is not None:
        flt["training"] = training
    tdb = TenantDB(principal.tenant_id)
    total = tdb.findings.count_documents(flt)
    sort = [("seq", 1)] if capture_id else [("created_at", -1), ("seq", 1)]
    docs = [clean(d) for d in tdb.findings.find(flt, LIST_PROJECTION).sort(sort).skip(offset).limit(limit)]
    return docs, total


def get_finding(principal: Principal, finding_id: str, capture_id: str | None = None) -> dict:
    fid = resolve_finding_id(capture_id, finding_id)
    doc = TenantDB(principal.tenant_id).findings.find_one({"_id": fid})
    if not doc:
        raise not_found("Finding")
    out = clean(doc)
    rule = get_rule(doc["rule_id"])
    out["rule"] = rule.to_dict() if rule else None
    return out


def update_finding(principal: Principal, finding_id: str, *, status: str | None = None, assignee: str | None = None,
                   note: str | None = None, capture_id: str | None = None) -> dict:
    principal.require("finding:update")
    fid = resolve_finding_id(capture_id, finding_id)
    tdb = TenantDB(principal.tenant_id)
    doc = tdb.findings.find_one({"_id": fid})
    if not doc:
        raise not_found("Finding")
    update: dict = {"$set": {"updated_at": utcnow(), "updated_by": principal.user_id}}
    if status:
        if status not in STATUSES:
            raise ApiError(400, "invalid_status", f"status must be one of {', '.join(STATUSES)}")
        if status == "confirmed" and (not note or len(note.strip()) < 20):
            raise ApiError(400, "verification_required",
                           "Confirming a root cause requires a note (20+ characters) describing how it was verified")
        update["$set"]["status"] = status
    if assignee is not None:
        assignee = assignee.strip()[:200]
        if assignee and not tdb.users.find_one({"$or": [{"_id": assignee}, {"email": assignee}]}, {"_id": 1}):
            raise ApiError(400, "invalid_assignee", "Assignee must be a user in your tenant")
        update["$set"]["assignee"] = assignee or None
    if note:
        update["$push"] = {"notes": {"id": new_id("note"), "author_id": principal.user_id, "author": principal.display_name,
                                     "text": note.strip()[:4000], "created_at": utcnow(), "status_change": status}}
    tdb.findings.update_one({"_id": fid}, update)
    audit(principal, "finding.update", "finding", fid, {"status": status, "assignee": assignee, "note": bool(note)})
    if status == "confirmed" and doc.get("status") != "confirmed":
        gamification.on_finding_confirmed(principal.tenant_id, principal.user_id, doc, note or "")
    return get_finding(principal, fid)


def finding_evidence(principal: Principal, finding_id: str, capture_id: str | None = None) -> dict:
    """Resolve a finding's evidence references to concrete packets, flows and the rule that produced it."""
    f = get_finding(principal, finding_id, capture_id)
    frames = [p["frame"] for p in f.get("packets", [])][:200]
    roles = {p["frame"]: p.get("role") for p in f.get("packets", [])}
    packets = query_packets(principal, f["capture_id"], frames=frames, limit=200)["items"] if frames else []
    for p in packets:
        p["role"] = roles.get(p["number"])
    tdb = TenantDB(principal.tenant_id)
    flows = [clean(d) for d in tdb.flows.find({"capture_id": f["capture_id"], "local_id": {"$in": f.get("flows", [])[:50]}},
                                              {"timeline": 1, "local_id": 1, "client_ip": 1, "client_port": 1, "server_ip": 1,
                                               "server_port": 1, "state": 1, "transport": 1})]
    return {"finding": f, "packets": packets, "flows": flows, "rule": f.get("rule"),
            "observations": f.get("observations", []), "missing_evidence": f.get("missing_evidence", [])}


def sort_key(f: dict) -> tuple:
    return SEVERITY_ORDER.get(f.get("severity"), 9), f.get("seq", 0)


EXPORT_COLUMNS = ["id", "rule_id", "rule_version", "severity", "confidence", "confidence_score", "status", "title", "summary",
                  "probable_cause", "flows", "evidence_frames", "assignee", "training"]


def export_findings(principal: Principal, capture_id: str, fmt: str = "json") -> tuple[bytes, str]:
    """Findings without payloads: facts, interpretation and evidence frame numbers only."""
    import csv
    import io
    import json

    from app.services.packets import _csv_safe

    principal.require("export:data")
    if fmt not in ("json", "csv"):
        raise ApiError(400, "invalid_format", "format must be json or csv")
    cap = get_capture(principal, capture_id)
    docs = list(TenantDB(principal.tenant_id).findings.find({"capture_id": capture_id}).sort("seq", 1))
    audit(principal, "findings.export", "capture", capture_id, {"format": fmt, "count": len(docs)})
    if fmt == "json":
        out = {"capture": {"id": cap["_id"], "filename": cap["filename"], "sha256": cap["sha256"], "training": cap.get("training", False)},
               "exported_at": utcnow().isoformat(), "payloads_included": False,
               "findings": [{k: v for k, v in clean(d).items() if k not in ("analysis_job_id",)} for d in docs]}
        return json.dumps(out, default=str, indent=2).encode(), "application/json"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(EXPORT_COLUMNS)
    for d in docs:
        w.writerow([_csv_safe(v) for v in (
            d["short_id"], d["rule_id"], d["rule_version"], d["severity"], d["confidence"]["level"], d["confidence"]["score"],
            d["status"], d["title"], d["summary"], d["probable_cause"], " ".join(d.get("flows", [])),
            " ".join(str(p["frame"]) for p in d.get("packets", [])), d.get("assignee") or "", d.get("training", False))])
    return buf.getvalue().encode(), "text/csv"
