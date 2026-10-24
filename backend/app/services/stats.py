"""Capture statistics and the tenant overview dashboard."""

from __future__ import annotations

import datetime as dt
from collections import Counter

from app.core.errors import ApiError
from app.core.security import Principal
from app.db import TenantDB, clean, utcnow
from app.services import gamification
from app.services.captures import get_capture


def capture_summary(principal: Principal, capture_id: str) -> dict:
    get_capture(principal, capture_id)
    doc = TenantDB(principal.tenant_id).packet_summaries.find_one({"capture_id": capture_id})
    if not doc:
        raise ApiError(409, "not_analyzed", "Capture has not been analysed yet")
    return clean(doc)


def overview(principal: Principal) -> dict:
    tdb = TenantDB(principal.tenant_id)
    recent = [clean(d, ("tenant_id", "storage_key", "derived_key")) for d in tdb.captures.find(
        {"deleted_at": None}, {"filename": 1, "status": 1, "created_at": 1, "stats": 1, "training": 1, "size_bytes": 1, "sha256": 1}
    ).sort("created_at", -1).limit(8)]
    status_counts = {d["_id"]: d["n"] for d in tdb.captures.aggregate(
        [{"$match": {"deleted_at": None}}, {"$group": {"_id": "$status", "n": {"$sum": 1}}}])}
    active_jobs = [clean(d) for d in tdb.analysis_jobs.find({"status": {"$in": ["queued", "running"]}}).sort("created_at", -1).limit(10)]
    analyzed_ids = [c["id"] for c in recent if c["status"] == "analyzed" and not c.get("training")][:5]
    protocols: Counter = Counter()
    endpoints: Counter = Counter()
    for s in tdb.packet_summaries.find({"capture_id": {"$in": analyzed_ids}}, {"protocols": 1, "endpoints": 1}):
        for p in s.get("protocols", []):
            protocols[p["name"]] += p["packets"]
        for e in s.get("endpoints", [])[:20]:
            endpoints[e["ip"]] += e["bytes_tx"] + e["bytes_rx"]
    top_findings = [clean(d) for d in tdb.findings.find(
        {"status": {"$in": ["open", "investigating"]}, "severity": {"$in": ["critical", "high"]}, "training": False},
        {"title": 1, "severity": 1, "confidence": 1, "rule_id": 1, "capture_id": 1, "short_id": 1, "status": 1, "created_at": 1},
    ).sort("created_at", -1).limit(10)]
    since = utcnow() - dt.timedelta(days=14)
    activity = [{"day": d["_id"], "events": d["n"]} for d in tdb.audit_events.aggregate([
        {"$match": {"ts": {"$gte": since}}},
        {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$ts"}}, "n": {"$sum": 1}}},
        {"$sort": {"_id": 1}}])]
    investigations = [clean(d) for d in tdb.investigations.find({"status": {"$ne": "closed"}}).sort("updated_at", -1).limit(5)]
    severity_counts = {d["_id"]: d["n"] for d in tdb.findings.aggregate(
        [{"$match": {"training": False}}, {"$group": {"_id": "$severity", "n": {"$sum": 1}}}])}
    return {
        "recent_captures": recent,
        "capture_status": status_counts,
        "active_jobs": active_jobs,
        "protocol_distribution": [{"name": k, "packets": v} for k, v in protocols.most_common(12)],
        "protocol_scope": f"latest {len(analyzed_ids)} analysed evidence capture(s)",
        "top_endpoints": [{"ip": k, "bytes": v} for k, v in endpoints.most_common(10)],
        "top_findings": top_findings,
        "finding_severity": severity_counts,
        "activity": activity,
        "active_investigations": investigations,
        "profile": gamification.profile(principal.tenant_id, principal.user_id),
    }
