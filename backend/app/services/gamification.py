"""XP, levels and achievements.

Design rules:
* XP is granted only for verifiable outcomes, never for running commands.
* Every grant has an idempotency key (unique index on tenant/user/event_key), so
  repeating an action never grants XP twice.
* Gamification reads analysis results but never writes to findings: severity and
  confidence cannot be influenced by XP, levels or achievements.
"""

from __future__ import annotations

import logging

from pymongo.errors import DuplicateKeyError

from app.db import TenantDB, clean, new_id, utcnow

log = logging.getLogger(__name__)

LEVELS = [
    (1, "Packet Rookie", 0),
    (2, "Flow Explorer", 100),
    (3, "TCP Investigator", 300),
    (4, "TLS Analyst", 600),
    (5, "F5 Traffic Engineer", 1000),
    (6, "Packet Forensics Specialist", 1600),
    (7, "Incident Commander", 2500),
]
LEVEL_NOTE = "Levels are platform learning milestones, not professional certification or proof of expertise."

XP = {
    "capture_ingested": 20,
    "investigation_completed": 50,
    "root_cause_validated": 40,
    "report_with_evidence": 30,
    "objective_completed": 10,
    "correlation_matched": 25,
}

ACHIEVEMENTS = {
    "first_capture": ("First Capture", "Successfully ingest and analyse a capture."),
    "handshake_hunter": ("Handshake Hunter", "Complete the TCP handshake mission or confirm a handshake-failure finding."),
    "retransmission_detective": ("Retransmission Detective", "Complete the retransmission mission or confirm a TCP-003 finding."),
    "tls_sleuth": ("TLS Sleuth", "Complete the TLS mission or confirm a TLS finding."),
    "dns_investigator": ("DNS Investigator", "Complete the DNS mission or confirm a DNS finding."),
    "flow_correlator": ("Flow Correlator", "Correlate client-side and server-side flows through a BIG-IP."),
    "evidence_driven": ("Evidence-Driven Analyst", "Confirm five findings with written verification notes."),
    "root_cause_confirmed": ("Root Cause Confirmed", "Confirm the root cause of a finding with verification notes."),
    "forensics_report_complete": ("Forensics Report Complete", "Generate a report that cites packet evidence."),
}

MISSION_ACHIEVEMENTS = {
    "tcp-handshake": "handshake_hunter",
    "retransmission": "retransmission_detective",
    "tls-failure": "tls_sleuth",
    "dns-timeout": "dns_investigator",
    "snat-correlation": "flow_correlator",
    "capture-comparison": "flow_correlator",
}
RULE_ACHIEVEMENTS = {"TCP-001": "handshake_hunter", "TCP-002": "handshake_hunter", "TCP-011": "handshake_hunter",
                     "TCP-003": "retransmission_detective", "TLS-": "tls_sleuth", "DNS-": "dns_investigator"}


def level_for(xp: int) -> dict:
    current = LEVELS[0]
    for lvl in LEVELS:
        if xp >= lvl[2]:
            current = lvl
    idx = LEVELS.index(current)
    nxt = LEVELS[idx + 1] if idx + 1 < len(LEVELS) else None
    return {"level": current[0], "title": current[1], "xp_floor": current[2],
            "next_level_xp": nxt[2] if nxt else None, "next_title": nxt[1] if nxt else None}


def _progress(tdb: TenantDB, user_id: str) -> dict:
    doc = tdb.user_progress.find_one_and_update(
        {"user_id": user_id},
        {"$setOnInsert": {"_id": new_id("prg"), "xp": 0, "xp_training": 0, "achievements": [], "counters": {}, "missions": {},
                          "created_at": utcnow()}},
        upsert=True, return_document=True)
    return doc


def award(tenant_id: str, user_id: str, event: str, key: str, *, mode: str = "production", xp: int | None = None,
          details: dict | None = None) -> dict | None:
    """Grant XP once per (user, event_key). Returns the ledger entry, or None if already granted."""
    tdb = TenantDB(tenant_id)
    amount = XP.get(event, 0) if xp is None else xp
    entry = {"_id": new_id("xp"), "user_id": user_id, "event": event, "event_key": f"{event}:{key}", "xp": amount,
             "mode": mode, "details": details or {}, "created_at": utcnow()}
    try:
        tdb.xp_ledger.insert_one(entry)
    except DuplicateKeyError:
        return None
    _progress(tdb, user_id)
    inc = {"xp": amount, f"counters.{event}": 1}
    if mode == "training":
        inc["xp_training"] = amount
    tdb.user_progress.update_one({"user_id": user_id}, {"$inc": inc, "$set": {"updated_at": utcnow()}})
    return entry


def grant_achievement(tenant_id: str, user_id: str, achievement_id: str, reason: str) -> bool:
    if achievement_id not in ACHIEVEMENTS:
        return False
    tdb = TenantDB(tenant_id)
    _progress(tdb, user_id)
    res = tdb.user_progress.update_one(
        {"user_id": user_id, "achievements.id": {"$ne": achievement_id}},
        {"$push": {"achievements": {"id": achievement_id, "name": ACHIEVEMENTS[achievement_id][0], "reason": reason,
                                    "awarded_at": utcnow()}}})
    return res.modified_count == 1


def on_capture_analyzed(tenant_id: str, user_id: str, capture_id: str) -> None:
    cap = TenantDB(tenant_id).captures.find_one({"_id": capture_id}, {"training": 1, "status": 1})
    if not cap or cap.get("status") != "analyzed":
        return
    if award(tenant_id, user_id, "capture_ingested", capture_id, mode="training" if cap.get("training") else "production"):
        grant_achievement(tenant_id, user_id, "first_capture", f"Capture {capture_id} ingested and analysed")


def on_finding_confirmed(tenant_id: str, user_id: str, finding: dict, note: str) -> None:
    mode = "training" if finding.get("training") else "production"
    if award(tenant_id, user_id, "root_cause_validated", finding["_id"], mode=mode, details={"rule_id": finding["rule_id"]}):
        grant_achievement(tenant_id, user_id, "root_cause_confirmed", f"Confirmed {finding['_id']}")
        for prefix, ach in RULE_ACHIEVEMENTS.items():
            if finding["rule_id"].startswith(prefix):
                grant_achievement(tenant_id, user_id, ach, f"Confirmed {finding['rule_id']} finding")
        prog = TenantDB(tenant_id).user_progress.find_one({"user_id": user_id})
        if prog and prog.get("counters", {}).get("root_cause_validated", 0) >= 5:
            grant_achievement(tenant_id, user_id, "evidence_driven", "Five findings confirmed with verification notes")


def on_report_generated(tenant_id: str, user_id: str, report: dict) -> None:
    if not report.get("evidence_count"):
        return
    # One grant per capture: regenerating reports does not farm XP.
    if award(tenant_id, user_id, "report_with_evidence", report["capture_id"], details={"report_id": report["_id"]}):
        grant_achievement(tenant_id, user_id, "forensics_report_complete", f"Report {report['_id']}")


def on_mission_completed(tenant_id: str, user_id: str, mission: dict) -> dict | None:
    entry = award(tenant_id, user_id, "mission_completed", mission["id"], mode="training", xp=mission["xp"])
    if entry:
        ach = MISSION_ACHIEVEMENTS.get(mission["id"])
        if ach:
            grant_achievement(tenant_id, user_id, ach, f"Mission {mission['id']} completed")
    return entry


def on_correlation(tenant_id: str, user_id: str, correlation_id: str, matched: int) -> None:
    if matched > 0 and award(tenant_id, user_id, "correlation_matched", correlation_id, details={"matched": matched}):
        grant_achievement(tenant_id, user_id, "flow_correlator", f"Correlation {correlation_id} matched {matched} flow pair(s)")


def on_investigation_completed(tenant_id: str, user_id: str, investigation: dict) -> None:
    if investigation.get("finding_ids"):
        award(tenant_id, user_id, "investigation_completed", investigation["_id"])


def profile(tenant_id: str, user_id: str) -> dict:
    tdb = TenantDB(tenant_id)
    prog = _progress(tdb, user_id)
    lvl = level_for(prog.get("xp", 0))
    recent = [clean(d, ("tenant_id", "user_id")) for d in tdb.xp_ledger.find({"user_id": user_id}).sort("created_at", -1).limit(20)]
    earned = {a["id"]: a for a in prog.get("achievements", [])}
    return {
        "user_id": user_id,
        "xp": prog.get("xp", 0),
        "xp_training": prog.get("xp_training", 0),
        **lvl,
        "levels": [{"level": n, "title": t, "xp": x} for n, t, x in LEVELS],
        "level_note": LEVEL_NOTE,
        "achievements": [{"id": k, "name": v[0], "criteria": v[1], "earned": k in earned,
                          "awarded_at": earned[k]["awarded_at"] if k in earned else None} for k, v in ACHIEVEMENTS.items()],
        "missions": prog.get("missions", {}),
        "recent_xp": recent,
    }
