"""Findings across captures, triage workflow, evidence, rule catalog and copilot synthesis."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.ai.copilot import synthesize
from app.analysis.rules import get_rule, rule_catalog
from app.core.errors import not_found
from app.core.security import Principal, current_principal, require
from app.db import TenantDB, clean
from app.schemas import FindingUpdate
from app.services import findings as find_svc

router = APIRouter(tags=["findings"])
P = Annotated[Principal, Depends(current_principal)]


@router.get("/findings")
def list_findings(principal: P, capture_id: str | None = Query(None, pattern=r"^cap_[0-9a-f]{20}$"),
                  severity: str | None = None, status: str | None = None, rule_id: str | None = Query(None, max_length=20),
                  category: str | None = None, confidence: str | None = None, assignee: str | None = None,
                  training: bool | None = None, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    principal.require("finding:read")
    items, total = find_svc.list_findings(principal, capture_id=capture_id, severity=severity, status=status, rule_id=rule_id,
                                          category=category, confidence=confidence, assignee=assignee, training=training,
                                          limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, principal: P):
    principal.require("finding:read")
    return find_svc.get_finding(principal, finding_id)


@router.patch("/findings/{finding_id}")
def update_finding(finding_id: str, body: FindingUpdate, principal: Annotated[Principal, Depends(require("finding:update"))]):
    return find_svc.update_finding(principal, finding_id, status=body.status, assignee=body.assignee, note=body.note)


@router.get("/findings/{finding_id}/evidence")
def finding_evidence(finding_id: str, principal: P):
    principal.require("finding:read")
    return find_svc.finding_evidence(principal, finding_id)


@router.get("/rules")
def rules(principal: P):
    return [m.to_dict() for m in rule_catalog()]


@router.get("/rules/{rule_id}")
def rule(rule_id: str, principal: P):
    r = get_rule(rule_id.upper())
    if not r:
        raise not_found("Rule")
    return r.to_dict()


@router.post("/captures/{capture_id}/copilot", summary="AI synthesis over the capture's findings (validated against evidence)")
def copilot(capture_id: str, principal: Annotated[Principal, Depends(require("finding:read"))]):
    return synthesize(principal, capture_id)


@router.get("/captures/{capture_id}/copilot")
def copilot_history(capture_id: str, principal: Annotated[Principal, Depends(require("finding:read"))]):
    cur = TenantDB(principal.tenant_id).ai_syntheses.find({"capture_id": capture_id}, {"rejected_output": 0}).sort("created_at", -1).limit(10)
    return [clean(d) for d in cur]
