"""Console, missions, gamification, reports, investigations, overview and audit."""

from __future__ import annotations

import datetime as dt
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import FileResponse

from app.console import engine
from app.core.security import Principal, current_principal, require
from app.db import TenantDB, clean
from app.schemas import ConsoleComplete, ConsoleExecute, InvestigationCreate, InvestigationUpdate, MissionSubmit, ReportCreate
from app.services import gamification, investigations, missions, reports, stats

router = APIRouter()
P = Annotated[Principal, Depends(current_principal)]


# ---------------------------------------------------------------- console
@router.post("/console/execute", tags=["console"])
def console_execute(body: ConsoleExecute, principal: Annotated[Principal, Depends(require("console:use"))]):
    return engine.execute(principal, body.line)


@router.post("/console/complete", tags=["console"])
def console_complete(body: ConsoleComplete, principal: Annotated[Principal, Depends(require("console:use"))]):
    return {"completions": engine.complete(principal, body.line)}


@router.get("/console/commands", tags=["console"])
def console_commands(principal: P):
    return [{"name": c.name, "usage": c.usage(), "summary": c.summary, "category": c.category, "permission": c.permission,
             "allowed": principal.can(c.permission), "examples": c.examples} for c in engine.REGISTRY.commands.values()]


# ---------------------------------------------------------------- missions & progress
@router.get("/missions", tags=["missions"])
def list_missions(principal: Annotated[Principal, Depends(require("mission:read"))]):
    return missions.list_missions(principal)


@router.post("/missions/{mission_id}/start", tags=["missions"])
def start_mission(mission_id: str, principal: Annotated[Principal, Depends(require("mission:play"))]):
    return missions.start_mission(principal, mission_id)


@router.get("/missions/active", tags=["missions"])
def active_mission(principal: Annotated[Principal, Depends(require("mission:read"))]):
    return missions.active_run(principal)


@router.post("/missions/active/submit", tags=["missions"])
def submit(body: MissionSubmit, principal: Annotated[Principal, Depends(require("mission:play"))]):
    return missions.submit_answer(principal, body.objective, body.answer)


@router.get("/me/progress", tags=["gamification"])
def progress(principal: Annotated[Principal, Depends(require("profile:read"))]):
    return gamification.profile(principal.tenant_id, principal.user_id)


@router.get("/gamification/catalog", tags=["gamification"])
def catalog(principal: P):
    return {"levels": [{"level": lvl, "name": n, "min_xp": x} for lvl, n, x in gamification.LEVELS],
            "achievements": [{"id": k, "name": v[0], "description": v[1]} for k, v in gamification.ACHIEVEMENTS.items()],
            "note": gamification.LEVEL_NOTE}


# ---------------------------------------------------------------- reports
@router.post("/reports", status_code=201, tags=["reports"])
def create_report(body: ReportCreate, principal: Annotated[Principal, Depends(require("report:create"))]):
    return reports.create_report(principal, body.capture_id, body.format)


@router.get("/reports", tags=["reports"])
def list_reports(principal: Annotated[Principal, Depends(require("report:read"))], capture_id: str | None = None):
    return reports.list_reports(principal, capture_id)


@router.get("/reports/{report_id}/download", tags=["reports"])
def download_report(report_id: str, principal: Annotated[Principal, Depends(require("report:read"))]):
    path, filename, media = reports.report_file(principal, report_id)
    return FileResponse(path, media_type=media, filename=filename,
                        headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'", "Cache-Control": "no-store"})


# ---------------------------------------------------------------- investigations
@router.get("/investigations", tags=["investigations"])
def list_investigations(principal: P, status: str | None = None):
    return investigations.list_investigations(principal, status)


@router.post("/investigations", status_code=201, tags=["investigations"])
def create_investigation(body: InvestigationCreate, principal: Annotated[Principal, Depends(require("investigation:write"))]):
    return investigations.create_investigation(principal, body.title, body.description, body.capture_ids, body.finding_ids, body.severity)


@router.get("/investigations/{inv_id}", tags=["investigations"])
def get_investigation(inv_id: str, principal: P):
    return investigations.get_investigation(principal, inv_id)


@router.patch("/investigations/{inv_id}", tags=["investigations"])
def update_investigation(inv_id: str, body: InvestigationUpdate, principal: Annotated[Principal, Depends(require("investigation:write"))]):
    return investigations.update_investigation(principal, inv_id, status=body.status, title=body.title,
                                               add_capture_ids=body.add_capture_ids, add_finding_ids=body.add_finding_ids, note=body.note)


# ---------------------------------------------------------------- overview & audit
@router.get("/overview", tags=["overview"])
def overview(principal: Annotated[Principal, Depends(require("capture:read"))]):
    return stats.overview(principal)


@router.get("/audit", tags=["audit"])
def audit_events(principal: Annotated[Principal, Depends(require("audit:read"))], action: str | None = Query(None, max_length=64),
                 actor_id: str | None = Query(None, max_length=64), days: int = Query(30, ge=1, le=3650),
                 limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    flt: dict = {"ts": {"$gte": dt.datetime.now(dt.UTC) - dt.timedelta(days=days)}}
    if action:
        flt["action"] = action
    if actor_id:
        flt["actor_id"] = actor_id
    tdb = TenantDB(principal.tenant_id)
    return {"items": [clean(d) for d in tdb.audit_events.find(flt).sort("ts", -1).skip(offset).limit(limit)],
            "total": tdb.audit_events.count_documents(flt)}
