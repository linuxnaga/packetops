"""Captures: upload, analysis lifecycle, packets, conversations, findings of one capture."""

from __future__ import annotations

import asyncio
import json
from typing import Annotated

import anyio
from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import Response, StreamingResponse

from app.core.errors import ApiError
from app.core.security import Principal, current_principal, require
from app.db import TenantDB, clean
from app.schemas import AnalyzeRequest
from app.services import captures as cap_svc
from app.services import findings as find_svc
from app.services import flows as flow_svc
from app.services import packets as pkt_svc
from app.services import stats as stats_svc

router = APIRouter(prefix="/captures", tags=["captures"])
P = Annotated[Principal, Depends(current_principal)]
TERMINAL_JOB = {"completed", "failed", "cancelled"}
HIDDEN = ("tenant_id", "storage_key", "derived_key")


def _public(doc: dict) -> dict:
    return clean(doc, HIDDEN)


@router.post("", status_code=201, summary="Upload a PCAP/PCAPNG (raw body, Content-Type application/octet-stream)")
async def upload_capture(
    request: Request,
    principal: Annotated[Principal, Depends(require("capture:upload"))],
    x_filename: Annotated[str | None, Header(max_length=255)] = None,
    description: Annotated[str | None, Query(max_length=500)] = None,
    capture_point: Annotated[str | None, Query(pattern="^(client-side|server-side|on-box|other)$")] = None,
    f5_config_id: Annotated[str | None, Query(pattern=r"^f5c_[0-9a-f]{20}$")] = None,
    analyze: bool = True,
):
    ctype = request.headers.get("content-type", "")
    if ctype.startswith("multipart/"):
        raise ApiError(415, "unsupported_media_type", "Send the capture as the raw request body (application/octet-stream) "
                                                     "with the file name in the X-Filename header")
    agen = request.stream().__aiter__()

    def chunks():
        while True:
            try:
                chunk = anyio.from_thread.run(agen.__anext__)
            except StopAsyncIteration:
                return
            if chunk:
                yield chunk

    def work() -> dict:
        cap = cap_svc.ingest_capture(principal, chunks(), x_filename, description=description, capture_point=capture_point,
                                     f5_config_id=f5_config_id)
        job = cap_svc.start_analysis(principal, cap["id"]) if analyze else None
        return {"capture": cap, "job": job}

    res = await anyio.to_thread.run_sync(work)
    cap = res["capture"]
    return {"capture": {k: v for k, v in cap.items() if k not in HIDDEN}, "job": res["job"]}


@router.get("")
def list_captures(principal: P, training: bool | None = None, status: str | None = Query(None, max_length=20),
                  q: str | None = Query(None, max_length=100), limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0)):
    principal.require("capture:read")
    items, total = cap_svc.list_captures(principal, training=training, status=status, q=q, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/{capture_id}")
def get_capture(capture_id: str, principal: P):
    principal.require("capture:read")
    return _public(cap_svc.get_capture(principal, capture_id, audit_access=True))


@router.delete("/{capture_id}", status_code=204)
def delete_capture(capture_id: str, principal: Annotated[Principal, Depends(require("capture:delete"))]):
    cap_svc.delete_capture(principal, capture_id)
    return Response(status_code=204)


@router.post("/{capture_id}/analyze", status_code=202)
def analyze(capture_id: str, principal: Annotated[Principal, Depends(require("analysis:run"))], body: AnalyzeRequest | None = None):
    return cap_svc.start_analysis(principal, capture_id, force=bool(body and body.force))


@router.post("/{capture_id}/cancel")
def cancel(capture_id: str, principal: Annotated[Principal, Depends(require("analysis:run"))]):
    return cap_svc.cancel_analysis(principal, capture_id)


@router.get("/{capture_id}/status")
def status(capture_id: str, principal: P):
    principal.require("capture:read")
    return cap_svc.capture_status(principal, capture_id)


@router.get("/{capture_id}/events", summary="Server-sent events with analysis progress")
async def events(capture_id: str, principal: P):
    principal.require("capture:read")
    await anyio.to_thread.run_sync(cap_svc.get_capture, principal, capture_id)

    async def gen():
        last = None
        for _ in range(3600 * 2):
            st = await anyio.to_thread.run_sync(cap_svc.capture_status, principal, capture_id)
            job = st.get("job") or {}
            snap = {"status": st["status"], "progress": job.get("progress"), "stage": job.get("stage"), "message": job.get("message"),
                    "job_status": job.get("status"), "error": st.get("error")}
            if snap != last:
                yield f"event: progress\ndata: {json.dumps(snap, default=str)}\n\n"
                last = snap
            if job.get("status") in TERMINAL_JOB or st["status"] in ("analyzed", "rejected", "failed", "cancelled"):
                yield f"event: done\ndata: {json.dumps(snap, default=str)}\n\n"
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@router.get("/{capture_id}/summary")
def summary(capture_id: str, principal: P):
    principal.require("capture:read")
    return stats_svc.capture_summary(principal, capture_id)


@router.get("/{capture_id}/packets")
def packets(capture_id: str, principal: P,
            filter: str | None = Query(None, max_length=1000, description="Display filter (safe subset)"),
            ip: str | None = Query(None, max_length=45), port: int | None = Query(None, ge=0, le=65535),
            protocol: str | None = Query(None, max_length=32), flow: str | None = Query(None, max_length=40),
            text: str | None = Query(None, max_length=200), frame_from: int | None = Query(None, ge=1), frame_to: int | None = Query(None, ge=1),
            time_from: float | None = None, time_to: float | None = None, flags: str | None = Query(None, max_length=40),
            columns: str | None = Query(None, max_length=500), sort: str = Query("number", max_length=20),
            order: str = Query("asc", pattern="^(asc|desc)$"), limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    principal.require("capture:read")
    return pkt_svc.query_packets(principal, capture_id, columns=columns.split(",") if columns else None, sort=sort, order=order,
                                 limit=limit, offset=offset, display_filter=filter, ip=ip, port=port, protocol=protocol, flow=flow,
                                 text=text, frame_from=frame_from, frame_to=frame_to, time_from=time_from, time_to=time_to, flags=flags)


@router.get("/{capture_id}/packets/export")
def export_packets(capture_id: str, principal: Annotated[Principal, Depends(require("export:data"))],
                   format: str = Query("csv", pattern="^(csv|json)$"), include_sensitive: bool = False,
                   filter: str | None = Query(None, max_length=1000)):
    data, media = pkt_svc.export_packets(principal, capture_id, format, include_sensitive=include_sensitive, display_filter=filter)
    return Response(data, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="packets-{capture_id}.{format}"'})


@router.get("/{capture_id}/packets/{frame}")
def packet(capture_id: str, frame: int, principal: P, hex: bool = True):
    principal.require("capture:read")
    return pkt_svc.packet_detail(principal, capture_id, frame, include_hex=hex)


@router.get("/{capture_id}/flows")
def flows(capture_id: str, principal: P, transport: str | None = Query(None, pattern="^(tcp|udp)$"),
          state: str | None = Query(None, max_length=30), ip: str | None = Query(None, max_length=45),
          port: int | None = Query(None, ge=0, le=65535), has_findings: bool | None = None,
          sort: str = Query("issue_score", max_length=20), limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    principal.require("capture:read")
    items, total = flow_svc.list_flows(principal, capture_id, transport=transport, state=state, ip=ip, port=port,
                                       has_findings=has_findings, sort=sort, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/{capture_id}/graph")
def graph(capture_id: str, principal: P, limit: int = Query(300, ge=1, le=2000)):
    principal.require("capture:read")
    return flow_svc.flow_graph(principal, capture_id, limit=limit)


@router.get("/{capture_id}/flows/{flow_id}")
def flow(capture_id: str, flow_id: str, principal: P):
    principal.require("capture:read")
    return flow_svc.get_flow(principal, capture_id, flow_id)


@router.get("/{capture_id}/flows/{flow_id}/sequence")
def flow_sequence(capture_id: str, flow_id: str, principal: P):
    principal.require("capture:read")
    return flow_svc.flow_sequence(principal, capture_id, flow_id)


@router.get("/{capture_id}/flows/{flow_id}/payload", summary="Reassembled stream payload (audited)")
def flow_payload(capture_id: str, flow_id: str, principal: Annotated[Principal, Depends(require("export:data"))],
                 max_bytes: int = Query(65536, ge=1, le=1048576)):
    return pkt_svc.stream_payload(principal, capture_id, flow_id, max_bytes=max_bytes)


@router.get("/{capture_id}/findings")
def capture_findings(capture_id: str, principal: P, severity: str | None = None, status: str | None = None,
                     limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    principal.require("finding:read")
    items, total = find_svc.list_findings(principal, capture_id=capture_id, severity=severity, status=status, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/{capture_id}/findings/export")
def export_findings(capture_id: str, principal: Annotated[Principal, Depends(require("export:data"))],
                    format: str = Query("json", pattern="^(json|csv)$")):
    data, media = find_svc.export_findings(principal, capture_id, format)
    return Response(data, media_type=media, headers={"Content-Disposition": f'attachment; filename="findings-{capture_id}.{format}"'})


@router.get("/{capture_id}/jobs")
def jobs(capture_id: str, principal: P):
    principal.require("capture:read")
    cap_svc.get_capture(principal, capture_id)
    return [clean(j) for j in TenantDB(principal.tenant_id).analysis_jobs.find({"capture_id": capture_id}).sort("created_at", -1).limit(20)]
