"""BIG-IP configuration metadata and client/server-side flow correlation."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response

from app.core.errors import bad_request
from app.core.security import Principal, current_principal, require
from app.schemas import CorrelationRequest, F5ConfigImport
from app.services import f5 as f5_svc

router = APIRouter(prefix="/f5", tags=["f5"])
P = Annotated[Principal, Depends(current_principal)]


@router.get("/configs")
def list_configs(principal: P):
    return f5_svc.list_configs(principal)


@router.post("/configs", status_code=201)
def import_config(body: F5ConfigImport, principal: Annotated[Principal, Depends(require("f5config:write"))]):
    if (body.config is None) == (body.text is None):
        raise bad_request("Provide exactly one of 'config' (JSON object) or 'text' (tmsh list output)")
    return f5_svc.import_config(principal, body.config if body.config is not None else body.text, name=body.name,
                                source="manual" if body.config is not None else "tmsh", upsert=body.replace,
                                description=body.description)


@router.get("/configs/{config_id}")
def get_config(config_id: str, principal: P):
    return f5_svc.get_config(principal, config_id)


@router.delete("/configs/{config_id}", status_code=204)
def delete_config(config_id: str, principal: Annotated[Principal, Depends(require("f5config:write"))]):
    f5_svc.delete_config(principal, config_id)
    return Response(status_code=204)


@router.post("/correlations", status_code=201)
def correlate(body: CorrelationRequest, principal: Annotated[Principal, Depends(require("correlation:run"))]):
    return f5_svc.correlate(principal, body.client_capture_id, other_capture_id=body.server_capture_id, config_id=body.config_id)


@router.get("/correlations")
def list_correlations(principal: P, capture_id: str | None = None):
    return f5_svc.list_correlations(principal, capture_id)


@router.get("/correlations/{correlation_id}")
def get_correlation(correlation_id: str, principal: P):
    return f5_svc.get_correlation(principal, correlation_id)
