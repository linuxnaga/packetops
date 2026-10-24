"""Identity: development login (dev auth mode only) and the current principal."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.security import PERMISSIONS, Principal, current_principal, issue_dev_token
from app.db import get_db
from app.schemas import DevLogin
from app.services.audit import audit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/dev-login", summary="Development only: exchange a seeded user's email for a token")
def dev_login(body: DevLogin):
    s = get_settings()
    if s.auth_mode != "dev" or s.is_production:
        raise ApiError(404, "not_found", "Not found")
    user = get_db().users.find_one({"email": body.email.lower().strip(), "disabled": {"$ne": True}})
    if not user:
        raise ApiError(401, "unauthorized", "Unknown user")
    audit(None, "auth.dev_login", "user", user["_id"], tenant_id=user["tenant_id"])
    return {"access_token": issue_dev_token(user), "token_type": "bearer", "expires_in": s.jwt_ttl_minutes * 60}


@router.get("/config")
def auth_config():
    s = get_settings()
    return {"mode": s.auth_mode, "oidc_issuer": s.oidc_issuer if s.auth_mode == "oidc" else None,
            "oidc_client_id": s.oidc_client_id if s.auth_mode == "oidc" else None}


@router.get("/me")
def me(principal: Annotated[Principal, Depends(current_principal)]):
    tenant = get_db().tenants.find_one({"_id": principal.tenant_id}, {"name": 1, "slug": 1})
    return {"user_id": principal.user_id, "email": principal.email, "display_name": principal.display_name, "roles": principal.roles,
            "tenant": {"id": principal.tenant_id, "name": (tenant or {}).get("name"), "slug": (tenant or {}).get("slug")},
            "permissions": sorted(set().union(*(PERMISSIONS.get(r, set()) for r in principal.roles)))}
