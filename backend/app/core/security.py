"""Authentication (OIDC bearer tokens, or development tokens) and role-based access control."""

from __future__ import annotations

import datetime as dt
import functools
from dataclasses import dataclass, field

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.logging import tenant_id_var
from app.db import get_db, new_id, utcnow

ROLES = ("admin", "analyst", "investigator", "auditor", "read_only")

_READ = {"capture:read", "finding:read", "report:read", "investigation:read", "f5config:read", "mission:read",
         "console:use", "profile:read"}
PERMISSIONS: dict[str, set[str]] = {
    "admin": _READ | {"capture:upload", "capture:delete", "analysis:run", "finding:update", "report:create", "export:data",
                      "f5config:write", "correlation:run", "investigation:write", "mission:play", "audit:read",
                      "tenant:admin", "user:admin"},
    "analyst": _READ | {"capture:upload", "capture:delete", "analysis:run", "finding:update", "report:create", "export:data",
                        "f5config:write", "correlation:run", "investigation:write", "mission:play"},
    "investigator": _READ | {"capture:upload", "analysis:run", "finding:update", "report:create", "correlation:run",
                             "investigation:write", "mission:play"},
    "auditor": _READ | {"audit:read"},
    "read_only": set(_READ),
}


@dataclass
class Principal:
    user_id: str
    tenant_id: str
    email: str
    display_name: str
    roles: list[str] = field(default_factory=list)

    @property
    def permissions(self) -> set[str]:
        perms: set[str] = set()
        for r in self.roles:
            perms |= PERMISSIONS.get(r, set())
        return perms

    def can(self, perm: str) -> bool:
        return perm in self.permissions

    def require(self, perm: str) -> None:
        if not self.can(perm):
            raise ApiError(403, "forbidden", f"Missing permission '{perm}'", {"roles": self.roles})


bearer = HTTPBearer(auto_error=False)


def issue_dev_token(user: dict) -> str:
    s = get_settings()
    now = utcnow()
    claims = {
        "sub": user["_id"], "tid": user["tenant_id"], "email": user["email"], "roles": user["roles"],
        "iat": int(now.timestamp()), "exp": int((now + dt.timedelta(minutes=s.jwt_ttl_minutes)).timestamp()),
        "iss": "packetops-dev", "aud": "packetops",
    }
    return jwt.encode(claims, s.dev_jwt_secret, algorithm="HS256")


@functools.lru_cache(maxsize=1)
def _jwks_client() -> jwt.PyJWKClient:
    s = get_settings()
    if not s.oidc_jwks_url:
        raise RuntimeError("PKO_OIDC_JWKS_URL is required in oidc mode")
    return jwt.PyJWKClient(s.oidc_jwks_url, cache_keys=True, lifespan=3600)


def _principal_from_user(user: dict) -> Principal:
    return Principal(user_id=user["_id"], tenant_id=user["tenant_id"], email=user["email"],
                     display_name=user.get("display_name") or user["email"], roles=[r for r in user.get("roles", []) if r in ROLES])


def _verify_dev(token: str) -> Principal:
    s = get_settings()
    try:
        claims = jwt.decode(token, s.dev_jwt_secret, algorithms=["HS256"], audience="packetops", issuer="packetops-dev")
    except jwt.PyJWTError as exc:
        raise ApiError(401, "unauthorized", "Invalid or expired token") from exc
    user = get_db().users.find_one({"_id": claims["sub"], "tenant_id": claims["tid"], "disabled": {"$ne": True}})
    if not user:
        raise ApiError(401, "unauthorized", "User not found or disabled")
    return _principal_from_user(user)


def _verify_oidc(token: str) -> Principal:
    s = get_settings()
    try:
        key = _jwks_client().get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256", "ES256", "PS256"], audience=s.oidc_audience, issuer=s.oidc_issuer)
    except jwt.PyJWTError as exc:
        raise ApiError(401, "unauthorized", "Invalid or expired token") from exc
    db = get_db()
    tenant_slug = claims.get(s.oidc_tenant_claim)
    tenant = db.tenants.find_one({"slug": tenant_slug, "disabled": {"$ne": True}}) if tenant_slug else None
    if not tenant:
        raise ApiError(403, "forbidden", "Token is not mapped to an active tenant")
    roles_claim = claims.get(s.oidc_roles_claim) or []
    roles = [r for r in (roles_claim if isinstance(roles_claim, list) else [roles_claim]) if r in ROLES] or ["read_only"]
    email = claims.get(s.oidc_email_claim) or claims["sub"]
    user = db.users.find_one_and_update(
        {"oidc_issuer": s.oidc_issuer, "oidc_subject": claims["sub"]},
        {"$set": {"email": email, "roles": roles, "tenant_id": tenant["_id"], "last_login_at": utcnow(),
                  "display_name": claims.get("name") or email},
         "$setOnInsert": {"_id": new_id("usr"), "created_at": utcnow()}},
        upsert=True, return_document=True,
    )
    if user.get("tenant_id") != tenant["_id"] or user.get("disabled"):
        raise ApiError(403, "forbidden", "User is not permitted in this tenant")
    return _principal_from_user(user)


def authenticate_token(token: str) -> Principal:
    return _verify_dev(token) if get_settings().auth_mode == "dev" else _verify_oidc(token)


def current_principal(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    token = creds.credentials if creds else None
    if not token:
        # EventSource cannot send headers; allow a token query parameter only on SSE endpoints.
        if request.url.path.endswith("/events"):
            token = request.query_params.get("access_token")
    if not token:
        raise ApiError(401, "unauthorized", "Authentication required")
    principal = authenticate_token(token)
    tenant_id_var.set(principal.tenant_id)
    request.state.principal = principal
    return principal


def require(perm: str):
    def dep(principal: Principal = Depends(current_principal)) -> Principal:
        principal.require(perm)
        return principal

    return dep
