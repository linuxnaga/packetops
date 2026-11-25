"""REST API: authentication, role-based authorization and tenant isolation."""

import pytest

from .conftest import FIXTURES, token_for

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def acme_capture(client):
    h = token_for(client, "analyst@acme.example")
    r = client.post("/api/v1/captures", content=(FIXTURES / "connection-reset.pcapng").read_bytes(),
                    headers={**h, "X-Filename": "../../etc/passwd<script>.pcapng", "Content-Type": "application/octet-stream"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert "storage_key" not in body["capture"] and "tenant_id" not in body["capture"]
    assert "/" not in body["capture"]["filename"] and "<" not in body["capture"]["filename"]
    return body["capture"]["id"]


def test_unauthenticated_rejected(client):
    assert client.get("/api/v1/captures").status_code == 401
    assert client.get("/api/v1/captures", headers={"Authorization": "Bearer nonsense"}).status_code == 401


def test_upload_analyse_and_read(client, acme_capture):
    h = token_for(client, "analyst@acme.example")
    st = client.get(f"/api/v1/captures/{acme_capture}/status", headers=h).json()
    assert st["status"] == "analyzed"
    findings = client.get(f"/api/v1/captures/{acme_capture}/findings", headers=h).json()
    assert any(f["rule_id"] == "TCP-006" for f in findings["items"])
    fid = findings["items"][0]["id"]
    ev = client.get(f"/api/v1/findings/{fid}/evidence", headers=h).json()
    assert ev["packets"]


def test_rejects_non_capture(client):
    h = token_for(client, "analyst@acme.example")
    r = client.post("/api/v1/captures", content=b"PK\x03\x04" + b"\x00" * 100, headers={**h, "Content-Type": "application/octet-stream"})
    assert r.status_code == 415


@pytest.mark.parametrize("email,method,path,expected", [
    ("read-only@acme.example", "post", "/api/v1/captures", 403),
    ("read-only@acme.example", "get", "/api/v1/captures", 200),
    ("auditor@acme.example", "get", "/api/v1/audit", 200),
    ("analyst@acme.example", "get", "/api/v1/audit", 403),
    ("investigator@acme.example", "get", "/api/v1/captures/{cap}/findings/export", 403),
    ("analyst@acme.example", "get", "/api/v1/captures/{cap}/findings/export", 200),
    ("investigator@acme.example", "delete", "/api/v1/captures/{cap}", 403),
    ("read-only@acme.example", "post", "/api/v1/console/execute", 200),
])
def test_rbac(client, acme_capture, email, method, path, expected):
    h = token_for(client, email)
    kwargs = {"headers": h}
    if method == "post" and path.endswith("/execute"):
        kwargs["json"] = {"line": "status"}
    r = getattr(client, method)(path.format(cap=acme_capture), **kwargs)
    assert r.status_code == expected, r.text


def test_console_blocks_unpermitted_command(client):
    h = token_for(client, "read-only@acme.example")
    r = client.post("/api/v1/console/execute", json={"line": "mission start tcp-handshake"}, headers=h).json()
    assert r.get("error") and "requires" in r["blocks"][0]["text"]


def test_tenant_isolation(client, acme_capture):
    g = token_for(client, "admin@globex.example")
    for path in (f"/api/v1/captures/{acme_capture}", f"/api/v1/captures/{acme_capture}/packets", f"/api/v1/captures/{acme_capture}/flows",
                 f"/api/v1/findings/{acme_capture}-F1"):
        assert client.get(path, headers=g).status_code == 404, path
    listing = client.get("/api/v1/captures", headers=g).json()
    assert all(c["id"] != acme_capture for c in listing["items"])
    r = client.post("/api/v1/console/execute", json={"line": f"pcap use {acme_capture}"}, headers=g).json()
    assert r.get("error")


def test_tenant_collection_guard(seeded):
    from app.db import TenantDB, TenantIsolationError

    tdb = TenantDB("ten_acme0000000000000000")
    with pytest.raises(TenantIsolationError):
        tdb.captures.update_one({"_id": "x"}, {"$set": {"tenant_id": "ten_globex000000000000000"}})
    with pytest.raises(TenantIsolationError):
        list(tdb.captures.aggregate([{"$lookup": {"from": "users", "localField": "a", "foreignField": "b", "as": "c"}}]))


def test_export_excludes_payload_by_default(client, acme_capture):
    h = token_for(client, "analyst@acme.example")
    r = client.get(f"/api/v1/captures/{acme_capture}/packets/export?format=csv", headers=h)
    assert r.status_code == 200
    header = r.text.splitlines()[0].split(",")
    assert not {"info", "http_host", "dns_qname", "tls_sni", "eth_src", "eth_dst"} & set(header)


def test_security_headers(client):
    r = client.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert r.headers.get("X-Request-ID")


def test_dev_login_unknown_user(client):
    assert client.post("/api/v1/auth/dev-login", json={"email": "nobody@acme.example"}).status_code == 401
