"""Test configuration.

Unit tests need nothing external. Tests marked ``integration`` need MongoDB
(PKO_TEST_MONGO_URI, default mongodb://localhost:27017) and tshark; they are
skipped automatically when either is missing.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="pko-test-"))
os.environ.update({
    "PKO_APP_ENV": "test",
    "PKO_MONGO_URI": os.environ.get("PKO_TEST_MONGO_URI", "mongodb://localhost:27017"),
    "PKO_MONGO_DB": f"packetops_test_{uuid.uuid4().hex[:8]}",
    "PKO_CELERY_EAGER": "true",
    "PKO_STORAGE_BACKEND": "local",
    "PKO_STORAGE_LOCAL_ROOT": str(_TMP / "storage"),
    "PKO_WORK_DIR": str(_TMP / "work"),
    "PKO_CACHE_DIR": str(_TMP / "cache"),
    "PKO_AUTH_MODE": "dev",
    "PKO_DEV_JWT_SECRET": "test-secret-test-secret-test-secret-123",
    "PKO_LLM_PROVIDER": "none",
})

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "training"


def _mongo_ok() -> bool:
    try:
        from pymongo import MongoClient

        MongoClient(os.environ["PKO_MONGO_URI"], serverSelectionTimeoutMS=1500).admin.command("ping")
        return True
    except Exception:  # noqa: BLE001
        return False


HAVE_MONGO = _mongo_ok()
HAVE_TSHARK = shutil.which("tshark") is not None


def pytest_collection_modifyitems(config, items):
    skip = pytest.mark.skip(reason="integration test needs MongoDB and tshark")
    for item in items:
        if "integration" in item.keywords and not (HAVE_MONGO and HAVE_TSHARK):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def seeded():
    from app.db import get_client, get_db
    from app.seed import seed

    seed()
    yield get_db()
    get_client().drop_database(os.environ["PKO_MONGO_DB"])
    shutil.rmtree(_TMP, ignore_errors=True)


@pytest.fixture(scope="session")
def principals(seeded):
    from app.core.security import _principal_from_user

    out = {}
    for u in seeded.users.find({}):
        slug = "acme" if u["tenant_id"].startswith("ten_acme") else "globex"
        out[f"{slug}:{u['roles'][0]}"] = _principal_from_user(u)
    return out


@pytest.fixture(scope="session")
def client(seeded):
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


def token_for(client, email: str) -> dict:
    r = client.post("/api/v1/auth/dev-login", json={"email": email})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def analyzed(principals):
    """Every training fixture ingested and analysed once (as acme analyst), keyed by file name."""
    from app.services.captures import get_capture, ingest_capture, iter_file, start_analysis

    p = principals["acme:analyst"]
    caps = {}
    for path in sorted(FIXTURES.glob("*.pcapng")):
        cap = ingest_capture(p, iter_file(path), path.name, training=True)
        start_analysis(p, cap["id"])
        caps[path.name] = get_capture(p, cap["id"])
    return caps
