"""MongoDB access with mandatory tenant scoping.

All application code reaches tenant data through ``TenantDB``/``TenantCollection``.
The wrapper injects ``tenant_id`` into every filter, insert and aggregation
pipeline, and refuses filters that try to name a different tenant, so a missing
filter can never leak another tenant's documents.
"""

from __future__ import annotations

import datetime as dt
import functools
import secrets
from collections.abc import Iterable
from typing import Any

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

from app.core.config import get_settings

GLOBAL_COLLECTIONS = {"tenants", "missions_catalog", "achievements_catalog", "schema_migrations"}


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(10)}"


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@functools.lru_cache(maxsize=1)
def get_client() -> MongoClient:
    s = get_settings()
    return MongoClient(s.mongo_uri, tz_aware=True, serverSelectionTimeoutMS=5000, appname="packetops")


def get_db() -> Database:
    return get_client()[get_settings().mongo_db]


class TenantIsolationError(PermissionError):
    pass


class TenantCollection:
    def __init__(self, col: Collection, tenant_id: str):
        if not tenant_id:
            raise TenantIsolationError("tenant_id is required")
        self._col = col
        self.tenant_id = tenant_id

    def _scope(self, flt: dict | None) -> dict:
        flt = dict(flt or {})
        if "tenant_id" in flt and flt["tenant_id"] != self.tenant_id:
            raise TenantIsolationError("cross-tenant filter rejected")
        flt["tenant_id"] = self.tenant_id
        return flt

    def _stamp(self, doc: dict) -> dict:
        if doc.get("tenant_id") not in (None, self.tenant_id):
            raise TenantIsolationError("cross-tenant insert rejected")
        doc = dict(doc)
        doc["tenant_id"] = self.tenant_id
        return doc

    @staticmethod
    def _guard_update(update: dict) -> dict:
        for op in ("$set", "$setOnInsert", "$unset", "$rename"):
            if op in update and "tenant_id" in update[op]:
                raise TenantIsolationError("tenant_id cannot be modified")
        return update

    def find(self, flt: dict | None = None, *args, **kwargs):
        return self._col.find(self._scope(flt), *args, **kwargs)

    def find_one(self, flt: dict | None = None, *args, **kwargs):
        return self._col.find_one(self._scope(flt), *args, **kwargs)

    def count_documents(self, flt: dict | None = None, **kwargs) -> int:
        return self._col.count_documents(self._scope(flt), **kwargs)

    def distinct(self, key: str, flt: dict | None = None) -> list:
        return self._col.distinct(key, self._scope(flt))

    def insert_one(self, doc: dict):
        return self._col.insert_one(self._stamp(doc))

    def insert_many(self, docs: Iterable[dict], ordered: bool = False):
        docs = [self._stamp(d) for d in docs]
        if not docs:
            return None
        return self._col.insert_many(docs, ordered=ordered)

    def update_one(self, flt: dict, update: dict, **kwargs):
        return self._col.update_one(self._scope(flt), self._guard_update(update), **kwargs)

    def update_many(self, flt: dict, update: dict, **kwargs):
        return self._col.update_many(self._scope(flt), self._guard_update(update), **kwargs)

    def find_one_and_update(self, flt: dict, update: dict, **kwargs):
        return self._col.find_one_and_update(self._scope(flt), self._guard_update(update), **kwargs)

    def replace_one(self, flt: dict, doc: dict, **kwargs):
        return self._col.replace_one(self._scope(flt), self._stamp(doc), **kwargs)

    def delete_one(self, flt: dict):
        return self._col.delete_one(self._scope(flt))

    def delete_many(self, flt: dict):
        return self._col.delete_many(self._scope(flt))

    def aggregate(self, pipeline: list[dict], **kwargs):
        for stage in pipeline:
            if any(k in stage for k in ("$lookup", "$unionWith", "$graphLookup", "$out", "$merge")):
                raise TenantIsolationError("cross-collection aggregation stages are not allowed on tenant collections")
        return self._col.aggregate([{"$match": {"tenant_id": self.tenant_id}}, *pipeline], **kwargs)


class TenantDB:
    def __init__(self, tenant_id: str, db: Database | None = None):
        self.tenant_id = tenant_id
        self._db = db if db is not None else get_db()

    def __getattr__(self, name: str) -> TenantCollection:
        if name.startswith("_"):
            raise AttributeError(name)
        if name in GLOBAL_COLLECTIONS:
            raise TenantIsolationError(f"{name} is a global collection; use get_db()")
        return TenantCollection(self._db[name], self.tenant_id)


def clean(doc: dict | None, drop: Iterable[str] = ("tenant_id",)) -> dict | None:
    """Prepare a Mongo document for API output."""
    if doc is None:
        return None
    out = {k: v for k, v in doc.items() if k not in drop}
    if "_id" in out:
        out["id"] = out.pop("_id")
    return out


def as_list(cursor: Any, drop: Iterable[str] = ("tenant_id",)) -> list[dict]:
    return [clean(d, drop) for d in cursor]
