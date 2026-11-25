"""Capture ingestion, listing, deletion and analysis-job control."""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import re
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from app.analysis.pcapfile import CaptureReader, MalformedCaptureError, sniff_format
from app.core.config import get_settings
from app.core.errors import ApiError, not_found
from app.core.security import Principal
from app.db import TenantDB, clean, get_db, new_id, utcnow
from app.services.audit import audit
from app.storage import get_storage, tenant_key

log = logging.getLogger(__name__)

ARCHIVE_MAGICS = {
    b"\x1f\x8b": "gzip", b"PK\x03\x04": "zip", b"\xfd7zXZ": "xz", b"7z\xbc\xaf": "7z", b"BZh": "bzip2",
    b"\x28\xb5\x2f\xfd": "zstd", b"Rar!": "rar",
}
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]+")
ACTIVE_JOB_STATES = ("queued", "running")


def safe_display_name(name: str | None) -> str:
    base = (name or "capture").replace("\\", "/").split("/")[-1]
    base = _SAFE_NAME.sub("_", base).strip(" .") or "capture"
    return base[:128]


def tenant_usage_bytes(tdb: TenantDB) -> int:
    res = list(tdb.captures.aggregate([{"$match": {"deleted_at": None}}, {"$group": {"_id": None, "b": {"$sum": "$size_bytes"}}}]))
    return int(res[0]["b"]) if res else 0


def _receive(chunks: Iterable[bytes], dest: Path, max_bytes: int) -> tuple[str, int, bytes]:
    h = hashlib.sha256()
    size = 0
    head = b""
    with dest.open("wb") as fh:
        for chunk in chunks:
            if not chunk:
                continue
            size += len(chunk)
            if size > max_bytes:
                raise ApiError(413, "payload_too_large", f"Capture exceeds the {max_bytes} byte upload limit")
            if len(head) < 16:
                head += chunk[: 16 - len(head)]
            h.update(chunk)
            fh.write(chunk)
    return h.hexdigest(), size, head


def ingest_capture(principal: Principal, chunks: Iterable[bytes], filename: str | None, *, training: bool = False,
                   description: str | None = None, f5_config_id: str | None = None, mission_id: str | None = None,
                   capture_point: str | None = None) -> dict:
    """Stream an upload to disk, hash it, validate its structure and store it as write-once evidence."""
    settings = get_settings()
    tdb = TenantDB(principal.tenant_id)
    tenant = _tenant(principal.tenant_id)
    quota = tenant.get("storage_quota_bytes") or settings.tenant_storage_quota_bytes
    max_bytes = min(settings.max_upload_bytes, max(0, quota - tenant_usage_bytes(tdb)))
    if max_bytes <= 0:
        raise ApiError(413, "quota_exceeded", "Tenant storage quota is exhausted; delete captures or raise the quota")
    capture_id = new_id("cap")
    work = Path(settings.work_dir)
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work, prefix="upload_") as tmp:
        dest = Path(tmp) / "upload.bin"
        sha256, size, head = _receive(chunks, dest, max_bytes)
        if size == 0:
            raise ApiError(400, "empty_upload", "The uploaded file is empty")
        for magic, kind in ARCHIVE_MAGICS.items():
            if head.startswith(magic):
                audit(principal, "capture.upload", "capture", None, {"rejected": f"{kind} archive", "sha256": sha256}, outcome="rejected")
                raise ApiError(415, "unsupported_media_type",
                               f"Compressed {kind} archives are not accepted; upload the uncompressed .pcap or .pcapng file")
        fmt = sniff_format(head)
        if fmt is None:
            audit(principal, "capture.upload", "capture", None, {"rejected": "not a capture", "sha256": sha256}, outcome="rejected")
            raise ApiError(415, "unsupported_media_type", "File is not a PCAP or PCAPNG capture")
        try:
            meta = CaptureReader(dest, max_packets=settings.max_packets_per_capture).scan()
        except MalformedCaptureError as exc:
            audit(principal, "capture.upload", "capture", None, {"rejected": exc.reason, "sha256": sha256}, outcome="rejected")
            raise ApiError(422, "malformed_capture", f"Capture rejected: {exc}", {"reason": exc.reason, "offset": exc.offset}) from exc
        if meta.packet_count == 0:
            raise ApiError(422, "malformed_capture", "Capture contains no packets")
        if meta.packet_count >= settings.max_packets_per_capture:
            audit(principal, "capture.upload", "capture", None, {"rejected": "packet limit", "sha256": sha256}, outcome="rejected")
            raise ApiError(413, "too_many_packets", f"Capture has more than {settings.max_packets_per_capture} packets; split it "
                                                    "(editcap -c) or raise the limit")
        key = tenant_key(principal.tenant_id, "captures", capture_id, f"original.{fmt}")
        get_storage().put_file(key, dest)
    duplicate = tdb.captures.find_one({"sha256": sha256, "deleted_at": None}, {"_id": 1})
    retention_days = tenant.get("retention_days") or settings.retention_days_default
    now = utcnow()
    doc = {
        "_id": capture_id,
        "filename": safe_display_name(filename),
        "description": (description or "")[:1000] or None,
        "sha256": sha256,
        "size_bytes": size,
        "format": fmt,
        "storage_key": key,
        "status": "uploaded",
        "training": training,
        "mission_id": mission_id,
        "capture_point": capture_point,
        "f5_config_id": f5_config_id,
        "duplicate_of": duplicate["_id"] if duplicate else None,
        "metadata": meta.to_dict(),
        "created_by": principal.user_id,
        "created_at": now,
        "retain_until": now + dt.timedelta(days=retention_days),
        "deleted_at": None,
    }
    tdb.captures.insert_one(doc)
    audit(principal, "capture.upload", "capture", capture_id, {"sha256": sha256, "size": size, "format": fmt, "training": training})
    return clean(doc)


def _tenant(tenant_id: str) -> dict:
    t = get_db().tenants.find_one({"_id": tenant_id})
    if not t:
        raise ApiError(403, "forbidden", "Unknown tenant")
    return t


def get_capture(principal: Principal, capture_id: str, audit_access: bool = False) -> dict:
    doc = TenantDB(principal.tenant_id).captures.find_one({"_id": capture_id, "deleted_at": None})
    if not doc:
        raise not_found("Capture")
    if audit_access:
        audit(principal, "capture.access", "capture", capture_id)
    return doc


def list_captures(principal: Principal, *, training: bool | None = None, status: str | None = None, q: str | None = None,
                  limit: int = 25, offset: int = 0) -> tuple[list[dict], int]:
    flt: dict = {"deleted_at": None}
    if training is not None:
        flt["training"] = training
    if status:
        flt["status"] = status
    if q:
        flt["$or"] = [{"filename": {"$regex": re.escape(q), "$options": "i"}}, {"sha256": q.lower()}, {"_id": q}]
    tdb = TenantDB(principal.tenant_id)
    total = tdb.captures.count_documents(flt)
    docs = tdb.captures.find(flt, {"metadata.interfaces": 0, "metadata.comments": 0}).sort("created_at", -1).skip(offset).limit(limit)
    return [clean(d, ("tenant_id", "storage_key", "derived_key")) for d in docs], total


def delete_capture(principal: Principal, capture_id: str) -> None:
    tdb = TenantDB(principal.tenant_id)
    cap = get_capture(principal, capture_id)
    if tdb.analysis_jobs.count_documents({"capture_id": capture_id, "status": {"$in": list(ACTIVE_JOB_STATES)}}):
        raise ApiError(409, "conflict", "Cancel the running analysis before deleting the capture")
    removed = get_storage().delete_prefix(tenant_key(principal.tenant_id, "captures", capture_id))
    for col in ("flows", "findings", "evidence_references", "packet_summaries", "bookmarks"):
        getattr(tdb, col).delete_many({"capture_id": capture_id})
    tdb.captures.update_one({"_id": capture_id}, {"$set": {"deleted_at": utcnow(), "status": "deleted", "deleted_by": principal.user_id},
                                                  "$unset": {"metadata": "", "stats": "", "limitations": ""}})
    audit(principal, "capture.delete", "capture", capture_id, {"sha256": cap["sha256"], "objects_removed": removed})


# --------------------------------------------------------------------------- jobs
def start_analysis(principal: Principal, capture_id: str, *, force: bool = False) -> dict:
    settings = get_settings()
    tdb = TenantDB(principal.tenant_id)
    cap = get_capture(principal, capture_id)
    active = tdb.analysis_jobs.find_one({"capture_id": capture_id, "status": {"$in": list(ACTIVE_JOB_STATES)}})
    if active:
        return clean(active)  # idempotent: a second request returns the job already in progress
    if cap["status"] == "analyzed" and not force:
        last = tdb.analysis_jobs.find_one({"capture_id": capture_id, "status": "completed"}, sort=[("created_at", -1)])
        if last:
            return clean(last)
    running = tdb.analysis_jobs.count_documents({"status": {"$in": list(ACTIVE_JOB_STATES)}})
    if running >= settings.max_concurrent_analyses_per_tenant:
        raise ApiError(429, "analysis_limit", f"At most {settings.max_concurrent_analyses_per_tenant} analyses may run per tenant")
    attempt = tdb.analysis_jobs.count_documents({"capture_id": capture_id}) + 1
    job = {
        "_id": new_id("job"),
        "capture_id": capture_id,
        "idempotency_key": f"{capture_id}:{attempt}",
        "status": "queued",
        "stage": "queued",
        "progress": 0.0,
        "message": "Waiting for a worker",
        "attempts": 0,
        "attempt": attempt,
        "requested_by": principal.user_id,
        "cancel_requested": False,
        "created_at": utcnow(),
        "updated_at": utcnow(),
        "stages": [],
    }
    tdb.analysis_jobs.insert_one(job)
    tdb.captures.update_one({"_id": capture_id}, {"$set": {"status": "queued", "analysis_job_id": job["_id"]}})
    audit(principal, "analysis.start", "capture", capture_id, {"job_id": job["_id"], "attempt": attempt})
    from app.worker.dispatch import dispatch_analysis

    dispatch_analysis(principal.tenant_id, capture_id, job["_id"], principal.user_id)
    return clean(tdb.analysis_jobs.find_one({"_id": job["_id"]}))


def cancel_analysis(principal: Principal, capture_id: str) -> dict:
    tdb = TenantDB(principal.tenant_id)
    get_capture(principal, capture_id)
    job = tdb.analysis_jobs.find_one_and_update(
        {"capture_id": capture_id, "status": {"$in": list(ACTIVE_JOB_STATES)}},
        {"$set": {"cancel_requested": True, "updated_at": utcnow()}}, return_document=True)
    if not job:
        raise ApiError(409, "conflict", "No analysis is running for this capture")
    if job["status"] == "queued":
        tdb.analysis_jobs.update_one({"_id": job["_id"]}, {"$set": {"status": "cancelled", "finished_at": utcnow()}})
        tdb.captures.update_one({"_id": capture_id}, {"$set": {"status": "cancelled"}})
    from app.worker.dispatch import revoke

    revoke(job.get("celery_task_id"))
    audit(principal, "analysis.cancel", "capture", capture_id, {"job_id": job["_id"]})
    return clean(tdb.analysis_jobs.find_one({"_id": job["_id"]}))


def capture_status(principal: Principal, capture_id: str) -> dict:
    tdb = TenantDB(principal.tenant_id)
    cap = get_capture(principal, capture_id)
    job = tdb.analysis_jobs.find_one({"capture_id": capture_id}, sort=[("created_at", -1)])
    return {"capture_id": capture_id, "status": cap["status"], "job": clean(job) if job else None,
            "stats": cap.get("stats"), "error": cap.get("error")}


def iter_file(path: Path, chunk: int = 1024 * 1024) -> Iterator[bytes]:
    with path.open("rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                return
            yield b
