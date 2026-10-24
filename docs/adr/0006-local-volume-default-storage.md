# 0006: Shared volume as the default evidence store, S3 optional

**Status:** accepted

## Context
The single-host Compose deployment should work with no external services. Larger deployments need object storage.

## Decision
A `Storage` interface has two backends: a local filesystem rooted at a shared Docker volume (default), and S3 or any S3-compatible store (`PKO_STORAGE_BACKEND=s3`), using server-side encryption when it is configured. Originals are write-once. Derived files and reports are replaceable.

## Consequences
- `docker compose up` works with nothing outside the host.
- Multi-host deployments must use S3. The S3 backend is tested against moto (`tests/test_storage_s3.py`), including server-side encryption and prefix-scoped deletion.
- An Azure Blob backend is not implemented.
