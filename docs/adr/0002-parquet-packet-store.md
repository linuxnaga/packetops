# 0002: Parquet for packet rows, MongoDB for metadata

**Status:** accepted

## Context
Captures can hold tens of millions of packets. Storing one document per packet makes MongoDB the bottleneck and grows storage roughly 10×. The packet table needs fast filtering, paging and export.

## Decision
Write per-packet summary rows to a Parquet file per capture (`derived/packets.parquet`) in batches during extraction. Query it with PyArrow, using a safe display-filter subset compiled to Arrow expressions. Keep flows, findings, evidence references and everything else in MongoDB.

## Consequences
- Packet listing and filtering scale with columnar scans, and the derived file can always be regenerated from the original.
- The filter language is a subset of Wireshark's. Unsupported fields are rejected with an explanation, never passed to tshark.
- Workers and API need the Parquet file locally. With S3 it is materialised into a local cache, keyed by capture.
