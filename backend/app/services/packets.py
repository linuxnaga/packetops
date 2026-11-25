"""Packet list, search, single-packet detail (tree + hex) and metadata export."""

from __future__ import annotations

import csv
import io
import json
import tempfile
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.dataset as ds

from app.analysis.pcapfile import read_packet_bytes, write_single_packet_pcap
from app.analysis.tshark import dissect_single_frame, follow_stream
from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.security import Principal
from app.db import TenantDB
from app.services.audit import audit
from app.services.captures import get_capture
from app.services.filters import FilterError, compile_filter
from app.storage import get_storage

DEFAULT_COLUMNS = ["number", "rel_s", "ts_ns", "src", "sport", "dst", "dport", "protocol", "len", "flow", "tcp_flags",
                   "analysis", "expert", "info"]
ALL_COLUMNS = ["number", "ts_ns", "rel_s", "iface", "len", "caplen", "protocol", "protocols", "src", "dst", "sport", "dport",
               "transport", "flow", "tcp_flags", "tcp_seq", "tcp_ack", "tcp_len", "tcp_win", "analysis", "expert", "info",
               "vlan", "eth_src", "eth_dst", "ttl", "dns_qname", "http_host", "tls_sni", "f5_flowid"]
SORTABLE = {"number", "ts_ns", "rel_s", "len", "src", "dst", "sport", "dport", "protocol", "flow", "tcp_len"}
MAX_SORT_ROWS = 2_000_000
SENSITIVE_EXPORT_COLUMNS = {"info", "http_host", "dns_qname", "tls_sni", "eth_src", "eth_dst"}


def _dataset(principal: Principal, capture_id: str) -> tuple[dict, ds.Dataset]:
    cap = get_capture(principal, capture_id)
    if cap.get("status") != "analyzed" or not cap.get("derived_key"):
        raise ApiError(409, "not_analyzed", "Capture has not been analysed yet")
    path = get_storage().materialize(cap["derived_key"], Path(get_settings().cache_dir))
    return cap, ds.dataset(str(path), format="parquet")


def build_expression(*, display_filter: str | None = None, ip: str | None = None, port: int | None = None,
                     protocol: str | None = None, flow: str | None = None, text: str | None = None,
                     frame_from: int | None = None, frame_to: int | None = None, time_from: float | None = None,
                     time_to: float | None = None, flags: str | None = None, frames: list[int] | None = None):
    parts = []
    try:
        parts.append(compile_filter(display_filter))
        if ip:
            parts.append(compile_filter(f"ip.addr == {ip}"))
        if protocol:
            parts.append(compile_filter(protocol.lower()))
    except FilterError as exc:
        raise ApiError(400, "invalid_filter", str(exc)) from exc
    if port is not None:
        parts.append((pc.field("sport") == port) | (pc.field("dport") == port))
    if flow:
        parts.append(pc.field("flow") == flow)
    if text:
        t = text[:200]
        parts.append(pc.match_substring(pc.field("info"), t, ignore_case=True)
                     | pc.match_substring(pc.field("src"), t) | pc.match_substring(pc.field("dst"), t)
                     | pc.match_substring(pc.field("dns_qname"), t, ignore_case=True)
                     | pc.match_substring(pc.field("tls_sni"), t, ignore_case=True)
                     | pc.match_substring(pc.field("http_host"), t, ignore_case=True))
    if frame_from is not None:
        parts.append(pc.field("number") >= frame_from)
    if frame_to is not None:
        parts.append(pc.field("number") <= frame_to)
    if time_from is not None:
        parts.append(pc.field("rel_s") >= time_from)
    if time_to is not None:
        parts.append(pc.field("rel_s") <= time_to)
    if flags:
        for ch in flags.upper():
            if ch not in "SAFRPU":
                raise ApiError(400, "invalid_filter", "flags may only contain S, A, F, R, P, U")
            parts.append(pc.match_substring(pc.field("tcp_flags"), ch))
    if frames:
        parts.append(pc.field("number").isin(frames[:1000]))
    parts = [p for p in parts if p is not None]
    if not parts:
        return None
    expr = parts[0]
    for p in parts[1:]:
        expr = expr & p
    return expr


def _clean_rows(table: pa.Table) -> list[dict]:
    rows = table.to_pylist()
    for r in rows:
        if "rel_s" in r and r["rel_s"] is not None:
            r["rel_s"] = round(r["rel_s"], 9)
    return rows


def query_packets(principal: Principal, capture_id: str, *, columns: list[str] | None = None, sort: str = "number",
                  order: str = "asc", limit: int = 100, offset: int = 0, **filters) -> dict:
    _cap, dset = _dataset(principal, capture_id)
    cols = [c for c in (columns or DEFAULT_COLUMNS) if c in ALL_COLUMNS]
    if "number" not in cols:
        cols.insert(0, "number")
    expr = build_expression(**filters)
    if sort not in SORTABLE:
        raise ApiError(400, "invalid_sort", f"Cannot sort by {sort}")
    scanner_cols = list(dict.fromkeys(cols + [sort]))
    if sort == "number" and order == "asc":
        # Fast path: stream in file order and stop once the page is filled.
        matched, page = 0, []
        total = dset.count_rows(filter=expr) if expr is not None else dset.count_rows()
        for batch in dset.to_batches(columns=scanner_cols, filter=expr, batch_size=10_000):
            if matched + batch.num_rows <= offset:
                matched += batch.num_rows
                continue
            start = max(0, offset - matched)
            take = batch.slice(start, limit - len(page))
            page.extend(_clean_rows(pa.Table.from_batches([take]).select(cols)))
            matched += batch.num_rows
            if len(page) >= limit:
                break
        return {"items": page, "total": total, "limit": limit, "offset": offset, "columns": cols}
    table = dset.to_table(columns=scanner_cols, filter=expr)
    if table.num_rows > MAX_SORT_ROWS:
        raise ApiError(400, "too_many_rows", f"Narrow the filter to under {MAX_SORT_ROWS} packets to sort by {sort}")
    table = table.sort_by([(sort, "ascending" if order == "asc" else "descending"), ("number", "ascending")])
    page = table.slice(offset, limit).select(cols)
    return {"items": _clean_rows(page), "total": table.num_rows, "limit": limit, "offset": offset, "columns": cols}


def packet_row(principal: Principal, capture_id: str, frame: int) -> dict:
    _cap, dset = _dataset(principal, capture_id)
    t = dset.to_table(filter=pc.field("number") == frame)
    if t.num_rows == 0:
        raise ApiError(404, "not_found", f"Frame {frame} not found")
    return _clean_rows(t)[0]


def _simplify_tree(layers: dict, depth: int = 0) -> list[dict]:
    """Convert tshark JSON layers into a bounded tree of {name, value, children}."""
    out = []
    if depth > 12:
        return out
    for key, val in list(layers.items())[:400]:
        if key.endswith("_raw"):
            continue
        if isinstance(val, dict):
            out.append({"name": key, "children": _simplify_tree(val, depth + 1)})
        elif isinstance(val, list):
            children = []
            for i, item in enumerate(val[:100]):
                if isinstance(item, dict):
                    children.append({"name": f"{key}[{i}]", "children": _simplify_tree(item, depth + 1)})
                else:
                    children.append({"name": key, "value": str(item)[:512]})
            out.append({"name": key, "children": children})
        else:
            out.append({"name": key, "value": str(val)[:512]})
    return out


def packet_detail(principal: Principal, capture_id: str, frame: int, include_hex: bool = True) -> dict:
    cap = get_capture(principal, capture_id)
    row = packet_row(principal, capture_id, frame)
    if row.get("offset", -1) < 0:
        raise ApiError(409, "unavailable", "Packet bytes are not indexed for this frame")
    src = get_storage().materialize(cap["storage_key"], Path(get_settings().cache_dir))
    data = read_packet_bytes(src, row["offset"], row["caplen"])
    iface = (cap.get("metadata") or {}).get("interfaces", [])
    link_type = iface[row.get("iface") or 0]["link_type"] if iface and (row.get("iface") or 0) < len(iface) else 1
    work = Path(get_settings().work_dir)
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work, prefix="pkt_") as tmp:
        one = Path(tmp) / "one.pcap"
        write_single_packet_pcap(one, link_type, row["ts_ns"], data, row["len"])
        tree = dissect_single_frame(one)
    layers = (tree.get("_source") or {}).get("layers") or {}
    layers.pop("frame_raw", None)
    findings = list(TenantDB(principal.tenant_id).evidence_references.find(
        {"capture_id": capture_id, "kind": "packet", "ref": frame}, {"finding_id": 1, "label": 1, "_id": 0}))
    result = {
        "summary": row,
        "tree": _simplify_tree({k: v for k, v in layers.items() if not k.endswith("_raw")}),
        "cited_by": findings,
        "note": "The detail tree is dissected from this single frame; stream-level analysis (retransmission, reassembly) "
                "comes from the full-capture pass shown in the summary.",
    }
    if include_hex:
        result["hex"] = data.hex()
        result["length"] = len(data)
    return result


def stream_payload(principal: Principal, capture_id: str, flow: str, max_bytes: int = 65536) -> dict:
    """Reassembled payload of a conversation in capture order (tshark follow), per direction."""
    cap = get_capture(principal, capture_id)
    if cap.get("status") != "analyzed":
        raise ApiError(409, "not_analyzed", "Capture has not been analysed yet")
    if len(flow) < 2 or flow[0] not in "tu" or not flow[1:].isdigit():
        raise ApiError(400, "invalid_flow", "Flow ids look like t12 (TCP) or u3 (UDP)")
    fdoc = TenantDB(principal.tenant_id).flows.find_one({"capture_id": capture_id, "local_id": flow})
    if not fdoc:
        raise ApiError(404, "not_found", "Flow not found")
    src_path = get_storage().materialize(cap["storage_key"], Path(get_settings().cache_dir))
    res = follow_stream(src_path, "tcp" if flow[0] == "t" else "udp", int(flow[1:]), max_bytes=max_bytes)
    printable = {i: 46 for i in list(range(0, 9)) + list(range(14, 32)) + list(range(127, 256))}
    chunks = [{"dir": "c2s" if c["node"] == 0 else "s2c", "hex": c["data"].hex(),
               "text": c["data"].decode("latin-1").translate(printable)} for c in res["chunks"]]
    audit(principal, "capture.payload_view", "flow", f"{capture_id}-{flow}", {"bytes": res["bytes"]})
    return {"flow": flow, "nodes": res["nodes"], "chunks": chunks, "bytes": res["bytes"], "truncated": res["truncated"],
            "note": "Reassembled payload exactly as captured; node 0 is the side that sent the first packet. "
                    "Encrypted protocols (TLS) remain encrypted."}


def export_packets(principal: Principal, capture_id: str, fmt: str, include_sensitive: bool = False, **filters) -> tuple[bytes, str]:
    principal.require("export:data")
    _cap, dset = _dataset(principal, capture_id)
    cols = [c for c in ALL_COLUMNS if include_sensitive or c not in SENSITIVE_EXPORT_COLUMNS]
    expr = build_expression(**filters)
    table = dset.to_table(columns=cols, filter=expr)
    if table.num_rows > 1_000_000:
        raise ApiError(400, "too_many_rows", "Export at most 1,000,000 packets; narrow the filter")
    audit(principal, "export.packets", "capture", capture_id,
          {"format": fmt, "rows": table.num_rows, "sensitive_columns": include_sensitive})
    if fmt == "json":
        return json.dumps({"capture_id": capture_id, "columns": cols, "packets": table.to_pylist()}, default=str).encode(), "application/json"
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for row in table.to_pylist():
        w.writerow(["" if row[c] is None else _csv_safe(row[c]) for c in cols])
    return buf.getvalue().encode(), "text/csv"


def _csv_safe(v):
    """Neutralise spreadsheet formula injection in exported text cells."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v
