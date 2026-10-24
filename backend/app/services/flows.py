"""Conversation (flow) queries, connection graph and TCP sequence data."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import pyarrow.compute as pc
import pyarrow.dataset as ds

from app.core.config import get_settings
from app.core.errors import ApiError, not_found
from app.core.security import Principal
from app.db import TenantDB, clean
from app.services.captures import get_capture
from app.storage import get_storage

LIST_PROJECTION = {"timeline": 0, "http": 0, "analysis": 0, "tls.certificates": 0, "tls.client_hello.cipher_suites": 0,
                   "icmp": 0, "handshake.syns": 0, "handshake.synacks": 0, "rsts": 0, "fins": 0}
FLOW_SORTS = {"issue_score": -1, "first_ts_ns": 1, "packets": -1, "bytes_s2c": -1, "duration_ms": -1, "retransmissions": -1}
LOCAL_ID = re.compile(r"^[tu]\d{1,9}$")


def resolve_flow_id(capture_id: str | None, flow_id: str) -> tuple[str | None, str]:
    """Accept a global id 'cap_x-t12' or a local id 't12' (needs capture context)."""
    if LOCAL_ID.match(flow_id):
        return capture_id, flow_id
    m = re.match(r"^(cap_[0-9a-f]{20})-([tu]\d{1,9})$", flow_id)
    if not m:
        raise ApiError(400, "invalid_flow_id", "Flow ids look like t12, u3 or cap_<id>-t12")
    return m.group(1), m.group(2)


def list_flows(principal: Principal, capture_id: str, *, transport: str | None = None, state: str | None = None,
               ip: str | None = None, port: int | None = None, has_findings: bool | None = None, sort: str = "issue_score",
               limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
    get_capture(principal, capture_id)
    flt: dict = {"capture_id": capture_id}
    if transport:
        flt["transport"] = transport
    if state:
        flt["state"] = state
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError as exc:
            raise ApiError(400, "invalid_ip", "ip must be an IP address") from exc
        flt["$or"] = [{"client_ip": ip}, {"server_ip": ip}]
    if port is not None:
        flt.setdefault("$and", []).append({"$or": [{"client_port": port}, {"server_port": port}]})
    if has_findings is not None:
        flt["finding_ids.0"] = {"$exists": has_findings}
    if sort not in FLOW_SORTS:
        raise ApiError(400, "invalid_sort", f"sort must be one of {', '.join(FLOW_SORTS)}")
    tdb = TenantDB(principal.tenant_id)
    total = tdb.flows.count_documents(flt)
    cur = tdb.flows.find(flt, LIST_PROJECTION).sort([(sort, FLOW_SORTS[sort]), ("first_ts_ns", 1)]).skip(offset).limit(limit)
    return [clean(d) for d in cur], total


def get_flow(principal: Principal, capture_id: str | None, flow_id: str) -> dict:
    cap_id, local = resolve_flow_id(capture_id, flow_id)
    if not cap_id:
        raise ApiError(400, "capture_required", "A capture must be selected to use a short flow id")
    get_capture(principal, cap_id)
    doc = TenantDB(principal.tenant_id).flows.find_one({"capture_id": cap_id, "local_id": local})
    if not doc:
        raise not_found("Flow")
    return clean(doc)


def flow_sequence(principal: Principal, capture_id: str, local_id: str, limit: int = 20000) -> dict:
    """Per-packet seq/ack/len points for the TCP sequence chart (Stevens graph), with retransmission markers."""
    cap = get_capture(principal, capture_id)
    if not cap.get("derived_key"):
        raise ApiError(409, "not_analyzed", "Capture has not been analysed yet")
    flow = get_flow(principal, capture_id, local_id)
    dset = ds.dataset(str(get_storage().materialize(cap["derived_key"], Path(get_settings().cache_dir))), format="parquet")
    t = dset.to_table(columns=["number", "rel_s", "src", "sport", "tcp_seq", "tcp_ack", "tcp_len", "tcp_win", "tcp_flags", "analysis"],
                      filter=pc.field("flow") == local_id)
    rows = t.slice(0, limit).to_pylist()
    client = (flow["client_ip"], flow["client_port"])
    for r in rows:
        r["dir"] = "c2s" if (r["src"], r["sport"]) == client else "s2c"
        del r["src"], r["sport"]
    return {"flow": local_id, "points": rows, "truncated": t.num_rows > limit}


def flow_graph(principal: Principal, capture_id: str, limit: int = 300) -> dict:
    """Endpoint graph: nodes are IPs, edges aggregate conversations client→server:port."""
    get_capture(principal, capture_id)
    tdb = TenantDB(principal.tenant_id)
    edges = list(tdb.flows.aggregate([
        {"$match": {"capture_id": capture_id}},
        {"$group": {"_id": {"c": "$client_ip", "s": "$server_ip", "p": "$server_port", "t": "$transport"},
                    "flows": {"$sum": 1}, "packets": {"$sum": "$packets"},
                    "bytes": {"$sum": {"$add": ["$bytes_c2s", "$bytes_s2c"]}},
                    "issues": {"$sum": {"$size": {"$ifNull": ["$finding_ids", []]}}},
                    "states": {"$addToSet": "$state"}, "sample": {"$first": "$local_id"}}},
        {"$sort": {"issues": -1, "packets": -1}},
        {"$limit": limit},
    ]))
    nodes: dict[str, dict] = {}
    out_edges = []
    for e in edges:
        k = e["_id"]
        for ip, role in ((k["c"], "client"), (k["s"], "server")):
            n = nodes.setdefault(ip, {"id": ip, "roles": set(), "packets": 0, "issues": 0})
            n["roles"].add(role)
            n["packets"] += e["packets"]
            n["issues"] += e["issues"]
        out_edges.append({"source": k["c"], "target": k["s"], "port": k["p"], "transport": k["t"], "flows": e["flows"],
                          "packets": e["packets"], "bytes": e["bytes"], "issues": e["issues"], "states": sorted(e["states"]),
                          "sample_flow": e["sample"]})
    return {"nodes": [{**n, "roles": sorted(n["roles"])} for n in nodes.values()], "edges": out_edges}
