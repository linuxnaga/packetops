"""End-to-end analysis of one capture: validate → dissect → aggregate → rules → persist.

Bulk per-packet data goes to a Parquet file in object storage (one row per
frame, written in batches), never to MongoDB. MongoDB receives bounded
documents: one per conversation, one per finding, evidence references and a
single statistics summary per capture.
"""

from __future__ import annotations

import logging
import struct
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from app.core.config import get_settings
from app.db import TenantDB, utcnow
from app.storage import get_storage, tenant_key

from .aggregator import Aggregator
from .pcapfile import CaptureReader, MalformedCaptureError
from .rules import run_rules
from .rules.context import RuleContext, tcp_timeline
from .state import DNS_RCODES, TcpFlow, UdpFlow
from .tshark import AnalysisCancelled, dissect, tshark_version

log = logging.getLogger(__name__)

ENGINE_VERSION = "1.0.0"
BATCH_ROWS = 50_000
INDEX_REC = struct.Struct("<qii")  # data offset, caplen, interface

PACKET_SCHEMA = pa.schema([
    ("number", pa.int64()), ("ts_ns", pa.int64()), ("rel_s", pa.float64()), ("iface", pa.int32()),
    ("len", pa.int32()), ("caplen", pa.int32()), ("offset", pa.int64()),
    ("protocol", pa.string()), ("protocols", pa.string()), ("src", pa.string()), ("dst", pa.string()),
    ("sport", pa.int32()), ("dport", pa.int32()), ("transport", pa.string()), ("flow", pa.string()),
    ("tcp_flags", pa.string()), ("tcp_seq", pa.int64()), ("tcp_ack", pa.int64()), ("tcp_len", pa.int32()),
    ("tcp_win", pa.int64()), ("analysis", pa.string()), ("expert", pa.string()), ("info", pa.string()),
    ("vlan", pa.string()), ("eth_src", pa.string()), ("eth_dst", pa.string()), ("ttl", pa.int32()),
    ("dns_qname", pa.string()), ("http_host", pa.string()), ("tls_sni", pa.string()), ("f5_flowid", pa.string()),
])


class Progress:
    def __init__(self, tdb: TenantDB, job_id: str):
        self.tdb, self.job_id = tdb, job_id
        self._last = 0.0

    def __call__(self, stage: str, pct: float, message: str = "", force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last < 0.5:
            return
        self._last = now
        self.tdb.analysis_jobs.update_one(
            {"_id": self.job_id},
            {"$set": {"stage": stage, "progress": round(min(100.0, pct), 1), "message": message, "updated_at": utcnow()},
             "$push": {"stages": {"$each": [{"stage": stage, "at": utcnow(), "message": message}], "$slice": -50}}}
            if force else
            {"$set": {"stage": stage, "progress": round(min(100.0, pct), 1), "message": message, "updated_at": utcnow()}},
        )

    def cancelled(self) -> bool:
        job = self.tdb.analysis_jobs.find_one({"_id": self.job_id}, {"cancel_requested": 1})
        return bool(job and job.get("cancel_requested"))


def _flow_doc(fl: TcpFlow | UdpFlow, capture_id: str, findings_by_flow: dict[str, list[str]]) -> dict:
    is_tcp = isinstance(fl, TcpFlow)
    local = f"{'t' if is_tcp else 'u'}{fl.stream}"
    doc = {
        "_id": f"{capture_id}-{local}",
        "capture_id": capture_id,
        "local_id": local,
        "transport": "tcp" if is_tcp else "udp",
        "stream": fl.stream,
        "client_ip": fl.client[0], "client_port": fl.client[1],
        "server_ip": fl.server[0], "server_port": fl.server[1],
        "ip_version": fl.ip_version,
        "first_frame": fl.first_frame, "last_frame": fl.last_frame,
        "first_ts_ns": fl.first_ts, "last_ts_ns": fl.last_ts,
        "duration_ms": round((fl.last_ts - fl.first_ts) / 1e6, 3),
        "packets_c2s": fl.packets["c2s"], "packets_s2c": fl.packets["s2c"],
        "bytes_c2s": fl.bytes["c2s"], "bytes_s2c": fl.bytes["s2c"],
        "packets": fl.total_packets,
        "app_protocols": sorted(fl.app_protocols),
        "finding_ids": findings_by_flow.get(local, []),
    }
    if not is_tcp:
        doc.update(state="udp", issue_score=len(doc["finding_ids"]) * 10)
        return doc
    assert isinstance(fl, TcpFlow)
    retrans = fl.retrans["c2s"].count + fl.retrans["s2c"].count
    doc.update(
        state=fl.state,
        direction_inferred=fl.direction_inferred,
        handshake={
            "syn_count": fl.syn_count, "synack_count": fl.synack_count, "complete": fl.handshake_complete,
            "syns": fl.syns, "synacks": fl.synacks, "ack": fl.handshake_ack,
            "rtt_ms": round(fl.handshake_rtt_ns / 1e6, 3) if fl.handshake_rtt_ns else None,
            "connect_ms": round(fl.connect_time_ns / 1e6, 3) if fl.connect_time_ns else None,
        },
        payload_c2s=fl.payload["c2s"], payload_s2c=fl.payload["s2c"],
        first_data={d: {"frame": v[0], "ts_ns": v[1]} for d, v in fl.first_data.items()},
        last_data={d: {"frame": v[0], "ts_ns": v[1]} for d, v in fl.last_data.items()},
        mss={"client": fl.mss.get("c2s"), "server": fl.mss.get("s2c")},
        wscale={"client": fl.wscale.get("c2s"), "server": fl.wscale.get("s2c")},
        max_segment={"client": fl.max_segment["c2s"], "server": fl.max_segment["s2c"]},
        rsts=fl.rsts, fins=fl.fins,
        analysis={
            "retransmissions_c2s": fl.retrans["c2s"].to_dict(), "retransmissions_s2c": fl.retrans["s2c"].to_dict(),
            "fast_retransmissions": fl.fast_retrans.to_dict(), "spurious_retransmissions": fl.spurious.to_dict(),
            "duplicate_acks": fl.dupacks.to_dict(), "out_of_order": fl.ooo.to_dict(),
            "lost_segments": fl.lost.to_dict(), "acked_unseen": fl.ack_lost.to_dict(),
            "zero_window_c2s": fl.zero_window["c2s"].to_dict(), "zero_window_s2c": fl.zero_window["s2c"].to_dict(),
            "window_full": fl.window_full.to_dict(), "keepalives": fl.keepalive.to_dict(),
            "reused_ports": fl.reused_ports,
        },
        retransmissions=retrans,
        max_idle_ms=round(fl.max_gap_ns / 1e6, 3),
        max_idle_frames=list(fl.max_gap_frames) if fl.max_gap_frames else None,
        tls=fl.tls.to_dict() if fl.tls else None,
        http=[h.to_dict() for h in fl.http[:200]],
        http_requests=fl.http_count,
        h2_streams=len(fl.h2_streams),
        f5=fl.f5 or None,
        icmp=fl.icmp[:20],
        vlans=sorted(fl.vlans),
        timeline=tcp_timeline(fl, limit=60),
        issue_score=len(doc["finding_ids"]) * 10 + retrans + fl.rst_count * 3 + fl.dupacks.count,
    )
    return doc


def _limitations(agg: Aggregator, meta: dict, tshark_packets: int) -> list[dict]:
    lim: list[dict] = []
    tls_flows = [fl for fl in agg.tcp.values() if fl.tls]
    if tls_flows and not meta.get("has_decryption_secrets"):
        lim.append({"code": "encrypted_payload", "severity": "info",
                    "text": f"{len(tls_flows)} TLS conversation(s): application payload (HTTP inside TLS) is encrypted and was not "
                            "decoded. Handshake metadata (SNI, versions, certificates in TLS ≤1.2, cleartext alerts) is analysed."})
    one_dir = [fl for fl in agg.tcp.values() if not (fl.packets["c2s"] and fl.packets["s2c"])]
    if one_dir:
        lim.append({"code": "one_direction", "severity": "warning",
                    "text": f"{len(one_dir)} TCP conversation(s) show packets in one direction only (missing capture direction, "
                            "asymmetric routing, unanswered attempts, or capture filter)."})
    mid = [fl for fl in agg.tcp.values() if not fl.syn_seen and not fl.synack_count]
    if mid:
        lim.append({"code": "incomplete_handshake", "severity": "info",
                    "text": f"{len(mid)} TCP conversation(s) started before the capture; handshake parameters (MSS, window scale) "
                            "are unknown and client/server roles were inferred from port numbers."})
    lost = sum(fl.lost.count for fl in agg.tcp.values())
    if lost:
        lim.append({"code": "missing_packets", "severity": "warning",
                    "text": f"{lost} sequence gap(s) where segments were not captured ('previous segment not captured'). "
                            "This can be real loss upstream of the capture point or capture drops."})
    if meta.get("truncated_packets"):
        lim.append({"code": "snaplen", "severity": "warning",
                    "text": f"{meta['truncated_packets']} packet(s) were truncated by the capture snap length; payload-based "
                            "analysis (HTTP, TLS certificates) may be incomplete."})
    if meta.get("truncated_tail"):
        lim.append({"code": "truncated_file", "severity": "warning",
                    "text": "The capture file ends in the middle of a packet; the final partial packet was ignored."})
    if agg.malformed.count:
        lim.append({"code": "malformed", "severity": "warning",
                    "text": f"{agg.malformed.count} packet(s) were reported as malformed by the dissector."})
    if agg.quic_frames:
        lim.append({"code": "quic", "severity": "info",
                    "text": f"{agg.quic_frames} QUIC packet(s): HTTP/3 content is encrypted and is not analysed."})
    undissected = agg.layers.get("data", 0)
    if undissected:
        lim.append({"code": "undissected", "severity": "info",
                    "text": f"{undissected} packet(s) carry payload that no dissector recognised (unknown port or unsupported "
                            "encapsulation)."})
    if agg.dropped_flows:
        lim.append({"code": "flow_limit", "severity": "warning",
                    "text": f"Flow tracking limit reached; {agg.dropped_flows} packet(s) belong to conversations that were not tracked."})
    if tshark_packets != meta.get("packet_count"):
        lim.append({"code": "dissector_mismatch", "severity": "warning",
                    "text": f"The dissector processed {tshark_packets} frames but the file index contains {meta.get('packet_count')}."})
    if meta.get("out_of_order_timestamps"):
        lim.append({"code": "timestamp_order", "severity": "info",
                    "text": f"{meta['out_of_order_timestamps']} packet(s) have timestamps earlier than the previous packet "
                            "(multi-interface merge or clock adjustments). Original order is preserved."})
    if agg.dns_stats.get("pending_at_capture_end"):
        lim.append({"code": "dns_window", "severity": "info",
                    "text": f"{agg.dns_stats['pending_at_capture_end']} DNS query(ies) were sent within 2 s of the end of the "
                            "capture; their responses may simply be outside the capture window."})
    return lim


def _summary_doc(agg: Aggregator, capture_id: str) -> dict:
    endpoints = sorted(agg.endpoints.items(), key=lambda kv: kv[1][1] + kv[1][3], reverse=True)[:50]
    io = [{"t": int(k), "packets": v[0], "bytes": v[1], "retransmissions": v[2], "resets": v[3]}
          for k, v in sorted(agg.io.items())]
    dns_rcodes: dict[str, int] = {}
    for t in agg.dns_txns:
        if t.rcode is not None:
            name = DNS_RCODES.get(t.rcode, str(t.rcode))
            dns_rcodes[name] = dns_rcodes.get(name, 0) + 1
    return {
        "_id": capture_id,
        "capture_id": capture_id,
        "protocols": [{"name": k, "packets": v} for k, v in agg.highest_protocols.most_common(40)],
        "layers": [{"name": k, "packets": v} for k, v in agg.layers.most_common(80)],
        "endpoints": [{"ip": ip, "packets_tx": v[0], "bytes_tx": v[1], "packets_rx": v[2], "bytes_rx": v[3]} for ip, v in endpoints],
        "io_bucket_ns": agg.bucket_ns,
        "io": io,
        "ip_versions": {str(k): v for k, v in agg.ip_versions.items()},
        "vlans": dict(agg.vlan_ids.most_common(50)),
        "qinq_frames": agg.qinq_frames,
        "encapsulation": dict(agg.encapsulation),
        "arp": dict(agg.arp),
        "icmp": [{"type": k[0], "code": k[1], "count": v} for k, v in agg.icmp_counts.most_common(30)],
        "icmp_errors": agg.icmp_events[:200],
        "dns": {**dict(agg.dns_stats), "rcodes": dns_rcodes, "unmatched_responses": agg.dns_unmatched_responses.count},
        "dns_transactions": [t.to_dict() for t in agg.dns_txns[:2000]],
        "expert": dict(agg.expert_levels),
        "expert_messages": [{"message": k, "count": v} for k, v in agg.expert_messages.most_common(30)],
        "fragments": agg.fragments.to_dict(),
        "malformed": agg.malformed.to_dict(),
        "f5": {"trailer_frames": agg.f5_trailer_frames, "virtual_servers": dict(agg.f5_vips.most_common(50))},
        "tcp_conversations": len(agg.tcp),
        "udp_conversations": len(agg.udp),
        "other_conversations": len(agg.other_convs),
        "http2_frames": agg.h2_frames,
        "quic_frames": agg.quic_frames,
    }


def analyze_capture(tenant_id: str, capture_id: str, job_id: str, on_complete: Callable[[dict], None] | None = None) -> dict:
    settings = get_settings()
    tdb = TenantDB(tenant_id)
    cap = tdb.captures.find_one({"_id": capture_id})
    if not cap:
        raise LookupError("capture not found")
    progress = Progress(tdb, job_id)
    storage = get_storage()
    started = time.monotonic()
    tdb.analysis_jobs.update_one({"_id": job_id}, {"$set": {"status": "running", "started_at": utcnow(), "updated_at": utcnow()},
                                                   "$inc": {"attempts": 1}})
    tdb.captures.update_one({"_id": capture_id}, {"$set": {"status": "analyzing", "analysis_job_id": job_id}})
    work = Path(settings.work_dir)
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work, prefix="job_") as tmp:
        tmpdir = Path(tmp)
        try:
            src = storage.materialize(cap["storage_key"], Path(settings.cache_dir))
            progress("index", 2, "Validating evidence file structure", force=True)
            reader = CaptureReader(src, max_packets=settings.max_packets_per_capture)
            index_path = tmpdir / "index.bin"
            n = 0
            with index_path.open("wb") as idx:
                for entry in reader.packets():
                    idx.write(INDEX_REC.pack(entry.data_offset, entry.caplen, entry.interface_id))
                    n += 1
                    if n % 50_000 == 0:
                        progress("index", 2 + 13 * min(1.0, entry.data_offset / max(1, cap["size_bytes"])), f"Indexed {n} packets")
                        if progress.cancelled():
                            raise AnalysisCancelled("Analysis cancelled")
            meta = reader.metadata
            assert meta is not None
            metad = meta.to_dict()
            if meta.packet_count == 0:
                raise MalformedCaptureError("Capture contains no packets")
            progress("dissect", 15, f"Dissecting {meta.packet_count} packets with tshark", force=True)

            agg = Aggregator(meta.first_ts_ns or 0, meta.duration_ns, settings.evidence_refs_per_kind,
                             settings.max_flows_tracked, settings.redact_query_strings)
            parquet_path = tmpdir / "packets.parquet"
            writer = pq.ParquetWriter(parquet_path, PACKET_SCHEMA, compression="zstd")
            batch: list[dict] = []
            idx_fh = index_path.open("rb")
            total = meta.packet_count

            def flush() -> None:
                if batch:
                    writer.write_table(pa.Table.from_pylist(batch, schema=PACKET_SCHEMA))
                    batch.clear()

            def on_record(rec: dict) -> None:
                row = agg.observe(rec)
                raw = idx_fh.read(INDEX_REC.size)
                if len(raw) == INDEX_REC.size:
                    off, caplen, _iface = INDEX_REC.unpack(raw)
                    row["offset"], row["caplen"] = off, caplen
                else:
                    row["offset"], row["caplen"] = -1, rec.get("caplen") or 0
                batch.append(row)
                if len(batch) >= BATCH_ROWS:
                    flush()
                if agg.packets % 5000 == 0:
                    progress("dissect", 15 + 70 * agg.packets / max(1, total), f"Dissected {agg.packets}/{total} packets")

            try:
                result = dissect(src, on_record, should_cancel=progress.cancelled)
                flush()
            finally:
                writer.close()
                idx_fh.close()

            progress("correlate", 86, "Reconstructing conversations and running detection rules", force=True)
            agg.finalize_dns(meta.last_ts_ns or 0)
            f5_config = None
            if cap.get("f5_config_id"):
                f5_config = tdb.f5_configuration_metadata.find_one({"_id": cap["f5_config_id"]})
            ctx = RuleContext(agg, metad, meta.last_ts_ns or 0, meta.first_ts_ns or 0,
                              f5_presence={"trailer_frames": agg.f5_trailer_frames}, f5_config=f5_config)
            findings, rule_errors = run_rules(ctx)

            progress("persist", 92, "Storing derived data", force=True)
            derived_key = tenant_key(tenant_id, "captures", capture_id, "derived", "packets.parquet")
            storage.put_file(derived_key, parquet_path, "application/vnd.apache.parquet")

            # Replace any previous derived data (re-analysis is idempotent).
            for col in ("flows", "findings", "evidence_references", "packet_summaries"):
                getattr(tdb, col).delete_many({"capture_id": capture_id})

            now = utcnow()
            findings_by_flow: dict[str, list[str]] = {}
            evidence_docs = []
            finding_docs = []
            for f in findings:
                fid = f"{capture_id}-{f['short_id']}"
                for lf in f["flows"]:
                    findings_by_flow.setdefault(lf, []).append(f["short_id"])
                finding_docs.append({
                    **f, "_id": fid, "capture_id": capture_id, "analysis_job_id": job_id, "created_at": now,
                    "status": "open", "assignee": None, "notes": [], "training": bool(cap.get("training")),
                    "flow_ids": [f"{capture_id}-{lf}" for lf in f["flows"]],
                })
                for p in f["packets"]:
                    evidence_docs.append({"capture_id": capture_id, "finding_id": fid, "kind": "packet", "ref": p["frame"],
                                          "label": p.get("role")})
                for lf in f["flows"]:
                    evidence_docs.append({"capture_id": capture_id, "finding_id": fid, "kind": "flow", "ref": lf, "label": None})
                evidence_docs.append({"capture_id": capture_id, "finding_id": fid, "kind": "rule", "ref": f["rule_id"],
                                      "label": f["rule_version"]})
            tdb.findings.insert_many(finding_docs)
            for i in range(0, len(evidence_docs), 5000):
                tdb.evidence_references.insert_many(evidence_docs[i : i + 5000])
            flow_docs = [_flow_doc(fl, capture_id, findings_by_flow) for fl in agg.tcp.values()]
            flow_docs += [_flow_doc(fl, capture_id, findings_by_flow) for fl in agg.udp.values()]
            for i in range(0, len(flow_docs), 1000):
                tdb.flows.insert_many(flow_docs[i : i + 1000])
            tdb.packet_summaries.insert_one(_summary_doc(agg, capture_id))

            limitations = _limitations(agg, metad, result.packets)
            tcp = list(agg.tcp.values())
            stats = {
                "packets": meta.packet_count,
                "bytes": meta.total_original_bytes,
                "duration_s": round(meta.duration_ns / 1e9, 6),
                "tcp_conversations": len(tcp),
                "udp_conversations": len(agg.udp),
                "retransmissions": sum(fl.retrans["c2s"].count + fl.retrans["s2c"].count for fl in tcp),
                "syn_retransmissions": sum(1 for fl in tcp for s in fl.syns if s["retrans"]),
                "incomplete_handshakes": sum(1 for fl in tcp if fl.syn_seen and not fl.handshake_complete),
                "resets": sum(fl.rst_count for fl in tcp),
                "tls_handshakes": sum(1 for fl in tcp if fl.tls and fl.tls.client_hello),
                "tls_alerts": sum(len(fl.tls.alerts) for fl in tcp if fl.tls),
                "http_requests": sum(fl.http_count for fl in tcp),
                "dns_queries": agg.dns_stats.get("queries", 0),
                "dns_unanswered": agg.dns_stats.get("unanswered", 0),
                "findings": len(findings),
                "findings_by_severity": {s: sum(1 for f in findings if f["severity"] == s)
                                         for s in ("critical", "high", "medium", "low", "info")},
            }
            duration = time.monotonic() - started
            tdb.captures.update_one({"_id": capture_id}, {"$set": {
                "status": "analyzed", "metadata": metad, "stats": stats, "limitations": limitations,
                "derived_key": derived_key, "analyzed_at": utcnow(),
                "analysis": {"engine_version": ENGINE_VERSION, "tshark_version": tshark_version(), "job_id": job_id,
                             "duration_s": round(duration, 3), "rule_errors": rule_errors,
                             "dissector_stderr": result.stderr_tail[-500:] or None},
            }})
            tdb.analysis_jobs.update_one({"_id": job_id}, {"$set": {
                "status": "completed", "progress": 100.0, "stage": "done", "message": "Analysis complete",
                "finished_at": utcnow(), "updated_at": utcnow(), "duration_s": round(duration, 3)},
                "$push": {"stages": {"stage": "done", "at": utcnow(), "message": f"{len(findings)} finding(s)"}}})
            summary = {"capture_id": capture_id, "stats": stats, "limitations": limitations}
            if on_complete:
                on_complete(summary)
            return summary
        except AnalysisCancelled:
            tdb.analysis_jobs.update_one({"_id": job_id}, {"$set": {"status": "cancelled", "updated_at": utcnow(), "finished_at": utcnow(),
                                                                    "message": "Cancelled by user"}})
            tdb.captures.update_one({"_id": capture_id}, {"$set": {"status": "cancelled"}})
            raise
        except MalformedCaptureError as exc:
            tdb.analysis_jobs.update_one({"_id": job_id}, {"$set": {"status": "failed", "updated_at": utcnow(), "finished_at": utcnow(),
                                                                    "error": {"type": "malformed_capture", "message": str(exc)}}})
            tdb.captures.update_one({"_id": capture_id}, {"$set": {"status": "rejected", "error": str(exc)}})
            raise
        except Exception as exc:
            log.exception("analysis failed", extra={"capture_id": capture_id, "job_id": job_id})
            tdb.analysis_jobs.update_one({"_id": job_id}, {"$set": {"status": "failed", "updated_at": utcnow(), "finished_at": utcnow(),
                                                                    "error": {"type": type(exc).__name__, "message": str(exc)[:500]}}})
            tdb.captures.update_one({"_id": capture_id}, {"$set": {"status": "failed", "error": "Analysis failed; see job diagnostics"}})
            raise
