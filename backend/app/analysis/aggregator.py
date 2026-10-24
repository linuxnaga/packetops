"""Per-frame aggregation: turns tshark records into flows, transactions and statistics."""

from __future__ import annotations

import logging
from collections import Counter

from .certs import parse_certificate_hex
from .state import (
    ASM_BLOCK_RE,
    ASM_SUPPORT_ID_RE,
    EXPERT_LEVELS,
    TLS_ALERTS,
    TLS_VERSIONS,
    DnsTxn,
    EvidenceList,
    HttpTxn,
    TcpFlow,
    TlsState,
    UdpFlow,
    decode_bigip_cookie,
    redact_query,
)

log = logging.getLogger(__name__)

TCP_FLAG_LETTERS = [(0x02, "S"), (0x10, "A"), (0x08, "P"), (0x01, "F"), (0x04, "R"), (0x20, "U"), (0x40, "E"), (0x80, "C")]
ENCAP_PROTOCOLS = {"vxlan", "geneve", "gre", "erspan", "mpls", "pppoe", "gtp", "l2tp", "ipip", "nsh"}
GENERIC_LAYERS = {"eth", "ethertype", "ip", "ipv6", "tcp", "udp", "data", "frame", "vlan", "sll", "f5ethtrailer"}
NOISE_LAYERS = {"data", "data-text-lines", "media", "json", "xml", "image-gif", "image-jfif", "png"}
NOISE_PREFIXES = ("x509", "pkcs", "pkix", "ber", "per", "cms", "ocsp")
MAX_ENDPOINTS = 100_000
MAX_DNS_TXNS = 20_000
MAX_HTTP_PER_FLOW = 500


def flags_str(flags: int | None) -> str:
    if flags is None:
        return ""
    return "".join(letter for bit, letter in TCP_FLAG_LETTERS if flags & bit)


def _tls_version(v: str | None) -> str | None:
    if not v:
        return None
    try:
        return TLS_VERSIONS.get(int(v, 16), v)
    except ValueError:
        return v


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _pick(values, inner: bool):
    if not values:
        return None
    if not isinstance(values, list):
        return values
    return values[-1] if inner else values[0]


def _cookie_names(raw_values: list[str] | None) -> list[str]:
    names: list[str] = []
    for raw in raw_values or []:
        for part in raw.split(";"):
            if "=" in part:
                n = part.split("=", 1)[0].strip()
                if n and n.lower() not in ("path", "domain", "expires", "max-age", "secure", "httponly", "samesite"):
                    names.append(n[:80])
    return list(dict.fromkeys(names))[:30]


def _bigip_cookies(raw_values: list[str] | None) -> list[dict]:
    out = []
    for raw in raw_values or []:
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("BIGipServer") and "=" in part:
                name, value = part.split("=", 1)
                decoded = decode_bigip_cookie(value)
                entry = {"cookie": name[:120], "encrypted": decoded is None}
                if decoded:
                    entry["member_ip"], entry["member_port"] = decoded
                out.append(entry)
    return out


class Aggregator:
    def __init__(self, first_ts_ns: int, duration_ns: int, evidence_cap: int = 50, max_flows: int = 500_000,
                 redact_queries: bool = True):
        self.first_ts = first_ts_ns
        self.bucket_ns = max(1_000_000_000, duration_ns // 600 + 1)
        self.evidence_cap = evidence_cap
        self.max_flows = max_flows
        self.redact = redact_queries
        self.tcp: dict[int, TcpFlow] = {}
        self.udp: dict[int, UdpFlow] = {}
        self.dropped_flows = 0
        self.tuple_index: dict[tuple, int] = {}
        self.dns_pending: dict[tuple, DnsTxn] = {}
        self.dns_txns: list[DnsTxn] = []
        self.dns_stats = Counter()
        self.dns_unmatched_responses = EvidenceList(evidence_cap)
        self.highest_protocols: Counter = Counter()
        self.layers: Counter = Counter()
        self.endpoints: dict[str, list[int]] = {}
        self.io: dict[int, list[int]] = {}
        self.icmp_events: list[dict] = []
        self.icmp_counts: Counter = Counter()
        self.arp: Counter = Counter()
        self.expert_levels: Counter = Counter()
        self.expert_messages: Counter = Counter()
        self.malformed = EvidenceList(evidence_cap)
        self.fragments = EvidenceList(evidence_cap)
        self.encapsulation: Counter = Counter()
        self.vlan_ids: Counter = Counter()
        self.qinq_frames = 0
        self.f5_trailer_frames = 0
        self.f5_vips: Counter = Counter()
        self.ip_versions: Counter = Counter()
        self.packets = 0
        self.bytes = 0
        self.other_convs: Counter = Counter()
        self.quic_frames = 0
        self.h2_frames = 0

    # ------------------------------------------------------------------ main
    def observe(self, rec: dict) -> dict:
        frame = rec["number"]
        ts = epoch_to_ns(rec.get("time_epoch"))
        length = rec.get("len") or 0
        self.packets += 1
        self.bytes += length
        protocols = (rec.get("protocols") or "").split(":")
        pset = set(protocols)
        for p in pset:
            if not p.startswith(NOISE_PREFIXES):
                self.layers[p] += 1
        highest = next((p for p in reversed(protocols) if p not in NOISE_LAYERS and not p.startswith(NOISE_PREFIXES)),
                       protocols[-1] if protocols else "")
        self.highest_protocols[rec.get("protocol") or highest.upper()] += 1
        is_icmp = "icmp" in pset or "icmpv6" in pset
        inner = not is_icmp
        for enc in ENCAP_PROTOCOLS & pset:
            self.encapsulation[enc] += 1
        vlans = rec.get("vlan") or []
        for v in vlans:
            if v is not None:
                self.vlan_ids[str(v)] += 1
        if len(vlans) > 1:
            self.qinq_frames += 1

        src = _pick(rec.get("ip_src"), inner) or _pick(rec.get("ip6_src"), inner)
        dst = _pick(rec.get("ip_dst"), inner) or _pick(rec.get("ip6_dst"), inner)
        ipver = 4 if rec.get("ip_src") else (6 if rec.get("ip6_src") else None)
        if ipver:
            self.ip_versions[ipver] += 1
        if rec.get("arp_opcode"):
            self.arp["request" if rec["arp_opcode"] == "1" else "reply"] += 1
            src = src or rec.get("arp_src")
            dst = dst or rec.get("arp_dst")

        bucket = (ts - self.first_ts) // self.bucket_ns if ts >= self.first_ts else 0
        io = self.io.setdefault(bucket, [0, 0, 0, 0])
        io[0] += 1
        io[1] += length

        sev_levels = [EXPERT_LEVELS.get(_to_int(s), "") for s in (rec.get("expert_severity") or [])]
        top_expert = ""
        for lvl in ("error", "warning", "note", "chat"):
            if lvl in sev_levels:
                top_expert = lvl
                break
        for lvl in sev_levels:
            if lvl:
                self.expert_levels[lvl] += 1
        for msg, lvl in zip(rec.get("expert_message") or [], sev_levels, strict=False):
            if lvl in ("warning", "error") and len(self.expert_messages) < 500:
                self.expert_messages[msg[:160]] += 1
            elif lvl in ("warning", "error"):
                if msg[:160] in self.expert_messages:
                    self.expert_messages[msg[:160]] += 1
        if rec.get("malformed"):
            self.malformed.add(frame, ts)
        if rec.get("ip_mf") or (rec.get("ip_frag_offset") or 0) > 0:
            self.fragments.add(frame, ts)
        if rec.get("f5_flowid"):
            self.f5_trailer_frames += 1
            if rec.get("f5_vip"):
                self.f5_vips[rec["f5_vip"]] += 1
        if rec.get("quic_version"):
            self.quic_frames += 1

        if src and dst:
            self._endpoint(src, length, tx=True)
            self._endpoint(dst, length, tx=False)

        row = {
            "number": frame,
            "ts_ns": ts,
            "rel_s": (ts - self.first_ts) / 1e9,
            "iface": rec.get("iface") or 0,
            "len": length,
            "protocol": rec.get("protocol") or highest.upper(),
            "protocols": rec.get("protocols") or "",
            "src": src,
            "dst": dst,
            "sport": None,
            "dport": None,
            "transport": None,
            "flow": None,
            "tcp_flags": None,
            "tcp_seq": None,
            "tcp_ack": None,
            "tcp_len": None,
            "tcp_win": None,
            "analysis": None,
            "expert": top_expert or None,
            "info": redact_query(rec.get("info")) if self.redact else rec.get("info"),
            "vlan": ",".join(str(v) for v in vlans if v is not None) or None,
            "eth_src": rec.get("eth_src"),
            "eth_dst": rec.get("eth_dst"),
            "ttl": rec.get("ip_ttl") or rec.get("ip6_hlim"),
            "dns_qname": rec.get("dns_qname"),
            "http_host": rec.get("http_host"),
            "tls_sni": rec.get("tls_sni"),
            "f5_flowid": rec.get("f5_flowid"),
        }

        if is_icmp:
            self._icmp(rec, frame, ts, src, dst)
            row["transport"] = "icmp" if "icmp" in pset else "icmpv6"
        elif rec.get("tcp_stream") is not None and src and dst:
            self._tcp(rec, frame, ts, src, dst, length, row, ipver or 4)
        elif rec.get("udp_stream") is not None and src and dst:
            self._udp(rec, frame, ts, src, dst, length, row, ipver or 4, protocols)
        elif src and dst:
            self.other_convs[(highest, src, dst)] += 1
        return row

    # ------------------------------------------------------------- helpers
    def _endpoint(self, ip: str, length: int, tx: bool) -> None:
        ep = self.endpoints.get(ip)
        if ep is None:
            if len(self.endpoints) >= MAX_ENDPOINTS:
                ip = "(other)"
                ep = self.endpoints.setdefault(ip, [0, 0, 0, 0])
            else:
                ep = self.endpoints[ip] = [0, 0, 0, 0]
        if tx:
            ep[0] += 1
            ep[1] += length
        else:
            ep[2] += 1
            ep[3] += length

    def _icmp(self, rec: dict, frame: int, ts: int, src: str | None, dst: str | None) -> None:
        itype = rec.get("icmp_type") if rec.get("icmp_type") is not None else rec.get("icmp6_type")
        code = rec.get("icmp_code") if rec.get("icmp_code") is not None else rec.get("icmp6_code")
        mtu = rec.get("icmp_mtu") or rec.get("icmp6_mtu")
        self.icmp_counts[(itype, code)] += 1
        ips = rec.get("ip_src") or rec.get("ip6_src") or []
        ipd = rec.get("ip_dst") or rec.get("ip6_dst") or []
        sp = _first(rec.get("tcp_sport")) or _first(rec.get("udp_sport"))
        dp = _first(rec.get("tcp_dport")) or _first(rec.get("udp_dport"))
        inner = None
        if len(ips) > 1 and len(ipd) > 1:
            inner = {"src": ips[1], "dst": ipd[1], "sport": _to_int(sp) if sp else None, "dport": _to_int(dp) if dp else None,
                     "proto": "tcp" if rec.get("tcp_sport") else ("udp" if rec.get("udp_sport") else None)}
        is_error = (rec.get("icmp_type") in (3, 11, 12)) or (rec.get("icmp6_type") in (1, 2, 3, 4))
        event = {"frame": frame, "ts_ns": ts, "src": src, "dst": dst, "type": itype, "code": code, "mtu": mtu,
                 "inner": inner, "v6": rec.get("icmp6_type") is not None}
        if is_error and len(self.icmp_events) < 5000:
            self.icmp_events.append(event)
        if inner and inner["proto"] == "tcp" and inner["sport"] and inner["dport"]:
            key = (inner["src"], inner["sport"], inner["dst"], inner["dport"])
            stream = self.tuple_index.get(key)
            if stream is not None and stream in self.tcp:
                fl = self.tcp[stream]
                if len(fl.icmp) < 50:
                    fl.icmp.append(event)

    def _udp(self, rec, frame, ts, src, dst, length, row, ipver, protocols) -> None:
        sport = _to_int(_pick(rec.get("udp_sport"), True))
        dport = _to_int(_pick(rec.get("udp_dport"), True))
        stream = rec["udp_stream"]
        fl = self.udp.get(stream)
        if fl is None:
            if len(self.udp) + len(self.tcp) >= self.max_flows:
                self.dropped_flows += 1
                fl = None
            else:
                if sport is not None and dport is not None and sport < 1024 <= dport:
                    client, server = (dst, dport), (src, sport)
                else:
                    client, server = (src, sport), (dst, dport)
                fl = self.udp[stream] = UdpFlow(stream, client, server, frame, ts, ip_version=ipver)
        if fl is not None:
            d = "c2s" if (src, sport) == fl.client else "s2c"
            fl.packets[d] += 1
            fl.bytes[d] += length
            fl.last_frame, fl.last_ts = frame, ts
            app = next((p for p in reversed(protocols) if p not in GENERIC_LAYERS), None)
            if app and len(fl.app_protocols) < 8:
                fl.app_protocols.add(app)
            row["flow"] = f"u{stream}"
        row.update(sport=sport, dport=dport, transport="udp")
        if rec.get("dns_id") is not None:
            self._dns(rec, frame, ts, src, dst, sport, dport, "udp")

    # ----------------------------------------------------------------- DNS
    def _dns(self, rec, frame, ts, src, dst, sport, dport, transport) -> None:
        txid = _to_int(rec["dns_id"])
        if txid is None:
            return
        qname = (rec.get("dns_qname") or "").rstrip(".").lower()
        if not rec.get("dns_response"):
            self.dns_stats["queries"] += 1
            key = (src, sport, dst, dport, txid, qname)
            existing = self.dns_pending.get(key)
            if existing:
                existing.duplicate_queries += 1
                self.dns_stats["duplicate_queries"] += 1
                return
            txn = DnsTxn(txid, (src, sport), (dst, dport), transport, qname, rec.get("dns_qtype"), frame, ts)
            self.dns_pending[key] = txn
            if len(self.dns_txns) < MAX_DNS_TXNS:
                self.dns_txns.append(txn)
            else:
                self.dns_stats["transactions_not_retained"] += 1
        else:
            self.dns_stats["responses"] += 1
            key = (dst, dport, src, sport, txid, qname)
            txn = self.dns_pending.pop(key, None)
            if txn is None:
                self.dns_unmatched_responses.add(frame, ts)
                return
            txn.response_frame, txn.response_ts = frame, ts
            txn.rcode = rec.get("dns_rcode") or 0
            txn.truncated = bool(rec.get("dns_tc"))
            txn.answers = rec.get("dns_answers")
            txn.answer_addrs = [a for a in (rec.get("dns_a") or []) + (rec.get("dns_aaaa") or []) if a][:10]
            txn.edns_size = rec.get("dns_edns_size")

    # ----------------------------------------------------------------- TCP
    def _tcp(self, rec, frame, ts, src, dst, length, row, ipver) -> None:
        stream = rec["tcp_stream"]
        sport = _to_int(_pick(rec.get("tcp_sport"), True))
        dport = _to_int(_pick(rec.get("tcp_dport"), True))
        flags = rec.get("tcp_flags") or 0
        syn, ack, rst, fin = flags & 0x02, flags & 0x10, flags & 0x04, flags & 0x01
        fl = self.tcp.get(stream)
        if fl is None:
            if len(self.tcp) + len(self.udp) >= self.max_flows:
                self.dropped_flows += 1
                row.update(sport=sport, dport=dport, transport="tcp", tcp_flags=flags_str(flags))
                return
            if syn and not ack:
                client, server, inferred = (src, sport), (dst, dport), False
            elif syn and ack:
                client, server, inferred = (dst, dport), (src, sport), False
            else:
                inferred = True
                if sport is not None and dport is not None and sport < dport:
                    client, server = (dst, dport), (src, sport)
                else:
                    client, server = (src, sport), (dst, dport)
            fl = self.tcp[stream] = TcpFlow(stream, client, server, inferred, frame, ts, ip_version=ipver)
            for name in ("fast_retrans", "spurious", "dupacks", "ooo", "lost", "ack_lost", "window_full", "keepalive"):
                getattr(fl, name).cap = self.evidence_cap
            self.tuple_index[(client[0], client[1], server[0], server[1])] = stream
            self.tuple_index[(server[0], server[1], client[0], client[1])] = stream
        d = "c2s" if (src, sport) == fl.client else "s2c"
        tcp_len = rec.get("tcp_len") or 0
        fl.packets[d] += 1
        fl.bytes[d] += length
        if fl._last_ts and ts - fl._last_ts > fl.max_gap_ns:
            fl.max_gap_ns = ts - fl._last_ts
            fl.max_gap_frames = (fl._last_frame, frame)
        fl._last_ts, fl._last_frame = ts, frame
        fl.last_frame, fl.last_ts = frame, ts
        for v in rec.get("vlan") or []:
            if v is not None and len(fl.vlans) < 4:
                fl.vlans.add(v)
        tags = []

        if syn and not ack:
            fl.syn_count += 1
            if len(fl.syns) < 20:
                fl.syns.append({"frame": frame, "ts_ns": ts, "retrans": bool(rec.get("a_retrans")), "dir": d})
            if rec.get("tcp_mss"):
                fl.mss[d] = rec["tcp_mss"]
            if rec.get("tcp_wscale") is not None:
                fl.wscale[d] = rec["tcp_wscale"]
        elif syn and ack:
            fl.synack_count += 1
            if len(fl.synacks) < 20:
                fl.synacks.append({"frame": frame, "ts_ns": ts, "retrans": bool(rec.get("a_retrans")), "dir": d})
            if rec.get("tcp_mss"):
                fl.mss[d] = rec["tcp_mss"]
            if rec.get("tcp_wscale") is not None:
                fl.wscale[d] = rec["tcp_wscale"]
        elif ack and d == "c2s" and fl.synack_count and fl.handshake_ack is None and not rst:
            fl.handshake_ack = {"frame": frame, "ts_ns": ts}
        if rst:
            fl.rst_count += 1
            io_b = self.io.get((ts - self.first_ts) // self.bucket_ns if ts >= self.first_ts else 0)
            if io_b:
                io_b[3] += 1
            if len(fl.rsts) < 20:
                fl.rsts.append({
                    "frame": frame, "ts_ns": ts, "dir": d, "with_ack": bool(ack),
                    "after_handshake": fl.handshake_complete,
                    "after_data": bool(fl.payload["c2s"] or fl.payload["s2c"]),
                    "pending_http": len(fl.http_pending),
                    "f5_rst_cause": rec.get("f5_rst_cause"),
                })
        if fin and len(fl.fins) < 10:
            fl.fins.append({"frame": frame, "ts_ns": ts, "dir": d})
        if tcp_len > 0:
            fl.payload[d] += tcp_len
            fl.first_data.setdefault(d, (frame, ts))
            fl.last_data[d] = (frame, ts)
            if tcp_len > fl.max_segment[d]:
                fl.max_segment[d] = tcp_len
        if ack and rec.get("tcp_ack") is not None:
            if d == "c2s":
                fl.max_ack_c2s = max(fl.max_ack_c2s, rec["tcp_ack"])
            else:
                fl.max_ack_s2c = max(fl.max_ack_s2c, rec["tcp_ack"])

        if rec.get("a_retrans") and not syn:
            # SYN / SYN-ACK retransmissions are tracked on the handshake lists, not as data retransmissions.
            fl.retrans[d].add(frame, ts)
            tags.append("retransmission")
            if tcp_len > fl.retrans_max_len[d]:
                fl.retrans_max_len[d] = tcp_len
            if rec.get("tcp_seq") is not None:
                fl.retrans_max_end[d] = max(fl.retrans_max_end[d], rec["tcp_seq"] + tcp_len)
            io_b = self.io.get((ts - self.first_ts) // self.bucket_ns if ts >= self.first_ts else 0)
            if io_b:
                io_b[2] += 1
        if rec.get("a_fast_retrans"):
            fl.fast_retrans.add(frame, ts)
            tags.append("fast-retransmission")
        if rec.get("a_spurious"):
            fl.spurious.add(frame, ts)
            tags.append("spurious-retransmission")
        if rec.get("a_dupack"):
            fl.dupacks.add(frame, ts)
            tags.append("dup-ack")
        if rec.get("a_ooo"):
            fl.ooo.add(frame, ts)
            tags.append("out-of-order")
        if rec.get("a_lost"):
            fl.lost.add(frame, ts)
            tags.append("previous-segment-not-captured")
        if rec.get("a_ack_lost"):
            fl.ack_lost.add(frame, ts)
            tags.append("acked-unseen-segment")
        if rec.get("a_zero_window"):
            fl.zero_window[d].add(frame, ts)
            tags.append("zero-window")
        if rec.get("a_window_full"):
            fl.window_full.add(frame, ts)
            tags.append("window-full")
        if rec.get("a_keepalive"):
            fl.keepalive.add(frame, ts)
            tags.append("keep-alive")
        if rec.get("a_reused_ports"):
            fl.reused_ports = True
            tags.append("port-reuse")
        if rec.get("malformed"):
            fl.malformed += 1

        if rec.get("f5_flowid"):
            f5 = fl.f5
            f5.setdefault("flow_ids", [])
            if rec["f5_flowid"] not in f5["flow_ids"] and len(f5["flow_ids"]) < 4:
                f5["flow_ids"].append(rec["f5_flowid"])
            if rec.get("f5_peerid") and rec["f5_peerid"] not in ("0x0000000000000000", "0"):
                f5.setdefault("peer_ids", [])
                if rec["f5_peerid"] not in f5["peer_ids"] and len(f5["peer_ids"]) < 4:
                    f5["peer_ids"].append(rec["f5_peerid"])
            if rec.get("f5_vip"):
                f5["vip"] = rec["f5_vip"]
            if rec.get("f5_peer_remote_addr"):
                f5["peer"] = {
                    "remote_addr": rec.get("f5_peer_remote_addr"), "remote_port": rec.get("f5_peer_remote_port"),
                    "local_addr": rec.get("f5_peer_local_addr"), "local_port": rec.get("f5_peer_local_port"),
                }
            if rec.get("f5_tmm") is not None:
                f5["tmm"] = rec.get("f5_tmm")
            if rec.get("f5_rst_cause"):
                f5.setdefault("rst_causes", [])
                if len(f5["rst_causes"]) < 10:
                    f5["rst_causes"].append({"frame": frame, "ts_ns": ts, "cause": rec["f5_rst_cause"][:300], "dir": d})

        if rec.get("tls_hs_type") or rec.get("tls_ctype") or rec.get("tls_opaque_type"):
            self._tls(fl, rec, frame, ts, d)
        if rec.get("h2_stream"):
            self.h2_frames += 1
            for s in rec.get("h2_stream") or []:
                if s and len(fl.h2_streams) < 1000:
                    fl.h2_streams.add(_to_int(s) or 0)
            fl.app_protocols.add("http2")
        self._http(fl, rec, frame, ts, d, tcp_len)
        if rec.get("protocols"):
            for p in rec["protocols"].split(":")[3:]:
                if p not in GENERIC_LAYERS and len(fl.app_protocols) < 8:
                    fl.app_protocols.add(p)

        row.update(
            sport=sport, dport=dport, transport="tcp", flow=f"t{stream}", tcp_flags=flags_str(flags),
            tcp_seq=rec.get("tcp_seq"), tcp_ack=rec.get("tcp_ack"), tcp_len=tcp_len, tcp_win=rec.get("tcp_win"),
            analysis=",".join(tags) or None,
        )
        if rec.get("dns_id") is not None:
            self._dns(rec, frame, ts, src, dst, sport, dport, "tcp")

    # ----------------------------------------------------------------- TLS
    def _tls(self, fl: TcpFlow, rec: dict, frame: int, ts: int, d: str) -> None:
        if fl.tls is None:
            fl.tls = TlsState()
        tls = fl.tls
        types = {_to_int(t) for t in (rec.get("tls_hs_type") or []) if t}
        tls.handshake_types |= {t for t in types if t is not None}
        ctypes = set(rec.get("tls_ctype") or []) | set(rec.get("tls_opaque_type") or [])
        if 1 in types and tls.client_hello is None:
            versions = [_tls_version(v) for v in (rec.get("tls_supported_versions") or []) if v]
            tls.client_hello = {
                "frame": frame, "ts_ns": ts, "dir": d,
                "sni": rec.get("tls_sni"),
                "alpn_offered": [a for a in (rec.get("tls_alpn") or []) if a][:10],
                "supported_versions": [v for v in versions if v and not v.startswith("0x")][:8] or None,
                "legacy_version": _tls_version(_first(rec.get("tls_hs_version"))),
                "cipher_suites_offered": len(rec.get("tls_ciphers") or []),
                "cipher_suites": (rec.get("tls_ciphers") or [])[:40],
            }
        elif 2 in types and tls.server_hello is None:
            sv = [_tls_version(v) for v in (rec.get("tls_supported_versions") or []) if v]
            tls.server_hello = {
                "frame": frame, "ts_ns": ts, "dir": d,
                "version": sv[0] if sv else _tls_version(_first(rec.get("tls_hs_version"))),
                "cipher_suite": _first(rec.get("tls_ciphers")),
                "alpn": _first(rec.get("tls_alpn")),
            }
        if 11 in types and not tls.certificates and rec.get("tls_certs"):
            tls.certificate_frame = frame
            for hexder in (rec.get("tls_certs") or [])[:5]:
                info = parse_certificate_hex(hexder)
                if info:
                    tls.certificates.append(info)
        levels = rec.get("tls_alert_level") or []
        descs = rec.get("tls_alert_desc") or []
        for i, desc in enumerate(descs):
            code = _to_int(desc) if desc else None
            lvl = _to_int(levels[i]) if i < len(levels) and levels[i] else None
            if len(tls.alerts) < 10:
                tls.alerts.append({
                    "frame": frame, "ts_ns": ts, "dir": d,
                    "level": "fatal" if lvl == 2 else ("warning" if lvl == 1 else str(lvl)),
                    "code": code, "description": TLS_ALERTS.get(code, f"alert_{code}"),
                    "before_app_data": not tls.first_app_data,
                })
        if "23" in ctypes and d not in tls.first_app_data:
            tls.first_app_data[d] = (frame, ts)
        if "20" in ctypes:
            tls.ccs_seen = True

    # ---------------------------------------------------------------- HTTP
    def _http(self, fl: TcpFlow, rec: dict, frame: int, ts: int, d: str, tcp_len: int) -> None:
        if d == "s2c" and tcp_len > 0 and fl.http_pending:
            head = fl.http_pending[0]
            if head.first_byte_frame is None:
                head.first_byte_frame, head.first_byte_ts = frame, ts
        method = rec.get("http_method")
        if method:
            fl.http_count += 1
            uri = rec.get("http_uri") or ""
            path = redact_query(uri) if self.redact else uri
            txn = HttpTxn(fl.stream, frame, ts, method[:16], (path or "")[:512], (rec.get("http_host") or "")[:255] or None)
            txn.request_cookie_names = _cookie_names(rec.get("http_cookie"))
            txn.bigip_persistence = _bigip_cookies(rec.get("http_cookie"))
            if len(fl.http) < MAX_HTTP_PER_FLOW:
                fl.http.append(txn)
            fl.http_pending.append(txn)
            if len(fl.http_pending) > 200:
                fl.http_pending.popleft()
            fl.app_protocols.add("http")
        code = rec.get("http_code")
        if code is not None and not method:
            txn = fl.http_pending.popleft() if fl.http_pending else None
            if txn is None:
                txn = HttpTxn(fl.stream, 0, ts, "?", "(request not captured)", None)
                if len(fl.http) < MAX_HTTP_PER_FLOW:
                    fl.http.append(txn)
            txn.resp_frame, txn.resp_ts = frame, ts
            if txn.first_byte_frame is None:
                txn.first_byte_frame, txn.first_byte_ts = frame, ts
            txn.status = code
            txn.phrase = (rec.get("http_phrase") or "")[:80] or None
            txn.server = (rec.get("http_server") or "")[:120] or None
            txn.content_type = (rec.get("http_ctype") or "")[:120] or None
            loc = rec.get("http_location")
            txn.location = (redact_query(loc) if self.redact else loc)[:512] if loc else None
            txn.set_cookie_names = _cookie_names(rec.get("http_set_cookie"))
            txn.bigip_persistence += _bigip_cookies(rec.get("http_set_cookie"))
            txn.www_authenticate = bool(rec.get("http_www_auth"))
            body = (rec.get("http_body") or "")[:8192]
            if body and ASM_BLOCK_RE.search(body):
                txn.asm_block_page = True
                m = ASM_SUPPORT_ID_RE.search(body)
                if m:
                    txn.asm_support_id = m.group(1)

    # ------------------------------------------------------------- finalize
    def finalize_dns(self, capture_end_ns: int, timeout_ns: int = 2_000_000_000) -> None:
        """Classify outstanding queries; queries near the end of capture are 'response outside window'."""
        for txn in self.dns_pending.values():
            if capture_end_ns - txn.query_ts < timeout_ns:
                self.dns_stats["pending_at_capture_end"] += 1
            else:
                self.dns_stats["unanswered"] += 1

    def dns_is_near_end(self, txn: DnsTxn, capture_end_ns: int, timeout_ns: int = 2_000_000_000) -> bool:
        return txn.response_ts is None and capture_end_ns - txn.query_ts < timeout_ns


def epoch_to_ns(value: str | None) -> int:
    """Convert tshark's decimal epoch string to integer nanoseconds without float rounding."""
    if not value:
        return 0
    sec, _, frac = value.partition(".")
    return int(sec) * 1_000_000_000 + int((frac + "000000000")[:9])


def _to_int(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    try:
        return int(v, 0) if isinstance(v, str) and v.startswith("0x") else int(v)
    except (ValueError, TypeError):
        return None
