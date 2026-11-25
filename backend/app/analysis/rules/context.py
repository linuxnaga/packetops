"""Shared inputs and helpers for detection rules."""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from functools import cached_property

from ..aggregator import Aggregator
from ..state import TcpFlow

NEAR_END_NS = 3_000_000_000  # Events this close to capture end may have been answered after capture stopped.


def ep(addr: tuple[str, int] | None) -> str:
    if not addr:
        return "?"
    ip, port = addr
    if ip and ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def ms(ns: int | None) -> str:
    if ns is None:
        return "n/a"
    v = ns / 1e6
    if v >= 1000:
        return f"{v / 1000:.3f} s"
    return f"{v:.1f} ms"


def frames_text(frames: list[int], limit: int = 8) -> str:
    if not frames:
        return "no frames"
    shown = ", ".join(f"#{f}" for f in frames[:limit])
    more = f" (+{len(frames) - limit} more)" if len(frames) > limit else ""
    return shown + more


def tuple_of(fl: TcpFlow, proto: str = "tcp") -> dict:
    return {"src": fl.client[0], "sport": fl.client[1], "dst": fl.server[0], "dport": fl.server[1], "proto": proto,
            "flow": f"t{fl.stream}"}


def tcp_timeline(fl: TcpFlow, limit: int = 40) -> list[dict]:
    """Key events of a TCP conversation in time order (facts only)."""
    ev: list[dict] = []
    c, s = ep(fl.client), ep(fl.server)
    for syn in fl.syns:
        ev.append({"ts_ns": syn["ts_ns"], "frame": syn["frame"], "dir": "c2s",
                   "event": f"SYN {c} → {s}" + (" (retransmission)" if syn["retrans"] else "")})
    for sa in fl.synacks:
        ev.append({"ts_ns": sa["ts_ns"], "frame": sa["frame"], "dir": "s2c",
                   "event": f"SYN-ACK {s} → {c}" + (" (retransmission)" if sa["retrans"] else "")})
    if fl.handshake_ack:
        ev.append({"ts_ns": fl.handshake_ack["ts_ns"], "frame": fl.handshake_ack["frame"], "dir": "c2s",
                   "event": "ACK completes three-way handshake"})
    if fl.tls:
        t = fl.tls
        if t.client_hello:
            ev.append({"ts_ns": t.client_hello["ts_ns"], "frame": t.client_hello["frame"], "dir": "c2s",
                       "event": "TLS ClientHello" + (f" SNI={t.client_hello['sni']}" if t.client_hello.get("sni") else "")})
        if t.server_hello:
            ev.append({"ts_ns": t.server_hello["ts_ns"], "frame": t.server_hello["frame"], "dir": "s2c",
                       "event": f"TLS ServerHello {t.server_hello.get('version') or ''} cipher {t.server_hello.get('cipher_suite') or '?'}"})
        for a in t.alerts:
            sender = c if a["dir"] == "c2s" else s
            ev.append({"ts_ns": a["ts_ns"], "frame": a["frame"], "dir": a["dir"],
                       "event": f"TLS alert {a['level']} {a['description']} sent by {sender}"})
        for d, (f, ts) in t.first_app_data.items():
            ev.append({"ts_ns": ts, "frame": f, "dir": d, "event": "first TLS application data " + ("client→server" if d == "c2s" else "server→client")})
    for h in fl.http[:10]:
        if h.req_frame:
            ev.append({"ts_ns": h.req_ts, "frame": h.req_frame, "dir": "c2s", "event": f"HTTP {h.method} {h.path}"})
        if h.resp_frame:
            ev.append({"ts_ns": h.resp_ts, "frame": h.resp_frame, "dir": "s2c", "event": f"HTTP {h.status} {h.phrase or ''} ({ms(h.latency_ns)})"})
    for r in fl.rsts:
        sender = c if r["dir"] == "c2s" else s
        cause = f" — BIG-IP reset cause: {r['f5_rst_cause']}" if r.get("f5_rst_cause") else ""
        ev.append({"ts_ns": r["ts_ns"], "frame": r["frame"], "dir": r["dir"], "event": f"RST sent by {sender}{cause}"})
    for f in fl.fins:
        sender = c if f["dir"] == "c2s" else s
        ev.append({"ts_ns": f["ts_ns"], "frame": f["frame"], "dir": f["dir"], "event": f"FIN sent by {sender}"})
    for d in ("c2s", "s2c"):
        for f, ts in fl.retrans[d].refs[:5]:
            ev.append({"ts_ns": ts, "frame": f, "dir": d, "event": "retransmission"})
        for f, ts in fl.zero_window[d].refs[:3]:
            ev.append({"ts_ns": ts, "frame": f, "dir": d, "event": "zero window advertised"})
    for i in fl.icmp[:5]:
        ev.append({"ts_ns": i["ts_ns"], "frame": i["frame"], "dir": "icmp",
                   "event": f"ICMP type {i['type']} code {i['code']} from {i['src']}" + (f" MTU {i['mtu']}" if i.get("mtu") else "")})
    if fl.max_gap_frames and fl.max_gap_ns > 5_000_000_000:
        a, b = fl.max_gap_frames
        ev.append({"ts_ns": fl.last_ts if b == fl.last_frame else 0, "frame": b, "dir": "-",
                   "event": f"resumes after {ms(fl.max_gap_ns)} idle (since #{a})"})
    ev = [e for e in ev if e["ts_ns"]]
    ev.sort(key=lambda e: (e["ts_ns"], e["frame"]))
    return ev[:limit]


@dataclass
class RuleContext:
    agg: Aggregator
    metadata: dict
    capture_end_ns: int
    capture_start_ns: int
    f5_presence: dict = field(default_factory=dict)  # evidence that a BIG-IP is in path, if any
    f5_config: dict | None = None

    @property
    def tcp_flows(self) -> list[TcpFlow]:
        return list(self.agg.tcp.values())

    def near_end(self, ts_ns: int) -> bool:
        return self.capture_end_ns - ts_ns < NEAR_END_NS

    @cached_property
    def bidirectional_hosts(self) -> set[str]:
        """Hosts for which the capture saw traffic in both directions of at least one TCP flow."""
        hosts = set()
        for fl in self.agg.tcp.values():
            if fl.packets["c2s"] and fl.packets["s2c"]:
                hosts.add(fl.client[0])
                hosts.add(fl.server[0])
        return hosts

    @cached_property
    def median_handshake_rtt_ns(self) -> int | None:
        vals = [fl.handshake_rtt_ns for fl in self.agg.tcp.values() if fl.handshake_rtt_ns]
        return int(statistics.median(vals)) if vals else None

    def is_known_bigip_address(self, ip: str) -> str | None:
        """Return why an address is known to belong to a BIG-IP, or None. Never guessed from address ranges."""
        if self.f5_config:
            for vs in self.f5_config.get("virtual_servers", []):
                if vs.get("address") == ip:
                    return f"operator-supplied BIG-IP metadata lists {ip} as virtual server {vs.get('name')}"
            for snat in self.f5_config.get("snat_addresses", []):
                if snat == ip:
                    return f"operator-supplied BIG-IP metadata lists {ip} as a SNAT address"
            for self_ip in self.f5_config.get("self_ips", []):
                if self_ip.get("address") == ip:
                    return f"operator-supplied BIG-IP metadata lists {ip} as a self IP"
        return None

    def bigip_hint(self, ip: str) -> str:
        reason = self.is_known_bigip_address(ip)
        if reason:
            return f"{ip} is a BIG-IP address ({reason})."
        if self.f5_presence.get("trailer_frames"):
            return "The capture contains F5 Ethernet trailers, so it was taken on a BIG-IP (tcpdump with :n flags)."
        return (f"Nothing in this capture proves that {ip} is a BIG-IP object. If it is a virtual server, "
                "the BIG-IP checks below apply; otherwise use the generic checks.")
