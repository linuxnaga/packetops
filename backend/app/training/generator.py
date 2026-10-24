"""Reproducible generator for synthetic training captures.

Run ``python -m app.training.generator <output_dir>`` to (re)build every
training capture. All captures use documentation address space
(RFC 5737 / RFC 3849 and RFC 1918 lab ranges), fixed timestamps and fixed
sequence numbers so they are byte-for-byte reproducible apart from the
certificate signature in the TLS scenario.

Each scenario lists its expected outcome in ``SCENARIOS`` so training
missions and golden tests can verify the analysis engine against it.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from .pcapng_writer import PcapNgWriter

BASE_NS = int(dt.datetime(2026, 1, 15, 10, 0, 0, tzinfo=dt.UTC).timestamp()) * 1_000_000_000
MS = 1_000_000
S = 1_000_000_000

MAC_CLIENT = "02:00:00:00:00:01"
MAC_GW = "02:00:00:00:00:fe"
MAC_F5_EXT = "02:00:00:00:f5:01"
MAC_F5_INT = "02:00:00:00:f5:02"
MAC_SERVER = "02:00:00:00:00:20"


# --------------------------------------------------------------------------- frames
@dataclass
class Frame:
    ts_ns: int
    data: bytes
    iface: int = 0
    comment: str | None = None


@dataclass
class Capture:
    frames: list[Frame] = field(default_factory=list)

    def add(self, ts_ns: int, pkt, iface: int = 0, comment: str | None = None, trailer: bytes = b"") -> None:
        self.frames.append(Frame(ts_ns, bytes(pkt) + trailer, iface, comment))

    def write(self, path: Path, interfaces: list[tuple[str, str]], comments: list[str]) -> None:
        with PcapNgWriter(path, comments) as w:
            for name, desc in interfaces:
                w.add_interface(name, description=desc)
            for f in sorted(self.frames, key=lambda f: f.ts_ns):
                w.write(f.ts_ns, f.data, f.iface, f.comment)


class TcpConv:
    """Builds a TCP conversation with consistent sequence/ack numbers."""

    def __init__(
        self,
        cap: Capture,
        cli: str,
        cport: int,
        srv: str,
        sport: int,
        cmac: str = MAC_CLIENT,
        smac: str = MAC_GW,
        isn_c: int = 1000,
        isn_s: int = 5000,
        mss_c: int = 1460,
        mss_s: int = 1460,
        iface: int = 0,
        trailer=None,
    ):
        self.cap, self.cli, self.cport, self.srv, self.sport = cap, cli, cport, srv, sport
        self.cmac, self.smac = cmac, smac
        self.cseq, self.sseq = isn_c, isn_s
        self.mss_c, self.mss_s = mss_c, mss_s
        self.iface = iface
        self.trailer = trailer  # callable(from_client, flags) -> bytes

    def _pkt(self, t: int, from_client: bool, flags: str, payload: bytes = b"", seq=None, ack=None, win=None, opts=None):
        if from_client:
            eth = Ether(src=self.cmac, dst=self.smac)
            ip = IP(src=self.cli, dst=self.srv, ttl=64, flags="DF")
            tcp = TCP(sport=self.cport, dport=self.sport)
            tcp.seq = self.cseq if seq is None else seq
            tcp.ack = self.sseq if ack is None else ack
        else:
            eth = Ether(src=self.smac, dst=self.cmac)
            ip = IP(src=self.srv, dst=self.cli, ttl=60, flags="DF")
            tcp = TCP(sport=self.sport, dport=self.cport)
            tcp.seq = self.sseq if seq is None else seq
            tcp.ack = self.cseq if ack is None else ack
        tcp.flags = flags
        # SYN windows are never scaled; later windows are scaled by 2**7.
        tcp.window = win if win is not None else (64240 if "S" in flags else 502)
        if "A" not in flags:
            tcp.ack = 0
        if opts is not None:
            tcp.options = opts
        pkt = eth / ip / tcp
        if payload:
            pkt = pkt / Raw(payload)
        trailer = self.trailer(from_client, flags) if self.trailer else b""
        self.cap.add(t, pkt, self.iface, trailer=trailer)

    def syn(self, t: int) -> None:
        self._pkt(t, True, "S", opts=[("MSS", self.mss_c), ("SAckOK", b""), ("WScale", 7)])

    def handshake(self, t: int, rtt: int = 20 * MS) -> int:
        self.syn(t)
        self.cseq += 1
        self._pkt(t + rtt, False, "SA", opts=[("MSS", self.mss_s), ("SAckOK", b""), ("WScale", 7)])
        self.sseq += 1
        self._pkt(t + rtt + 1 * MS // 10, True, "A")
        return t + rtt + MS // 10


    def data(self, t: int, from_client: bool, payload: bytes, ack_after: int | None = 5 * MS, push: bool = True) -> int:
        self._pkt(t, from_client, "PA" if push else "A", payload)
        if from_client:
            self.cseq += len(payload)
        else:
            self.sseq += len(payload)
        if ack_after is not None:
            self._pkt(t + ack_after, not from_client, "A")
            return t + ack_after
        return t

    def raw_segment(self, t: int, from_client: bool, payload: bytes, seq: int, flags: str = "PA") -> None:
        self._pkt(t, from_client, flags, payload, seq=seq)

    def ack(self, t: int, from_client: bool, win: int | None = None) -> None:
        self._pkt(t, from_client, "A", win=win)

    def fin(self, t: int, from_client: bool, rtt: int = 10 * MS) -> int:
        self._pkt(t, from_client, "FA")
        if from_client:
            self.cseq += 1
        else:
            self.sseq += 1
        self._pkt(t + rtt, not from_client, "FA")
        if from_client:
            self.sseq += 1
        else:
            self.cseq += 1
        self._pkt(t + rtt + MS // 10, from_client, "A")
        return t + rtt + MS // 10

    def rst(self, t: int, from_client: bool, with_ack: bool = True) -> None:
        self._pkt(t, from_client, "RA" if with_ack else "R")


# ---------------------------------------------------------------------- TLS bytes
def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _rand(seed: str, n: int = 32) -> bytes:
    return hashlib.sha256(seed.encode()).digest()[:n]


def tls_record(ctype: int, body: bytes, version: int = 0x0303) -> bytes:
    return bytes([ctype]) + _u16(version) + _u16(len(body)) + body


def tls_handshake(htype: int, body: bytes) -> bytes:
    return bytes([htype]) + _u24(len(body)) + body


def client_hello(sni: str, alpn: list[str], versions: list[int], ciphers: list[int], legacy: int = 0x0303) -> bytes:
    exts = b""
    name = sni.encode()
    sni_body = _u16(len(name) + 3) + b"\x00" + _u16(len(name)) + name
    exts += _u16(0) + _u16(len(sni_body)) + sni_body
    if alpn:
        lst = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        body = _u16(len(lst)) + lst
        exts += _u16(16) + _u16(len(body)) + body
    groups = _u16(4) + _u16(0x001D) + _u16(0x0017)
    exts += _u16(10) + _u16(len(groups)) + groups
    sigs = _u16(6) + _u16(0x0403) + _u16(0x0804) + _u16(0x0401)
    exts += _u16(13) + _u16(len(sigs)) + sigs
    if versions:
        sv = bytes([len(versions) * 2]) + b"".join(_u16(v) for v in versions)
        exts += _u16(43) + _u16(len(sv)) + sv
    body = _u16(legacy) + _rand("ch" + sni) + b"\x20" + _rand("sid" + sni)
    body += _u16(len(ciphers) * 2) + b"".join(_u16(c) for c in ciphers) + b"\x01\x00"
    body += _u16(len(exts)) + exts
    return tls_record(0x16, tls_handshake(1, body), 0x0301)


def server_hello(cipher: int, version: int = 0x0303, alpn: str | None = None, tls13: bool = False) -> bytes:
    exts = b""
    if tls13:
        exts += _u16(43) + _u16(2) + _u16(0x0304)
    if alpn:
        lst = bytes([len(alpn)]) + alpn.encode()
        body = _u16(len(lst)) + lst
        exts += _u16(16) + _u16(len(body)) + body
    body = _u16(version) + _rand("sh" + str(cipher)) + b"\x20" + _rand("ssid") + _u16(cipher) + b"\x00"
    body += _u16(len(exts)) + exts
    return tls_handshake(2, body)


def certificate_msg(ders: list[bytes]) -> bytes:
    lst = b"".join(_u24(len(d)) + d for d in ders)
    return tls_handshake(11, _u24(len(lst)) + lst)


def tls_alert(level: int, desc: int, version: int = 0x0303) -> bytes:
    return tls_record(0x15, bytes([level, desc]), version)


def make_cert(cn: str, not_before: dt.datetime, not_after: dt.datetime) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.derive_private_key(0x5EED, ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PacketOps Training Lab")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1001)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


# -------------------------------------------------------------------- helpers
def dns_exchange(cap: Capture, t: int, client: str, resolver: str, sport: int, txid: int, name: str,
                 rcode: int | None = 0, answer: str | None = None, latency: int = 15 * MS, qtype: str = "A",
                 tc: bool = False) -> None:
    q = Ether(src=MAC_CLIENT, dst=MAC_GW) / IP(src=client, dst=resolver) / UDP(sport=sport, dport=53) / DNS(
        id=txid, rd=1, qd=DNSQR(qname=name, qtype=qtype)
    )
    cap.add(t, q)
    if rcode is None:
        return
    an = DNSRR(rrname=name, type="A", ttl=300, rdata=answer) if answer and rcode == 0 else None
    r = Ether(src=MAC_GW, dst=MAC_CLIENT) / IP(src=resolver, dst=client) / UDP(sport=53, dport=sport) / DNS(
        id=txid, qr=1, rd=1, ra=1, rcode=rcode, tc=int(tc), qd=DNSQR(qname=name, qtype=qtype), an=an
    )
    cap.add(t + latency, r)


def http_get(host: str, path: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: training-client/1.0\r\nAccept: */*\r\n\r\n").encode()


def http_resp(code: int, reason: str, body: bytes = b"ok", extra: str = "") -> bytes:
    hdr = f"HTTP/1.1 {code} {reason}\r\nServer: lab-httpd\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n{extra}\r\n"
    return hdr.encode() + body


# ------------------------------------------------------------------- scenarios
def scenario_baseline(out: Path) -> None:
    """Healthy reference traffic: DNS, HTTP and TLS 1.3 all succeed."""
    cap = Capture()
    cap.add(BASE_NS, Ether(src=MAC_CLIENT, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="10.10.1.50", pdst="10.10.1.1"))
    cap.add(BASE_NS + 1 * MS, Ether(src=MAC_GW, dst=MAC_CLIENT) / ARP(op=2, psrc="10.10.1.1", pdst="10.10.1.50", hwsrc=MAC_GW))
    dns_exchange(cap, BASE_NS + 10 * MS, "10.10.1.50", "10.10.0.53", 40001, 0x1111, "www.example.com", 0, "192.0.2.20")
    c = TcpConv(cap, "10.10.1.50", 50100, "192.0.2.20", 80)
    t = c.handshake(BASE_NS + 50 * MS)
    t = c.data(t + 1 * MS, True, http_get("www.example.com", "/index.html"), ack_after=None)
    t = c.data(t + 30 * MS, False, http_resp(200, "OK", b"<html>hello</html>"), ack_after=2 * MS)
    c.fin(t + 50 * MS, True)
    s = TcpConv(cap, "10.10.1.50", 50101, "192.0.2.30", 443, isn_c=7000, isn_s=9000)
    t = s.handshake(BASE_NS + 300 * MS)
    t = s.data(t + 1 * MS, True, client_hello("secure.example.com", ["h2", "http/1.1"], [0x0304, 0x0303], [0x1301, 0x1302, 0xC02F]), ack_after=None)
    sh = tls_record(0x16, server_hello(0x1301, alpn="h2", tls13=True))
    t = s.data(t + 25 * MS, False, sh + tls_record(0x14, b"\x01") + tls_record(0x17, _rand("enc", 64)), ack_after=1 * MS)
    t = s.data(t + 2 * MS, True, tls_record(0x14, b"\x01") + tls_record(0x17, _rand("fin", 48)), ack_after=None)
    t = s.data(t + 5 * MS, True, tls_record(0x17, _rand("req", 120)), ack_after=None)
    t = s.data(t + 40 * MS, False, tls_record(0x17, _rand("resp", 400)), ack_after=1 * MS)
    s.fin(t + 100 * MS, True)
    cap.write(out, [("eth0", "Client workstation NIC")], ["Scenario: baseline healthy traffic"])


def scenario_tcp_handshake(out: Path) -> None:
    """Client SYNs to a VIP go unanswered; a second destination works."""
    cap = Capture()
    dns_exchange(cap, BASE_NS, "10.10.1.50", "10.10.0.53", 40010, 0x2001, "app.example.com", 0, "192.0.2.10")
    c = TcpConv(cap, "10.10.1.50", 51000, "192.0.2.10", 443)
    t0 = BASE_NS + 20 * MS
    for delay in (0, 1 * S, 3 * S, 7 * S):
        c.syn(t0 + delay)
    ok = TcpConv(cap, "10.10.1.50", 51001, "192.0.2.20", 80, isn_c=3000, isn_s=8000)
    t = ok.handshake(BASE_NS + 2 * S)
    t = ok.data(t + 1 * MS, True, http_get("www.example.com", "/"), ack_after=None)
    t = ok.data(t + 20 * MS, False, http_resp(200, "OK"), ack_after=2 * MS)
    ok.fin(t + 10 * MS, True)
    rej = TcpConv(cap, "10.10.1.50", 51002, "192.0.2.10", 8443, isn_c=4000)
    rej.syn(BASE_NS + 9 * S)
    rej._pkt(BASE_NS + 9 * S + 15 * MS, False, "RA", seq=0, ack=4001)
    cap.write(out, [("eth0", "Client workstation NIC")], ["Scenario: TCP handshake failure"])


def scenario_retransmission(out: Path) -> None:
    """Server-to-client data is retransmitted after timeout and after duplicate ACKs."""
    cap = Capture()
    c = TcpConv(cap, "10.10.1.50", 52000, "192.0.2.20", 80)
    t = c.handshake(BASE_NS, rtt=30 * MS)
    t = c.data(t + 1 * MS, True, http_get("www.example.com", "/large.bin"), ack_after=None)
    total = 9 * 1400
    prefix = b"HTTP/1.1 200 OK\r\nServer: lab-httpd\r\nContent-Type: application/octet-stream\r\nContent-Length: "
    body_len = total - len(prefix) - 4 - 5  # 5-digit length value
    header = prefix + str(body_len).encode() + b"\r\n\r\n"
    stream = header + b"X" * (total - len(header))
    chunks = [stream[i : i + 1400] for i in range(0, total, 1400)]
    seg_start = c.sseq
    t += 30 * MS
    for i in range(8):
        c.raw_segment(t + i * MS // 2, False, chunks[i], seq=seg_start + i * 1400, flags="A")
    # The capture point is upstream of the loss: segment 3 was seen here but never reached the client,
    # so the client ACKs up to it and then sends duplicate ACKs.
    lost_seq = seg_start + 2 * 1400
    c._pkt(t + 15 * MS, True, "A", ack=lost_seq)
    for k in range(4):
        c._pkt(t + 16 * MS + k * MS, True, "A", ack=lost_seq)
    # Fast retransmission of the missing segment, then a cumulative ACK.
    c.raw_segment(t + 22 * MS, False, chunks[2], seq=lost_seq, flags="A")
    c._pkt(t + 50 * MS, True, "A", ack=seg_start + 8 * 1400)
    # Timeout-based retransmission of the final segment (no ACK for 300 ms).
    last_seq = seg_start + 8 * 1400
    c.raw_segment(t + 60 * MS, False, chunks[8], seq=last_seq, flags="PA")
    c.raw_segment(t + 360 * MS, False, chunks[8], seq=last_seq, flags="PA")
    c.sseq = seg_start + total
    c._pkt(t + 395 * MS, True, "A", ack=c.sseq)
    c.fin(t + 500 * MS, True, rtt=30 * MS)
    cap.write(out, [("eth0", "Client workstation NIC")], ["Scenario: retransmissions and duplicate ACKs"])


def scenario_tls_failure(out: Path) -> None:
    """A TLS 1.2 handshake fails on an expired certificate; a legacy TLS 1.0 client is refused."""
    cap = Capture()
    cert = make_cert(
        "portal.example.com",
        dt.datetime(2024, 1, 1, tzinfo=dt.UTC),
        dt.datetime(2025, 1, 1, tzinfo=dt.UTC),
    )
    c = TcpConv(cap, "10.10.1.50", 53000, "192.0.2.40", 443)
    t = c.handshake(BASE_NS, rtt=12 * MS)
    t = c.data(t + 1 * MS, True, client_hello("portal.example.com", ["http/1.1"], [], [0xC02F, 0xC030, 0x009C]), ack_after=None)
    flight = tls_record(0x16, server_hello(0xC02F) + certificate_msg([cert]) + tls_handshake(14, b""))
    t = c.data(t + 14 * MS, False, flight, ack_after=None)
    t = c.data(t + 3 * MS, True, tls_alert(2, 45), ack_after=None)  # fatal certificate_expired
    c.fin(t + 1 * MS, True, rtt=12 * MS)

    legacy = TcpConv(cap, "10.10.1.60", 53001, "192.0.2.40", 443, isn_c=2000, isn_s=6000, cmac="02:00:00:00:00:02")
    t = legacy.handshake(BASE_NS + 2 * S, rtt=12 * MS)
    t = legacy.data(t + 1 * MS, True, client_hello("portal.example.com", [], [], [0x002F, 0x0035], legacy=0x0301), ack_after=None)
    t = legacy.data(t + 13 * MS, False, tls_alert(2, 40, 0x0301), ack_after=None)  # fatal handshake_failure
    legacy.rst(t + 1 * MS, False)
    cap.write(out, [("eth0", "Client segment SPAN")], ["Scenario: TLS negotiation failure"])


def scenario_dns_timeout(out: Path) -> None:
    """Resolver does not answer api.example.com; other queries fail or are slow."""
    cap = Capture()
    for i, delay in enumerate((0, 1 * S, 2 * S, 4 * S)):
        dns_exchange(cap, BASE_NS + delay, "10.10.1.50", "10.10.0.53", 41000 + i, 0x3000 + i, "api.example.com", None)
    dns_exchange(cap, BASE_NS + 5 * S, "10.10.1.50", "10.10.0.53", 41010, 0x3100, "billing.example.com", 2, latency=40 * MS)
    dns_exchange(cap, BASE_NS + 6 * S, "10.10.1.50", "10.10.0.53", 41011, 0x3101, "typo.example.com", 3, latency=20 * MS)
    dns_exchange(cap, BASE_NS + 7 * S, "10.10.1.50", "10.10.0.53", 41012, 0x3102, "www.example.com", 0, "192.0.2.20", latency=1200 * MS)
    dns_exchange(cap, BASE_NS + 9 * S, "10.10.1.50", "10.10.0.54", 41013, 0x3103, "www.example.com", 0, "192.0.2.20", latency=8 * MS)
    cap.write(out, [("eth0", "Client workstation NIC")], ["Scenario: DNS timeout"])


def scenario_http_latency(out: Path) -> None:
    """One HTTP request takes almost five seconds; another returns 503."""
    cap = Capture()
    c = TcpConv(cap, "10.10.1.50", 54000, "192.0.2.20", 80)
    t = c.handshake(BASE_NS, rtt=10 * MS)
    t = c.data(t + 1 * MS, True, http_get("shop.example.com", "/health"), ack_after=None)
    t = c.data(t + 12 * MS, False, http_resp(200, "OK"), ack_after=1 * MS)
    t = c.data(t + 100 * MS, True, http_get("shop.example.com", "/api/orders?customer=12345"), ack_after=None)
    c.ack(t + 10 * MS, False)
    t = c.data(t + 4800 * MS, False, http_resp(200, "OK", b'{"orders":[]}'), ack_after=1 * MS)
    t = c.data(t + 100 * MS, True, http_get("shop.example.com", "/api/report"), ack_after=None)
    t = c.data(t + 900 * MS, False, http_resp(503, "Service Unavailable", b"backend unavailable"), ack_after=1 * MS)
    c.fin(t + 50 * MS, True)
    cap.write(out, [("eth0", "Client workstation NIC")], ["Scenario: HTTP latency"])


def scenario_reset(out: Path) -> None:
    """An established connection is reset by the server right after a request."""
    cap = Capture()
    c = TcpConv(cap, "10.10.1.50", 55000, "192.0.2.50", 8080)
    t = c.handshake(BASE_NS, rtt=8 * MS)
    t = c.data(t + 1 * MS, True, http_get("legacy.example.com", "/login"), ack_after=None)
    c.rst(t + 9 * MS, False)
    ok = TcpConv(cap, "10.10.1.50", 55001, "192.0.2.50", 8080, isn_c=1500, isn_s=4500)
    t = ok.handshake(BASE_NS + 1 * S, rtt=8 * MS)
    t = ok.data(t + 1 * MS, True, http_get("legacy.example.com", "/"), ack_after=None)
    t = ok.data(t + 9 * MS, False, http_resp(200, "OK"), ack_after=1 * MS)
    ok.fin(t + 5 * MS, True)
    cap.write(out, [("eth0", "Client workstation NIC")], ["Scenario: unexpected connection reset"])


def scenario_asymmetric(out: Path) -> None:
    """Only client-to-server packets are visible although the client ACKs server data."""
    cap = Capture()
    c = TcpConv(cap, "10.10.1.50", 56000, "192.0.2.60", 443)
    c.syn(BASE_NS)
    c.cseq += 1
    c.sseq += 1
    c._pkt(BASE_NS + 20 * MS, True, "A")
    c._pkt(BASE_NS + 21 * MS, True, "PA", client_hello("asym.example.com", ["h2"], [0x0304, 0x0303], [0x1301]))
    c.cseq += 200
    for i in range(1, 5):
        c._pkt(BASE_NS + (40 + i * 10) * MS, True, "A", ack=c.sseq + i * 1400)
    c._pkt(BASE_NS + 2 * S, True, "FA", ack=c.sseq + 4 * 1400)
    cap.write(out, [("eth0", "Client-side SPAN (one routing path)")], ["Scenario: asymmetric routing"])


def scenario_mtu(out: Path) -> None:
    """Large segments are retransmitted while ICMP fragmentation-needed messages are sent back."""
    cap = Capture()
    c = TcpConv(cap, "10.10.1.50", 57000, "192.0.2.70", 443, mss_c=1460, mss_s=1460)
    t = c.handshake(BASE_NS, rtt=20 * MS)
    small = client_hello("vpn.example.com", ["http/1.1"], [0x0303], [0xC02F])
    t = c.data(t + 1 * MS, True, small, ack_after=20 * MS)
    big = b"\x17\x03\x03" + _u16(1395) + b"Y" * 1395
    seq = c.cseq
    for i in range(3):
        c.raw_segment(t + (10 + i * 400) * MS, True, big, seq=seq)
        icmp = Ether(src=MAC_GW, dst=MAC_CLIENT) / IP(src="10.10.1.1", dst="10.10.1.50") / ICMP(type=3, code=4, nexthopmtu=1400) / bytes(
            IP(src="10.10.1.50", dst="192.0.2.70", flags="DF", len=1440) / TCP(sport=57000, dport=443, seq=seq, flags="PA")
        )[:28]
        cap.add(t + (11 + i * 400) * MS, icmp)
    cap.write(out, [("eth0", "Client workstation NIC")], ["Scenario: MTU / PMTUD failure"])


SCENARIOS: dict[str, dict] = {
    "baseline": {
        "builder": scenario_baseline,
        "title": "Baseline healthy traffic",
        "expected": {"rules_absent": ["TCP-001", "TLS-001", "DNS-001", "HTTP-001"], "tcp_flows": 2, "dns_transactions": 1},
    },
    "tcp-handshake": {
        "builder": scenario_tcp_handshake,
        "title": "TCP handshake failure",
        "expected": {
            "rules_present": ["TCP-001", "TCP-002"],
            "unanswered_syn": {"dst": "192.0.2.10:443", "syn_count": 4},
            "rejected_syn": {"dst": "192.0.2.10:8443"},
        },
    },
    "retransmission": {
        "builder": scenario_retransmission,
        "title": "Retransmission and suspected packet loss",
        "expected": {"rules_present": ["TCP-003", "TCP-004"]},
    },
    "tls-failure": {
        "builder": scenario_tls_failure,
        "title": "TLS negotiation failure",
        "expected": {
            "rules_present": ["TLS-001", "TLS-004", "TLS-005"],
            "alerts": ["certificate_expired", "handshake_failure"],
            "sni": "portal.example.com",
        },
    },
    "dns-timeout": {
        "builder": scenario_dns_timeout,
        "title": "DNS timeout",
        "expected": {
            "rules_present": ["DNS-001", "DNS-002", "DNS-003", "DNS-004"],
            "unanswered_name": "api.example.com",
            "unanswered_queries": 4,
        },
    },
    "http-latency": {
        "builder": scenario_http_latency,
        "title": "HTTP latency",
        "expected": {"rules_present": ["HTTP-001", "HTTP-002"], "slow_uri": "/api/orders"},
    },
    "connection-reset": {
        "builder": scenario_reset,
        "title": "Unexpected connection reset",
        "expected": {"rules_present": ["TCP-006"], "reset_by": "192.0.2.50:8080"},
    },
    "asymmetric-routing": {
        "builder": scenario_asymmetric,
        "title": "Asymmetric routing investigation",
        "expected": {"rules_present": ["TCP-009"]},
    },
    "mtu-pmtud": {
        "builder": scenario_mtu,
        "title": "MTU / PMTUD failure",
        "expected": {"rules_present": ["TCP-008"]},
    },
}


def build_all(out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    built: dict[str, Path] = {}
    for key, spec in SCENARIOS.items():
        path = out_dir / f"{key}.pcapng"
        spec["builder"](path)
        built[key] = path
    from .f5_scenarios import F5_SCENARIOS, build_f5_scenarios

    built.update(build_f5_scenarios(out_dir))
    manifest = {k: {"title": v["title"], "expected": v["expected"], "files": [f"{k}.pcapng"], "synthetic": True}
                for k, v in SCENARIOS.items()}
    for k, v in F5_SCENARIOS.items():
        manifest[k] = {"title": v["title"], "expected": v["expected"], "files": [f"{f}.pcapng" for f in v["files"]],
                       "config": "bigip-config.json" if v["config"] else None, "synthetic": True}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return built


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "fixtures/training")
    for name, p in build_all(target).items():
        print(f"{name}: {p}")
