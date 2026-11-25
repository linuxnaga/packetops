"""Streaming conversation state built from tshark per-frame records.

Everything here is bounded: per-flow evidence lists keep the first N
references (``EvidenceList``) while counters stay exact, so memory grows
with the number of conversations, not the number of packets.
"""

from __future__ import annotations

import re
from collections import Counter, deque
from dataclasses import dataclass, field

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

TLS_ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed",
    22: "record_overflow", 40: "handshake_failure", 41: "no_certificate", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity", 116: "certificate_required",
    120: "no_application_protocol",
}

DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

# tshark expert severities
EXPERT_LEVELS = {2097152: "chat", 4194304: "note", 6291456: "warning", 8388608: "error", 1048576: "comment"}

ASM_BLOCK_RE = re.compile(r"The requested URL was rejected\. Please consult with your administrator\.", re.I)
ASM_SUPPORT_ID_RE = re.compile(r"support ID is:?\s*(?:<[^>]*>\s*)*([0-9]{8,24})", re.I)
BIGIP_COOKIE_RE = re.compile(r"^(BIGipServer[^=]*)=(\d+)\.(\d+)\.\d+$")
QUERY_RE = re.compile(r"\?[^\s\"']*")

APM_COOKIE_NAMES = {"MRHSession", "LastMRH_Session", "F5_ST", "F5_fullWT", "F5_HT_shrinked", "TIN", "MRHSHint"}
APM_PATH_HINTS = ("/my.policy", "/my.logon.php3", "/vdesk/", "/my.logout.php3", "/f5-w-")
ASM_COOKIE_PREFIX = "TS0"


def redact_query(text: str | None) -> str | None:
    """Replace query-string values with an ellipsis, keeping parameter names."""
    if not text:
        return text

    def repl(m: re.Match) -> str:
        q = m.group(0)[1:]
        parts = []
        for kv in q.split("&"):
            k = kv.split("=", 1)[0]
            parts.append(f"{k}=…" if "=" in kv else k)
        return "?" + "&".join(parts)

    return QUERY_RE.sub(repl, text)


def decode_bigip_cookie(value: str) -> tuple[str, int] | None:
    """Decode an unencrypted BIG-IP persistence cookie (IPv4 'encoded address.port.0000' form)."""
    try:
        addr = int(value.split(".")[0])
        port = int(value.split(".")[1])
    except (ValueError, IndexError):
        return None
    if addr > 0xFFFFFFFF or port > 0xFFFF:
        return None
    ip = ".".join(str((addr >> (8 * i)) & 0xFF) for i in range(4))
    port = ((port & 0xFF) << 8) | (port >> 8)
    return ip, port


class EvidenceList:
    """Exact count plus the first ``cap`` (frame, ts_ns) references."""

    __slots__ = ("count", "refs", "cap")

    def __init__(self, cap: int = 50):
        self.count = 0
        self.refs: list[tuple[int, int]] = []
        self.cap = cap

    def add(self, frame: int, ts: int) -> None:
        self.count += 1
        if len(self.refs) < self.cap:
            self.refs.append((frame, ts))

    def frames(self) -> list[int]:
        return [f for f, _ in self.refs]

    def to_dict(self) -> dict:
        return {"count": self.count, "refs": [{"frame": f, "ts_ns": t} for f, t in self.refs]}


@dataclass
class TlsState:
    client_hello: dict | None = None
    server_hello: dict | None = None
    certificates: list[dict] = field(default_factory=list)
    certificate_frame: int | None = None
    alerts: list[dict] = field(default_factory=list)
    first_app_data: dict[str, tuple[int, int]] = field(default_factory=dict)
    handshake_types: set[int] = field(default_factory=set)
    ccs_seen: bool = False

    def to_dict(self) -> dict:
        return {
            "client_hello": self.client_hello,
            "server_hello": self.server_hello,
            "certificates": self.certificates,
            "certificate_frame": self.certificate_frame,
            "alerts": self.alerts,
            "first_app_data": {k: {"frame": v[0], "ts_ns": v[1]} for k, v in self.first_app_data.items()},
            "handshake_types": sorted(self.handshake_types),
        }

    @property
    def negotiated_version(self) -> str | None:
        if not self.server_hello:
            return None
        return self.server_hello.get("version")


@dataclass
class HttpTxn:
    stream: int
    req_frame: int
    req_ts: int
    method: str
    path: str
    host: str | None
    first_byte_frame: int | None = None
    first_byte_ts: int | None = None
    resp_frame: int | None = None
    resp_ts: int | None = None
    status: int | None = None
    phrase: str | None = None
    server: str | None = None
    content_type: str | None = None
    location: str | None = None
    set_cookie_names: list[str] = field(default_factory=list)
    request_cookie_names: list[str] = field(default_factory=list)
    bigip_persistence: list[dict] = field(default_factory=list)
    asm_block_page: bool = False
    asm_support_id: str | None = None
    www_authenticate: bool = False
    version: str = "HTTP/1.1"

    @property
    def latency_ns(self) -> int | None:
        if self.resp_ts is None:
            return None
        return self.resp_ts - self.req_ts

    @property
    def ttfb_ns(self) -> int | None:
        if self.first_byte_ts is None:
            return None
        return self.first_byte_ts - self.req_ts

    def to_dict(self) -> dict:
        return {
            "stream": self.stream,
            "request_frame": self.req_frame,
            "request_ts_ns": self.req_ts,
            "method": self.method,
            "path": self.path,
            "host": self.host,
            "first_byte_frame": self.first_byte_frame,
            "ttfb_ms": round(self.ttfb_ns / 1e6, 3) if self.ttfb_ns is not None else None,
            "response_frame": self.resp_frame,
            "response_ts_ns": self.resp_ts,
            "latency_ms": round(self.latency_ns / 1e6, 3) if self.latency_ns is not None else None,
            "status": self.status,
            "phrase": self.phrase,
            "server": self.server,
            "content_type": self.content_type,
            "location": self.location,
            "set_cookie_names": self.set_cookie_names,
            "request_cookie_names": self.request_cookie_names,
            "bigip_persistence": self.bigip_persistence,
            "asm_block_page": self.asm_block_page,
            "asm_support_id": self.asm_support_id,
            "www_authenticate": self.www_authenticate,
            "version": self.version,
        }


@dataclass
class TcpFlow:
    stream: int
    client: tuple[str, int]
    server: tuple[str, int]
    direction_inferred: bool
    first_frame: int
    first_ts: int
    last_frame: int = 0
    last_ts: int = 0
    ip_version: int = 4
    vlans: set[int] = field(default_factory=set)
    packets: Counter = field(default_factory=Counter)  # c2s / s2c
    bytes: Counter = field(default_factory=Counter)
    payload: Counter = field(default_factory=Counter)
    syns: list[dict] = field(default_factory=list)  # client SYNs (frame, ts, retrans)
    syn_count: int = 0
    synacks: list[dict] = field(default_factory=list)
    synack_count: int = 0
    handshake_ack: dict | None = None
    rsts: list[dict] = field(default_factory=list)
    rst_count: int = 0
    fins: list[dict] = field(default_factory=list)
    retrans: dict = field(default_factory=dict)
    fast_retrans: EvidenceList = field(default_factory=EvidenceList)
    spurious: EvidenceList = field(default_factory=EvidenceList)
    dupacks: EvidenceList = field(default_factory=EvidenceList)
    ooo: EvidenceList = field(default_factory=EvidenceList)
    lost: EvidenceList = field(default_factory=EvidenceList)
    ack_lost: EvidenceList = field(default_factory=EvidenceList)
    zero_window: dict = field(default_factory=dict)
    window_full: EvidenceList = field(default_factory=EvidenceList)
    keepalive: EvidenceList = field(default_factory=EvidenceList)
    reused_ports: bool = False
    mss: dict = field(default_factory=dict)
    wscale: dict = field(default_factory=dict)
    max_segment: Counter = field(default_factory=Counter)
    first_data: dict = field(default_factory=dict)
    last_data: dict = field(default_factory=dict)
    max_gap_ns: int = 0
    max_gap_frames: tuple[int, int] | None = None
    retrans_max_len: Counter = field(default_factory=Counter)  # largest retransmitted segment per direction
    retrans_max_end: Counter = field(default_factory=Counter)  # highest relative seq+len retransmitted per direction
    max_ack_c2s: int = 0  # highest relative ACK the client sent (server bytes acknowledged)
    max_ack_s2c: int = 0
    tls: TlsState | None = None
    http: list[HttpTxn] = field(default_factory=list)
    http_pending: deque = field(default_factory=deque)
    http_count: int = 0
    h2_streams: set[int] = field(default_factory=set)
    f5: dict = field(default_factory=dict)
    icmp: list[dict] = field(default_factory=list)
    app_protocols: set[str] = field(default_factory=set)
    malformed: int = 0
    _last_ts: int = 0
    _last_frame: int = 0

    def __post_init__(self) -> None:
        self.retrans = {"c2s": EvidenceList(), "s2c": EvidenceList()}
        self.zero_window = {"c2s": EvidenceList(), "s2c": EvidenceList()}

    @property
    def handshake_complete(self) -> bool:
        return self.handshake_ack is not None

    @property
    def syn_seen(self) -> bool:
        return self.syn_count > 0

    @property
    def duration_ns(self) -> int:
        return max(0, self.last_ts - self.first_ts)

    @property
    def total_packets(self) -> int:
        return self.packets["c2s"] + self.packets["s2c"]

    @property
    def state(self) -> str:
        if self.rst_count:
            return "reset"
        fin_dirs = {f["dir"] for f in self.fins}
        if len(fin_dirs) == 2:
            return "closed"
        if fin_dirs:
            return "half-closed"
        if self.syn_seen and not self.synack_count:
            if self.syn_count and not self.packets["s2c"]:
                return "syn-unanswered"
        if self.handshake_complete:
            return "established"
        if not self.syn_seen:
            return "mid-stream"
        return "handshake-incomplete"

    @property
    def handshake_rtt_ns(self) -> int | None:
        if not self.syns or not self.synacks:
            return None
        return self.synacks[0]["ts_ns"] - self.syns[-1]["ts_ns"] if self.synacks[0]["ts_ns"] >= self.syns[-1]["ts_ns"] else None

    @property
    def connect_time_ns(self) -> int | None:
        """First SYN to the handshake-completing ACK (includes SYN retransmission delays)."""
        if not self.syns or not self.handshake_ack:
            return None
        return self.handshake_ack["ts_ns"] - self.syns[0]["ts_ns"]


@dataclass
class UdpFlow:
    stream: int
    client: tuple[str, int]
    server: tuple[str, int]
    first_frame: int
    first_ts: int
    last_frame: int = 0
    last_ts: int = 0
    ip_version: int = 4
    packets: Counter = field(default_factory=Counter)
    bytes: Counter = field(default_factory=Counter)
    app_protocols: set[str] = field(default_factory=set)

    @property
    def total_packets(self) -> int:
        return self.packets["c2s"] + self.packets["s2c"]


@dataclass
class DnsTxn:
    txid: int
    client: tuple[str, int]
    server: tuple[str, int]
    transport: str
    qname: str
    qtype: str | None
    query_frame: int
    query_ts: int
    response_frame: int | None = None
    response_ts: int | None = None
    rcode: int | None = None
    truncated: bool = False
    answers: int | None = None
    answer_addrs: list[str] = field(default_factory=list)
    edns_size: int | None = None
    duplicate_queries: int = 0

    @property
    def latency_ns(self) -> int | None:
        if self.response_ts is None:
            return None
        return self.response_ts - self.query_ts

    def to_dict(self) -> dict:
        return {
            "txid": self.txid,
            "txid_hex": f"0x{self.txid:04x}",
            "client": f"{self.client[0]}:{self.client[1]}",
            "server": f"{self.server[0]}:{self.server[1]}",
            "transport": self.transport,
            "qname": self.qname,
            "qtype": self.qtype,
            "query_frame": self.query_frame,
            "query_ts_ns": self.query_ts,
            "response_frame": self.response_frame,
            "response_ts_ns": self.response_ts,
            "latency_ms": round(self.latency_ns / 1e6, 3) if self.latency_ns is not None else None,
            "rcode": self.rcode,
            "rcode_name": DNS_RCODES.get(self.rcode, str(self.rcode)) if self.rcode is not None else None,
            "truncated": self.truncated,
            "answers": self.answers,
            "answer_addrs": self.answer_addrs[:10],
            "edns_size": self.edns_size,
            "duplicate_queries": self.duplicate_queries,
        }
