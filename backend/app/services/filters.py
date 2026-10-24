"""A safe, Wireshark-like display-filter language compiled to Arrow expressions.

Filters run against the platform's packet-summary columns (not raw packets),
so they never reach tshark or a shell. Supported syntax::

    ip.addr == 10.0.0.1 && tcp.port == 443
    tcp.flags.reset == 1 || tcp.analysis.retransmission
    !(dns) and frame.len > 1000
    info contains "Client Hello"

Regular expressions are intentionally unsupported (ReDoS); ``contains`` is a
literal substring match.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import pyarrow.compute as pc

MAX_FILTER_LEN = 1000
MAX_TOKENS = 200
MAX_DEPTH = 20

_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<lp>\() | (?P<rp>\)) |
        (?P<op>==|!=|>=|<=|>|<|\beq\b|\bne\b|\bgt\b|\blt\b|\bge\b|\ble\b|\bcontains\b) |
        (?P<and>&&|\band\b) | (?P<or>\|\||\bor\b) | (?P<not>!(?!=)|\bnot\b) |
        (?P<str>"(?:[^"\\]|\\.)*") |
        (?P<word>[A-Za-z0-9_.:/\-\[\]]+)
    )""",
    re.X,
)
_OPS = {"eq": "==", "ne": "!=", "gt": ">", "lt": "<", "ge": ">=", "le": "<="}


class FilterError(ValueError):
    pass


@dataclass
class Tok:
    kind: str
    value: str


def tokenize(text: str) -> list[Tok]:
    if len(text) > MAX_FILTER_LEN:
        raise FilterError(f"Filter longer than {MAX_FILTER_LEN} characters")
    pos, toks = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"Unexpected character at position {pos}: {text[pos:pos + 10]!r}")
        pos = m.end()
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "op":
            val = _OPS.get(val, val)
        if kind == "str":
            val = bytes(val[1:-1], "utf-8").decode("unicode_escape")
        toks.append(Tok(kind, val))
        if len(toks) > MAX_TOKENS:
            raise FilterError("Filter is too complex")
    return toks


NUMERIC = {
    "frame.number": "number", "frame.len": "len", "frame.cap_len": "caplen", "frame.time_relative": "rel_s",
    "tcp.len": "tcp_len", "tcp.seq": "tcp_seq", "tcp.ack": "tcp_ack", "tcp.window_size": "tcp_win",
    "ip.ttl": "ttl", "ipv6.hlim": "ttl", "frame.interface_id": "iface",
}
STRING = {
    "ip.src": "src", "ip.dst": "dst", "ipv6.src": "src", "ipv6.dst": "dst", "eth.src": "eth_src", "eth.dst": "eth_dst",
    "flow": "flow", "info": "info", "_ws.col.info": "info", "protocol": "protocol", "_ws.col.protocol": "protocol",
    "dns.qry.name": "dns_qname", "http.host": "http_host", "tls.sni": "tls_sni",
    "tls.handshake.extensions_server_name": "tls_sni", "expert": "expert", "_ws.expert.severity": "expert",
    "f5ethtrailer.flowid": "f5_flowid", "vlan.id": "vlan", "transport": "transport", "frame.protocols": "protocols",
}
PORT = {"tcp.srcport": ("sport", "tcp"), "tcp.dstport": ("dport", "tcp"), "udp.srcport": ("sport", "udp"),
        "udp.dstport": ("dport", "udp")}
FLAG_BITS = {"tcp.flags.syn": "S", "tcp.flags.ack": "A", "tcp.flags.reset": "R", "tcp.flags.fin": "F", "tcp.flags.push": "P",
             "tcp.flags.urg": "U"}
ANALYSIS = {
    "tcp.analysis.retransmission": "retransmission", "tcp.analysis.fast_retransmission": "fast-retransmission",
    "tcp.analysis.spurious_retransmission": "spurious-retransmission", "tcp.analysis.duplicate_ack": "dup-ack",
    "tcp.analysis.out_of_order": "out-of-order", "tcp.analysis.lost_segment": "previous-segment-not-captured",
    "tcp.analysis.ack_lost_segment": "acked-unseen-segment", "tcp.analysis.zero_window": "zero-window",
    "tcp.analysis.window_full": "window-full", "tcp.analysis.keep_alive": "keep-alive",
}
PROTO_WORD = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def _num(v: str) -> float | int:
    try:
        return int(v, 0) if v.lower().startswith("0x") else (float(v) if "." in v else int(v))
    except ValueError as exc:
        raise FilterError(f"Expected a number, got {v!r}") from exc


def _proto_present(name: str):
    if not PROTO_WORD.match(name):
        raise FilterError(f"Unknown field or protocol: {name}")
    return pc.match_substring_regex(pc.field("protocols"), f"(^|:){re.escape(name)}(:|$)")


def _cmp(col, op: str, value):
    f = pc.field(col)
    if op == "==":
        return f == value
    if op == "!=":
        return f != value
    if op == ">":
        return f > value
    if op == "<":
        return f < value
    if op == ">=":
        return f >= value
    if op == "<=":
        return f <= value
    if op == "contains":
        return pc.match_substring(f, str(value), ignore_case=True)
    raise FilterError(f"Unsupported operator {op}")


def _addr_value(v: str) -> str:
    try:
        return str(ipaddress.ip_address(v))
    except ValueError as exc:
        raise FilterError(f"{v!r} is not an IP address") from exc


def compile_comparison(field: str, op: str | None, value: str | None):
    f = field.lower()
    truthy = op is None
    if f in ("ip.addr", "ipv6.addr", "host"):
        if truthy or op not in ("==", "!="):
            raise FilterError(f"{field} supports == and !=")
        a = _addr_value(value or "")
        expr = (pc.field("src") == a) | (pc.field("dst") == a)
        return ~expr if op == "!=" else expr
    if f in ("eth.addr",):
        if op not in ("==", "!="):
            raise FilterError(f"{field} supports == and !=")
        v = (value or "").lower()
        expr = (pc.field("eth_src") == v) | (pc.field("eth_dst") == v)
        return ~expr if op == "!=" else expr
    if f in ("tcp.port", "udp.port", "port"):
        if truthy:
            raise FilterError(f"{field} needs a comparison")
        n = _num(value or "")
        expr = _cmp("sport", op, n) | _cmp("dport", op, n)
        if op == "!=":
            expr = (pc.field("sport") != n) & (pc.field("dport") != n)
        if f != "port":
            expr = expr & (pc.field("transport") == f.split(".")[0])
        return expr
    if f in PORT:
        col, transport = PORT[f]
        if truthy:
            raise FilterError(f"{field} needs a comparison")
        return _cmp(col, op, _num(value or "")) & (pc.field("transport") == transport)
    if f in FLAG_BITS:
        has = pc.match_substring(pc.field("tcp_flags"), FLAG_BITS[f])
        if truthy:
            return has
        want = _num(value or "1")
        if op not in ("==", "!="):
            raise FilterError(f"{field} supports == 0/1")
        return has if (want == 1) == (op == "==") else ~has
    if f in ANALYSIS or f == "tcp.analysis.flags":
        has = pc.match_substring(pc.field("analysis"), ANALYSIS.get(f, "")) if f in ANALYSIS else pc.is_valid(pc.field("analysis"))
        if not truthy and op == "!=":
            return ~has
        return has
    if f in NUMERIC:
        if truthy:
            return pc.is_valid(pc.field(NUMERIC[f]))
        return _cmp(NUMERIC[f], op, _num(value or ""))
    if f in STRING:
        col = STRING[f]
        if truthy:
            return pc.is_valid(pc.field(col))
        v = value or ""
        if col in ("src", "dst") and op in ("==", "!="):
            v = _addr_value(v)
        return _cmp(col, op, v)
    if truthy:
        return _proto_present(f)
    raise FilterError(f"Unknown field: {field}")


class Parser:
    def __init__(self, toks: list[Tok]):
        self.toks, self.i, self.depth = toks, 0, 0

    def peek(self) -> Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, kind: str | None = None) -> Tok:
        t = self.peek()
        if t is None or (kind and t.kind != kind):
            raise FilterError(f"Expected {kind or 'token'}" + (f" but found {t.value!r}" if t else " at end of filter"))
        self.i += 1
        return t

    def parse(self):
        if not self.toks:
            return None
        expr = self.or_()
        if self.peek() is not None:
            raise FilterError(f"Unexpected {self.peek().value!r}")
        return expr

    def or_(self):
        left = self.and_()
        while self.peek() and self.peek().kind == "or":
            self.take()
            left = left | self.and_()
        return left

    def and_(self):
        left = self.not_()
        while self.peek() and self.peek().kind == "and":
            self.take()
            left = left & self.not_()
        return left

    def not_(self):
        if self.peek() and self.peek().kind == "not":
            self.take()
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise FilterError("Filter nesting too deep")
            inner = self.not_()
            self.depth -= 1
            return ~inner
        return self.primary()

    def primary(self):
        t = self.peek()
        if t is None:
            raise FilterError("Unexpected end of filter")
        if t.kind == "lp":
            self.take()
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise FilterError("Filter nesting too deep")
            e = self.or_()
            self.take("rp")
            self.depth -= 1
            return e
        field = self.take("word").value
        nxt = self.peek()
        if nxt and nxt.kind == "op":
            op = self.take().value
            val_tok = self.peek()
            if val_tok is None or val_tok.kind not in ("word", "str"):
                raise FilterError(f"Missing value after {op}")
            self.take()
            return compile_comparison(field, op, val_tok.value)
        return compile_comparison(field, None, None)


def compile_filter(text: str | None):
    if not text or not text.strip():
        return None
    return Parser(tokenize(text)).parse()


FILTER_FIELDS = sorted(set(NUMERIC) | set(STRING) | set(PORT) | set(FLAG_BITS) | set(ANALYSIS) |
                       {"ip.addr", "ipv6.addr", "eth.addr", "tcp.port", "udp.port", "port", "tcp.analysis.flags"})
