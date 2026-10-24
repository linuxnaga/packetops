"""Safe tshark integration.

* tshark is always invoked with an argument list (never a shell string).
* The only path passed to tshark is one the platform generated (a UUID inside
  the worker scratch directory); user-supplied filenames never reach argv.
* Name resolution is disabled (``-n``) so dissection causes no DNS egress.
* The child runs with a minimal environment, its own session (so the whole
  process group can be killed on cancel/timeout) and POSIX resource limits.
* Output is consumed line by line, so memory use does not grow with capture size.
"""

from __future__ import annotations

import functools
import json
import os
import resource
import shutil
import signal
import subprocess
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings

FIELD_SEP = "\x1e"
AGG_SEP = "\x1f"

# (tshark field, record key, mode). Modes: first, last, all, flag
FIELDS: list[tuple[str, str, str]] = [
    ("frame.number", "number", "first"),
    ("frame.time_epoch", "time_epoch", "first"),
    ("frame.len", "len", "first"),
    ("frame.cap_len", "caplen", "first"),
    ("frame.interface_id", "iface", "first"),
    ("frame.protocols", "protocols", "first"),
    ("_ws.col.protocol", "protocol", "first"),
    ("_ws.col.info", "info", "first"),
    ("_ws.expert.severity", "expert_severity", "all"),
    ("_ws.expert.message", "expert_message", "all"),
    ("_ws.malformed", "malformed", "flag"),
    ("eth.src", "eth_src", "first"),
    ("eth.dst", "eth_dst", "first"),
    ("vlan.id", "vlan", "all"),
    ("arp.opcode", "arp_opcode", "first"),
    ("arp.src.proto_ipv4", "arp_src", "first"),
    ("arp.dst.proto_ipv4", "arp_dst", "first"),
    ("ip.src", "ip_src", "all"),
    ("ip.dst", "ip_dst", "all"),
    ("ip.ttl", "ip_ttl", "first"),
    ("ip.id", "ip_id", "first"),
    ("ip.flags.df", "ip_df", "flag"),
    ("ip.flags.mf", "ip_mf", "flag"),
    ("ip.frag_offset", "ip_frag_offset", "first"),
    ("ip.len", "ip_len", "first"),
    ("ipv6.src", "ip6_src", "all"),
    ("ipv6.dst", "ip6_dst", "all"),
    ("ipv6.hlim", "ip6_hlim", "first"),
    ("tcp.srcport", "tcp_sport", "all"),
    ("tcp.dstport", "tcp_dport", "all"),
    ("tcp.stream", "tcp_stream", "first"),
    ("tcp.flags", "tcp_flags", "first"),
    ("tcp.seq", "tcp_seq", "first"),
    ("tcp.ack", "tcp_ack", "first"),
    ("tcp.len", "tcp_len", "first"),
    ("tcp.window_size_value", "tcp_win_raw", "first"),
    ("tcp.window_size", "tcp_win", "first"),
    ("tcp.options.mss_val", "tcp_mss", "first"),
    ("tcp.options.wscale.shift", "tcp_wscale", "first"),
    ("tcp.analysis.retransmission", "a_retrans", "flag"),
    ("tcp.analysis.fast_retransmission", "a_fast_retrans", "flag"),
    ("tcp.analysis.spurious_retransmission", "a_spurious", "flag"),
    ("tcp.analysis.duplicate_ack", "a_dupack", "flag"),
    ("tcp.analysis.out_of_order", "a_ooo", "flag"),
    ("tcp.analysis.lost_segment", "a_lost", "flag"),
    ("tcp.analysis.ack_lost_segment", "a_ack_lost", "flag"),
    ("tcp.analysis.zero_window", "a_zero_window", "flag"),
    ("tcp.analysis.zero_window_probe", "a_zwp", "flag"),
    ("tcp.analysis.window_full", "a_window_full", "flag"),
    ("tcp.analysis.keep_alive", "a_keepalive", "flag"),
    ("tcp.analysis.reused_ports", "a_reused_ports", "flag"),
    ("tcp.analysis.ack_rtt", "a_ack_rtt", "first"),
    ("udp.srcport", "udp_sport", "all"),
    ("udp.dstport", "udp_dport", "all"),
    ("udp.stream", "udp_stream", "first"),
    ("udp.length", "udp_len", "first"),
    ("icmp.type", "icmp_type", "first"),
    ("icmp.code", "icmp_code", "first"),
    ("icmp.mtu", "icmp_mtu", "first"),
    ("icmpv6.type", "icmp6_type", "first"),
    ("icmpv6.code", "icmp6_code", "first"),
    ("icmpv6.mtu", "icmp6_mtu", "first"),
    ("dns.id", "dns_id", "first"),
    ("dns.flags.response", "dns_response", "flag"),
    ("dns.flags.rcode", "dns_rcode", "first"),
    ("dns.flags.truncated", "dns_tc", "flag"),
    ("dns.qry.name", "dns_qname", "first"),
    ("dns.qry.type", "dns_qtype", "first"),
    ("dns.count.answers", "dns_answers", "first"),
    ("dns.a", "dns_a", "all"),
    ("dns.aaaa", "dns_aaaa", "all"),
    ("dns.rr.udp_payload_size", "dns_edns_size", "first"),
    ("tls.record.content_type", "tls_ctype", "all"),
    ("tls.record.opaque_type", "tls_opaque_type", "all"),
    ("tls.record.version", "tls_record_version", "all"),
    ("tls.handshake.type", "tls_hs_type", "all"),
    ("tls.handshake.version", "tls_hs_version", "all"),
    ("tls.handshake.extensions_server_name", "tls_sni", "first"),
    ("tls.handshake.extensions_alpn_str", "tls_alpn", "all"),
    ("tls.handshake.extensions.supported_version", "tls_supported_versions", "all"),
    ("tls.handshake.ciphersuite", "tls_ciphers", "all"),
    ("tls.handshake.certificate", "tls_certs", "all"),
    ("tls.alert_message.level", "tls_alert_level", "all"),
    ("tls.alert_message.desc", "tls_alert_desc", "all"),
    ("http.request.method", "http_method", "first"),
    ("http.request.uri", "http_uri", "first"),
    ("http.host", "http_host", "first"),
    ("http.response.code", "http_code", "first"),
    ("http.response.phrase", "http_phrase", "first"),
    ("http.server", "http_server", "first"),
    ("http.content_type", "http_ctype", "first"),
    ("http.location", "http_location", "first"),
    ("http.set_cookie", "http_set_cookie", "all"),
    ("http.cookie", "http_cookie", "all"),
    ("http.www_authenticate", "http_www_auth", "first"),
    ("http.file_data", "http_body", "first"),
    ("http2.streamid", "h2_stream", "all"),
    ("http2.headers.method", "h2_method", "all"),
    ("http2.headers.path", "h2_path", "all"),
    ("http2.headers.authority", "h2_authority", "all"),
    ("http2.headers.status", "h2_status", "all"),
    ("quic.version", "quic_version", "first"),
    ("vxlan.vni", "vxlan_vni", "first"),
    ("geneve.vni", "geneve_vni", "first"),
    ("gre.proto", "gre_proto", "first"),
    ("f5ethtrailer.flowid", "f5_flowid", "first"),
    ("f5ethtrailer.peerid", "f5_peerid", "first"),
    ("f5ethtrailer.vip", "f5_vip", "first"),
    ("f5ethtrailer.ingress", "f5_ingress", "flag"),
    ("f5ethtrailer.slot", "f5_slot", "first"),
    ("f5ethtrailer.tmm", "f5_tmm", "first"),
    ("f5ethtrailer.peerremoteaddr", "f5_peer_remote_addr", "first"),
    ("f5ethtrailer.peerlocaladdr", "f5_peer_local_addr", "first"),
    ("f5ethtrailer.peerremoteport", "f5_peer_remote_port", "first"),
    ("f5ethtrailer.peerlocalport", "f5_peer_local_port", "first"),
    ("f5ethtrailer.rstcausetxt", "f5_rst_cause", "first"),
]

INT_KEYS = {
    "number", "len", "caplen", "iface", "tcp_flags", "dns_id", "ip_ttl", "ip_frag_offset", "ip_len", "ip6_hlim", "tcp_stream",
    "tcp_seq", "tcp_ack", "tcp_len", "tcp_win_raw", "tcp_win", "tcp_mss", "tcp_wscale", "udp_stream", "udp_len",
    "icmp_type", "icmp_code", "icmp_mtu", "icmp6_type", "icmp6_code", "icmp6_mtu", "dns_rcode",
    "dns_answers", "dns_edns_size", "http_code", "vxlan_vni", "geneve_vni", "f5_slot", "f5_tmm",
    "f5_peer_remote_port", "f5_peer_local_port",
}


class TsharkError(RuntimeError):
    pass


class AnalysisCancelled(RuntimeError):
    pass


def tshark_path() -> str:
    path = get_settings().tshark_path or shutil.which("tshark")
    if not path:
        raise TsharkError("tshark is not installed or not on PATH")
    return path


@functools.lru_cache(maxsize=1)
def tshark_version() -> str:
    out = subprocess.run([tshark_path(), "--version"], capture_output=True, text=True, timeout=30, env=_child_env())
    return out.stdout.splitlines()[0].strip() if out.stdout else "unknown"


@functools.lru_cache(maxsize=1)
def available_fields() -> frozenset[str]:
    """Field names this tshark build understands (field names differ between versions)."""
    out = subprocess.run(
        [tshark_path(), "-G", "fields"], capture_output=True, text=True, timeout=120, env=_child_env()
    )
    names = set()
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) > 2 and parts[0] in ("F", "P"):
            names.add(parts[2])
    return frozenset(names)


def active_fields() -> list[tuple[str, str, str]]:
    known = available_fields()
    return [f for f in FIELDS if f[0] in known]


def _child_env() -> dict[str, str]:
    home = tempfile.gettempdir()
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def _limits(cpu_seconds: int, memory_bytes: int) -> Callable[[], None]:
    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 5))
        if memory_bytes:
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))  # tshark must not write files
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return apply


def _base_args(path: Path) -> list[str]:
    if not path.is_file():
        raise TsharkError("Capture file is missing")
    return [
        tshark_path(),
        "-n",
        "-r",
        str(path),
        "-o", "tcp.analyze_sequence_numbers:TRUE",
        "-o", "tcp.relative_sequence_numbers:TRUE",
        "-o", "tcp.calculate_timestamps:TRUE",
        "-o", "tcp.desegment_tcp_streams:TRUE",
    ]


@dataclass
class DissectionResult:
    packets: int
    stderr_tail: str
    returncode: int


def _parse_value(key: str, raw: str, mode: str):
    if mode == "flag":
        # FT_NONE analysis fields print "1"; FT_BOOLEAN fields print "True"/"False".
        return raw.split(AGG_SEP)[0] not in ("", "False", "0")
    if raw == "":
        return None
    if mode == "all":
        vals = raw.split(AGG_SEP)
        if key in INT_KEYS:
            return [_to_int(v) for v in vals]
        return vals
    val = raw.split(AGG_SEP)[0] if mode == "first" else raw.split(AGG_SEP)[-1]
    if key in INT_KEYS:
        return _to_int(val)
    return val


def _to_int(v: str):
    try:
        return int(v, 0) if v.startswith("0x") else int(v)
    except ValueError:
        try:
            return int(float(v))
        except ValueError:
            return None


def dissect(
    path: Path,
    on_record: Callable[[dict], None],
    should_cancel: Callable[[], bool] | None = None,
    timeout_s: int | None = None,
) -> DissectionResult:
    """Stream every frame through tshark and call ``on_record`` with a dict per frame."""
    settings = get_settings()
    fields = active_fields()
    args = _base_args(path) + ["-T", "fields", "-E", "header=n", "-E", f"separator={FIELD_SEP}",
                               "-E", f"aggregator={AGG_SEP}", "-E", "occurrence=a", "-E", "quote=n"]
    for name, _key, _mode in fields:
        args += ["-e", name]
    timeout_s = timeout_s or settings.analysis_timeout_s
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=_child_env(),
        start_new_session=True,
        preexec_fn=_limits(timeout_s, settings.tshark_memory_limit_bytes),
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1024 * 1024,
    )
    stderr_chunks: list[str] = []

    def drain_stderr() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            if len(stderr_chunks) < 200:
                stderr_chunks.append(line)

    t_err = threading.Thread(target=drain_stderr, daemon=True)
    t_err.start()
    timer = threading.Timer(timeout_s, lambda: _kill(proc))
    timer.start()
    count = 0
    cancelled = False
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            parts = line.rstrip("\n").split(FIELD_SEP)
            if len(parts) < len(fields):
                parts += [""] * (len(fields) - len(parts))
            rec = {key: _parse_value(key, parts[i], mode) for i, (_n, key, mode) in enumerate(fields)}
            on_record(rec)
            count += 1
            if should_cancel and count % 2000 == 0 and should_cancel():
                cancelled = True
                _kill(proc)
                break
    finally:
        timer.cancel()
        rc = proc.wait()
        t_err.join(timeout=5)
    if cancelled:
        raise AnalysisCancelled("Analysis cancelled")
    stderr_tail = "".join(line for line in stderr_chunks if "Running as user" not in line and "could be dangerous" not in line)
    if rc not in (0, 2) and count == 0:
        raise TsharkError(f"tshark failed with exit code {rc}: {stderr_tail[-500:]}")
    if rc < 0:
        raise TsharkError(f"tshark was terminated (signal {-rc}); time or resource limit reached")
    return DissectionResult(packets=count, stderr_tail=stderr_tail[-2000:], returncode=rc)


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def dissect_single_frame(pcap_path: Path, timeout_s: int = 30) -> dict:
    """Full protocol tree (JSON) and hex for a one-packet capture produced by the offset index."""
    settings = get_settings()
    args = _base_args(pcap_path) + ["-T", "json", "-x", "--no-duplicate-keys"]
    out = subprocess.run(
        args,
        capture_output=True,
        timeout=timeout_s,
        env=_child_env(),
        start_new_session=True,
        preexec_fn=_limits(timeout_s, settings.tshark_memory_limit_bytes),
        stdin=subprocess.DEVNULL,
    )
    if out.returncode not in (0, 2):
        raise TsharkError("tshark could not dissect the packet")
    data = json.loads(out.stdout.decode("utf-8", "replace") or "[]")
    return data[0] if data else {}


def follow_stream(path: Path, transport: str, stream: int, max_bytes: int = 262_144, timeout_s: int = 120) -> dict:
    """Reassembled payload of one TCP/UDP stream (tshark 'follow' in raw mode), bounded to ``max_bytes``."""
    if transport not in ("tcp", "udp") or not isinstance(stream, int) or stream < 0:
        raise TsharkError("invalid stream reference")
    settings = get_settings()
    args = _base_args(path) + ["-q", "-z", f"follow,{transport},raw,{stream}"]
    out = subprocess.run(
        args, capture_output=True, timeout=timeout_s, env=_child_env(), start_new_session=True,
        preexec_fn=_limits(timeout_s, settings.tshark_memory_limit_bytes), stdin=subprocess.DEVNULL,
    )
    nodes: dict[int, str] = {}
    chunks: list[dict] = []
    total = 0
    truncated = False
    for line in out.stdout.decode("ascii", "replace").splitlines():
        if line.startswith("Node 0:") or line.startswith("Node 1:"):
            nodes[int(line[5])] = line.split(":", 1)[1].strip()
            continue
        if not line.strip() or line.startswith(("=", "Follow:", "Filter:")):
            continue
        node = 1 if line.startswith("\t") else 0
        hexdata = line.strip()
        try:
            data = bytes.fromhex(hexdata)
        except ValueError:
            continue
        if total + len(data) > max_bytes:
            data = data[: max_bytes - total]
            truncated = True
        total += len(data)
        if data:
            chunks.append({"node": node, "data": data})
        if truncated:
            break
    return {"nodes": nodes, "chunks": chunks, "bytes": total, "truncated": truncated}
