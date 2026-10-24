"""Synthetic BIG-IP scenarios: paired client/server-side captures and an on-box capture with F5 Ethernet trailers.

Topology (documentation/lab address space)::

    client 10.1.1.10 ──► VIP 10.0.0.100:443 (vs_app_https) ══ BIG-IP ══ SNAT 10.2.2.5 ──► pool_app members
                                                                              10.2.2.20:8443 (healthy)
                                                                              10.2.2.21:8443 (silently drops SYN)
                                                                              10.2.2.22:8443 (port closed → RST)

The F5 Ethernet trailer bytes follow the "DPT" (new-format) layout documented by
Wireshark's f5ethtrailer dissector: low-noise v3 (ingress/slot/tmm/virtual name),
medium-noise v4 (flow id, peer id, optional reset cause) and high-noise v1 (peer
addresses/ports).
"""

from __future__ import annotations

import ipaddress
import json
import struct
from pathlib import Path

from .generator import (
    BASE_NS,
    MS,
    Capture,
    S,
    TcpConv,
    client_hello,
    http_get,
    http_resp,
    server_hello,
    tls_record,
)

CLIENT = "10.1.1.10"
VIP = "10.0.0.100"
SNAT = "10.2.2.5"
MEMBERS = ["10.2.2.20", "10.2.2.21", "10.2.2.22"]
M_CLIENT = "02:00:00:00:01:10"
M_EXT = "02:00:00:00:f5:01"
M_INT = "02:00:00:00:f5:02"
M_SRV = ["02:00:00:00:02:20", "02:00:00:00:02:21", "02:00:00:00:02:22"]

BIGIP_CONFIG = {
    "name": "lab-bigip-01 (synthetic)",
    "synthetic": True,
    "virtual_servers": [{
        "name": "/Common/vs_app_https", "address": VIP, "port": 443, "protocol": "tcp", "pool": "/Common/pool_app",
        "source_address_translation": {"type": "snat", "pool": "/Common/snat_app"},
        "profiles": ["/Common/tcp", "/Common/http", "/Common/clientssl_app", "/Common/serverssl"],
        "persistence": "/Common/cookie", "vlans": ["/Common/external"],
    }],
    "pools": [{"name": "/Common/pool_app", "monitor": "/Common/https",
               "members": [{"address": m, "port": 8443} for m in MEMBERS]}],
    "snat_pools": [{"name": "/Common/snat_app", "members": [SNAT]}],
    "self_ips": [{"name": "self_ext", "address": "10.0.0.5", "vlan": "/Common/external"},
                 {"name": "self_int", "address": "10.2.2.4", "vlan": "/Common/internal"}],
    "vlans": [{"name": "/Common/external", "tag": 100}, {"name": "/Common/internal", "tag": 200}],
    "routes": [{"name": "default", "network": "0.0.0.0/0", "gateway": "10.0.0.1"}],
}


# ------------------------------------------------------------------ F5 trailer
def _v4as6(ip: str) -> bytes:
    return b"\x00" * 10 + b"\xff\xff" + ipaddress.IPv4Address(ip).packed


def f5_trailer(ingress: bool, flow_id: int, peer_id: int, vip: str = "", *, slot: int = 0, tmm: int = 0,
               peer: tuple[str, int, str, int] | None = None, rst_cause: str | None = None) -> bytes:
    def tlv(ttype: int, ver: int, body: bytes) -> bytes:
        return struct.pack(">HHHH", 1, ttype, 8 + len(body), ver) + body

    low = bytes([1 if ingress else 0, slot, tmm, len(vip)]) + vip.encode()
    med = struct.pack(">QQIIBBIB", flow_id, peer_id, 0, 0, 0, 0, 0, 0)
    if rst_cause:
        body = bytes([0x00]) + struct.pack(">Q", (0x2C0F3D5 << 16) | 1004) + rst_cause.encode()
        med += bytes([len(body)]) + body
    else:
        med += b"\x00"
    tlvs = tlv(1, 3, low) + tlv(2, 4, med)
    if peer:
        remote, rport, local, lport = peer
        high = bytes([6]) + struct.pack(">H", 0) + _v4as6(remote) + _v4as6(local) + struct.pack(">HH", rport, lport)
        tlvs += tlv(3, 1, high)
    return struct.pack(">IHH", 0xF5DEB0F5, 8 + len(tlvs), 1) + tlvs


def _trailer_fn(flow_id: int, peer_id: int, vip: str, peer: tuple | None, client_is_remote: bool, rst_cause_for=None):
    """Trailer for a conversation captured on BIG-IP: ingress when the packet arrives from the conversation's remote side."""

    def fn(from_client: bool, flags: str) -> bytes:
        ingress = from_client if client_is_remote else not from_client
        cause = rst_cause_for(from_client, flags) if rst_cause_for else None
        return f5_trailer(ingress, flow_id, peer_id, vip, tmm=0, peer=peer, rst_cause=cause)

    return fn


# ---------------------------------------------------------------- scenarios
def _tls_exchange(c: TcpConv, t: int, sni: str, server_delay: int = 10 * MS) -> int:
    t = c.data(t + 1 * MS, True, client_hello(sni, ["http/1.1"], [0x0304, 0x0303], [0x1301, 0xC02F]), ack_after=None)
    sh = tls_record(0x16, server_hello(0x1301, alpn="http/1.1", tls13=True)) + tls_record(0x14, b"\x01") + tls_record(0x17, b"E" * 80)
    t = c.data(t + server_delay, False, sh, ack_after=1 * MS)
    t = c.data(t + 2 * MS, True, tls_record(0x14, b"\x01") + tls_record(0x17, b"F" * 53), ack_after=None)
    return t


def scenario_snat_paired(out_dir: Path) -> dict[str, Path]:
    """Mission 7: client-side and server-side captures of the same three requests through SNAT."""
    client_cap, server_cap = Capture(), Capture()
    plan = [  # (client port, start offset, member index, snat port, response size)
        (50001, 0, 0, 30001, 320), (50002, 400 * MS, 1, 30002, 1200), (50003, 900 * MS, 0, 30003, 64),
    ]
    for i, (cport, start, midx, sport, size) in enumerate(plan):
        t0 = BASE_NS + start
        cs = TcpConv(client_cap, CLIENT, cport, VIP, 443, cmac=M_CLIENT, smac=M_EXT, isn_c=1000 + i * 100, isn_s=90000 + i * 100)
        t = cs.handshake(t0, rtt=4 * MS)
        t = _tls_exchange(cs, t, "app.example.com", server_delay=3 * MS)
        req = b"\x17\x03\x03" + struct.pack(">H", 180) + b"R" * 180
        t_req = t + 1 * MS
        cs.data(t_req, True, req, ack_after=1 * MS)
        # BIG-IP opens the server-side connection after the client request arrives (full proxy, HTTP profile).
        ss = TcpConv(server_cap, SNAT, sport, MEMBERS[midx], 8443, cmac=M_INT, smac=M_SRV[midx], isn_c=5000 + i * 100, isn_s=70000 + i * 100)
        ts = ss.handshake(t_req + 2 * MS, rtt=1 * MS)
        ts = _tls_exchange(ss, ts, "app.example.com", server_delay=2 * MS)
        sreq = b"\x17\x03\x03" + struct.pack(">H", 210) + b"S" * 210  # X-Forwarded-For makes it slightly larger
        ts = ss.data(ts + 1 * MS, True, sreq, ack_after=None)
        resp = b"\x17\x03\x03" + struct.pack(">H", size) + b"P" * size
        ts = ss.data(ts + 25 * MS, False, resp, ack_after=1 * MS)
        cs.data(ts + 1 * MS, False, b"\x17\x03\x03" + struct.pack(">H", size) + b"Q" * size, ack_after=2 * MS)
        cs.fin(ts + 60 * MS, True, rtt=4 * MS)
        ss.fin(ts + 5 * S, True, rtt=1 * MS)  # OneConnect-style idle close later on the server side
    cpath, spath = out_dir / "snat-correlation-client.pcapng", out_dir / "snat-correlation-server.pcapng"
    client_cap.write(cpath, [("client-span", "Client-side SPAN in front of the BIG-IP external VLAN")],
                     ["Scenario: BIG-IP SNAT correlation (client side)"])
    server_cap.write(spath, [("server-span", "Server-side SPAN on the BIG-IP internal VLAN")],
                     ["Scenario: BIG-IP SNAT correlation (server side)"])
    return {"snat-correlation-client": cpath, "snat-correlation-server": spath}


def scenario_capture_comparison(out_dir: Path) -> dict[str, Path]:
    """Mission 9: the client sees the VIP reset its request; the server-side capture shows the pool member reset first."""
    client_cap, server_cap = Capture(), Capture()
    # Healthy request for reference.
    cs = TcpConv(client_cap, CLIENT, 51001, VIP, 80, cmac=M_CLIENT, smac=M_EXT, isn_c=100, isn_s=200)
    t = cs.handshake(BASE_NS, rtt=3 * MS)
    t_req = t + 1 * MS
    cs.data(t_req, True, http_get("app.example.com", "/status"), ack_after=None)
    ss = TcpConv(server_cap, SNAT, 31001, MEMBERS[0], 8080, cmac=M_INT, smac=M_SRV[0], isn_c=300, isn_s=400)
    ts = ss.handshake(t_req + 1 * MS, rtt=1 * MS)
    ts = ss.data(ts + 1 * MS, True, http_get("app.example.com", "/status"), ack_after=None)
    ts = ss.data(ts + 8 * MS, False, http_resp(200, "OK", b"up"), ack_after=1 * MS)
    cs.data(ts + 1 * MS, False, http_resp(200, "OK", b"up"), ack_after=1 * MS)
    cs.fin(ts + 20 * MS, True, rtt=3 * MS)
    ss.fin(ts + 21 * MS, True, rtt=1 * MS)
    # Failing request: member 10.2.2.21 accepts, then resets after the request.
    cs2 = TcpConv(client_cap, CLIENT, 51002, VIP, 80, cmac=M_CLIENT, smac=M_EXT, isn_c=1100, isn_s=1200)
    t = cs2.handshake(BASE_NS + 1 * S, rtt=3 * MS)
    t_req = t + 1 * MS
    cs2.data(t_req, True, http_get("app.example.com", "/api/checkout"), ack_after=None)
    ss2 = TcpConv(server_cap, SNAT, 31002, MEMBERS[1], 8080, cmac=M_INT, smac=M_SRV[1], isn_c=1300, isn_s=1400)
    ts = ss2.handshake(t_req + 1 * MS, rtt=1 * MS)
    ts = ss2.data(ts + 1 * MS, True, http_get("app.example.com", "/api/checkout"), ack_after=None)
    ss2.rst(ts + 40 * MS, False)
    cs2.rst(ts + 41 * MS, False)
    cpath, spath = out_dir / "capture-comparison-client.pcapng", out_dir / "capture-comparison-server.pcapng"
    client_cap.write(cpath, [("client-span", "Client-side SPAN")], ["Scenario: client-side/server-side comparison (client side)"])
    server_cap.write(spath, [("server-span", "Server-side SPAN")], ["Scenario: client-side/server-side comparison (server side)"])
    return {"capture-comparison-client": cpath, "capture-comparison-server": spath}


def scenario_pool_member(out_dir: Path) -> dict[str, Path]:
    """Mission 10: on-box capture (tcpdump -i 0.0:nnnp) with F5 trailers linking client-side and server-side flows."""
    cap = Capture()
    vipname = "/Common/vs_app_http"
    flows = [  # (client port, member index, behaviour, client flow id, server flow id)
        (52001, 0, "ok", 0x1001, 0x2001),
        (52002, 1, "silent", 0x1002, 0x2002),
        (52003, 2, "refused", 0x1003, 0x2003),
    ]
    for i, (cport, midx, behaviour, cfid, sfid) in enumerate(flows):
        t0 = BASE_NS + i * 2 * S
        member = MEMBERS[midx]
        cause = {"silent": "Server-side connection timed out", "refused": "Server-side connection refused (RST from pool member)"}.get(behaviour)

        def client_rst(from_client: bool, flags: str, _c=cause) -> str | None:
            return _c if (not from_client and "R" in flags) else None

        cs = TcpConv(cap, CLIENT, cport, VIP, 80, cmac=M_CLIENT, smac=M_EXT, isn_c=10 + i * 1000, isn_s=20 + i * 1000,
                     trailer=_trailer_fn(cfid, sfid, vipname, (SNAT, 32000 + i, member, 8080), True, client_rst))
        ss = TcpConv(cap, SNAT, 32000 + i, member, 8080, cmac=M_INT, smac=M_SRV[midx], isn_c=30 + i * 1000, isn_s=40 + i * 1000,
                     trailer=_trailer_fn(sfid, cfid, vipname, (CLIENT, cport, VIP, 80), False))
        t = cs.handshake(t0, rtt=2 * MS)
        t_req = t + 1 * MS
        cs.data(t_req, True, http_get("app.example.com", "/cart"), ack_after=1 * MS)
        if behaviour == "ok":
            ts = ss.handshake(t_req + 1 * MS, rtt=1 * MS)
            ts = ss.data(ts + 1 * MS, True, http_get("app.example.com", "/cart"), ack_after=None)
            ts = ss.data(ts + 6 * MS, False, http_resp(200, "OK", b"cart"), ack_after=1 * MS)
            cs.data(ts + 1 * MS, False, http_resp(200, "OK", b"cart"), ack_after=1 * MS)
            cs.fin(ts + 30 * MS, True, rtt=2 * MS)
            ss.fin(ts + 31 * MS, True, rtt=1 * MS)
        elif behaviour == "silent":
            for d in (1 * MS, 1001 * MS, 3001 * MS):
                ss.syn(t_req + d)
            cs.rst(t_req + 4100 * MS, False)
        else:
            ss.syn(t_req + 1 * MS)
            ss._pkt(t_req + 2 * MS, False, "RA", seq=0, ack=ss.cseq + 1)
            cs.rst(t_req + 3 * MS, False)
    path = out_dir / "pool-member.pcapng"
    cap.write(path, [("0.0:nnnp", "BIG-IP all VLANs with F5 Ethernet trailer (tcpdump -i 0.0:nnnp)")],
              ["Scenario: pool-member connectivity (captured on BIG-IP)"])
    return {"pool-member": path}


F5_SCENARIOS = {
    "snat-correlation": {"title": "BIG-IP SNAT correlation", "files": ["snat-correlation-client", "snat-correlation-server"],
                         "config": True, "expected": {"pairs": 3, "snat": SNAT, "member_for_50002": "10.2.2.21:8443"}},
    "capture-comparison": {"title": "Client-side/server-side capture comparison",
                           "files": ["capture-comparison-client", "capture-comparison-server"], "config": True,
                           "expected": {"pairs": 2, "failing_member": "10.2.2.21:8080", "first_reset_side": "server"}},
    "pool-member": {"title": "Pool-member connectivity investigation", "files": ["pool-member"], "config": True,
                    "expected": {"silent_member": "10.2.2.21:8080", "refusing_member": "10.2.2.22:8080",
                                 "trailer_pairs": 3}},
}


def build_f5_scenarios(out_dir: Path) -> dict[str, Path]:
    built: dict[str, Path] = {}
    built.update(scenario_snat_paired(out_dir))
    built.update(scenario_capture_comparison(out_dir))
    built.update(scenario_pool_member(out_dir))
    cfg_http = json.loads(json.dumps(BIGIP_CONFIG))
    cfg_http["virtual_servers"].append({**cfg_http["virtual_servers"][0], "name": "/Common/vs_app_http", "port": 80,
                                        "profiles": ["/Common/tcp", "/Common/http"], "pool": "/Common/pool_app_http"})
    cfg_http["pools"].append({"name": "/Common/pool_app_http", "monitor": "/Common/http",
                              "members": [{"address": m, "port": 8080} for m in MEMBERS]})
    (out_dir / "bigip-config.json").write_text(json.dumps(cfg_http, indent=2) + "\n")
    built["bigip-config"] = out_dir / "bigip-config.json"
    return built
