"""BIG-IP configuration metadata and client-side/server-side flow correlation.

Nothing here assumes that an address belongs to a BIG-IP because of its range.
A BIG-IP is only considered present when the capture carries F5 Ethernet
trailers, when operator-supplied configuration metadata names the address, or
when the operator labelled a capture as taken in front of/behind a BIG-IP.

Correlation methods, strongest first:

* ``f5-trailer``: the flow ID of one leg equals the peer ID of the other leg
  (on-box capture with ``tcpdump -i 0.0:nnn``). Confidence high.
* ``config+timing``: the client-side flow targets a configured virtual server,
  the server-side flow goes from a configured SNAT/self IP (or the client's own
  address when SNAT is off) to a member of that virtual server's pool, and the
  server-side connection starts shortly after the client's request. Confidence
  medium, raised to high when response sizes agree.
* ``timing``: two operator-supplied captures without metadata; legs paired by
  start time only. Confidence low, always reported as such.
"""

from __future__ import annotations

import ipaddress
import json
import re
from statistics import median

from app.core.errors import ApiError, bad_request, not_found
from app.core.security import Principal
from app.db import TenantDB, clean, new_id, utcnow
from app.services import gamification
from app.services.audit import audit
from app.services.captures import get_capture

MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_OBJECTS = 5000
NAME_RE = re.compile(r"^[A-Za-z0-9_.:/ ()+-]{1,200}$")
# Server-side connection must start within this window after the client's first request bytes (or handshake).
WINDOW_BEFORE_NS = 50_000_000
WINDOW_AFTER_NS = 5_000_000_000
FLOW_FIELDS = {"local_id": 1, "client_ip": 1, "client_port": 1, "server_ip": 1, "server_port": 1, "first_ts_ns": 1, "last_ts_ns": 1,
               "state": 1, "rsts": 1, "fins": 1, "f5": 1, "handshake": 1, "payload_c2s": 1, "payload_s2c": 1, "packets_c2s": 1,
               "packets_s2c": 1, "first_data": 1, "transport": 1}

CORRELATION_LIMITATIONS = [
    "Correlation shows which client-side and server-side connections belong together; it does not show BIG-IP internal "
    "decisions (iRule logic, load-balancing state, monitor results) unless an F5 trailer reset cause records them.",
    "Without F5 trailers, pairing relies on configuration metadata and timing. Concurrent connections to the same pool can "
    "be mis-paired; each pair's confidence and method are stated.",
    "When two captures come from different devices, their clocks may differ. Reset ordering across captures assumes the "
    "clocks agree to within a few milliseconds.",
    "Configuration metadata is operator-supplied and may be stale; the capture is the evidence, the metadata is context.",
]


# ------------------------------------------------------------------ configuration metadata
def _ip(value, field: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).split("%")[0].split("/")[0]))
    except ValueError as exc:
        raise bad_request(f"Invalid IP address in {field}: {str(value)[:60]!r}") from exc


def _name(value, field: str) -> str:
    v = str(value or "").strip()
    if not NAME_RE.match(v):
        raise bad_request(f"Invalid object name in {field}: {v[:60]!r}")
    return v


def _port(value, field: str) -> int:
    try:
        p = int(value)
    except (TypeError, ValueError) as exc:
        raise bad_request(f"Invalid port in {field}") from exc
    if not 0 <= p <= 65535:
        raise bad_request(f"Invalid port in {field}")
    return p


def _split_dest(dest: str) -> tuple[str, int]:
    """'/Common/10.0.0.100:443', '10.0.0.100%2:443', '2001:db8::1.443' → (ip, port)."""
    d = dest.rsplit("/", 1)[-1]
    if d.count(":") > 1:  # IPv6: BIG-IP writes addr.port
        addr, _, port = d.rpartition(".")
    else:
        addr, _, port = d.rpartition(":")
    return _ip(addr, "destination"), _port(port or 0, "destination")


def normalize_config(data: dict) -> dict:
    """Validate and normalise BIG-IP metadata (sanitized JSON export or manual entry). Unknown keys are dropped."""
    if not isinstance(data, dict):
        raise bad_request("Configuration metadata must be a JSON object")
    out: dict = {"virtual_servers": [], "pools": [], "snat_pools": [], "snat_addresses": [], "self_ips": [], "vlans": [], "routes": []}
    pools_seen: set[str] = set()
    count = 0
    for i, p in enumerate(data.get("pools") or []):
        members = []
        for j, m in enumerate(p.get("members") or []):
            members.append({"address": _ip(m.get("address"), f"pools[{i}].members[{j}]"),
                            "port": _port(m.get("port", 0), f"pools[{i}].members[{j}]"),
                            **({"name": _name(m["name"], "member name")} if m.get("name") else {})})
        name = _name(p.get("name"), f"pools[{i}].name")
        pools_seen.add(name)
        out["pools"].append({"name": name, "monitor": _name(p["monitor"], "monitor") if p.get("monitor") else None,
                             "lb_method": _name(p["lb_method"], "lb_method") if p.get("lb_method") else None, "members": members})
        count += 1 + len(members)
    for i, sp in enumerate(data.get("snat_pools") or []):
        addrs = [_ip(a, f"snat_pools[{i}]") for a in sp.get("members") or []]
        out["snat_pools"].append({"name": _name(sp.get("name"), f"snat_pools[{i}].name"), "members": addrs})
        out["snat_addresses"].extend(addrs)
        count += 1 + len(addrs)
    for a in data.get("snat_addresses") or []:
        out["snat_addresses"].append(_ip(a, "snat_addresses"))
    out["snat_addresses"] = sorted(set(out["snat_addresses"]))
    for i, s in enumerate(data.get("self_ips") or []):
        out["self_ips"].append({"name": _name(s.get("name") or f"self_{i}", f"self_ips[{i}].name"),
                                "address": _ip(s.get("address"), f"self_ips[{i}]"),
                                "vlan": _name(s["vlan"], "vlan") if s.get("vlan") else None,
                                "floating": bool(s.get("floating", False))})
    for i, v in enumerate(data.get("vlans") or []):
        tag = v.get("tag")
        out["vlans"].append({"name": _name(v.get("name"), f"vlans[{i}].name"), "tag": int(tag) if tag is not None else None})
    for i, r in enumerate(data.get("routes") or []):
        net = str(r.get("network", ""))
        try:
            net = str(ipaddress.ip_network(net, strict=False))
        except ValueError as exc:
            raise bad_request(f"Invalid network in routes[{i}]") from exc
        out["routes"].append({"name": _name(r.get("name") or f"route_{i}", "route name"), "network": net,
                              "gateway": _ip(r["gateway"], f"routes[{i}].gateway") if r.get("gateway") else None})
    for i, vs in enumerate(data.get("virtual_servers") or []):
        if vs.get("destination") and not vs.get("address"):
            addr, port = _split_dest(str(vs["destination"]))
        else:
            addr, port = _ip(vs.get("address"), f"virtual_servers[{i}]"), _port(vs.get("port", 0), f"virtual_servers[{i}]")
        sat = vs.get("source_address_translation") or {}
        sat_type = str(sat.get("type") or "none").lower()
        if sat_type not in ("none", "snat", "automap", "lsn"):
            raise bad_request(f"virtual_servers[{i}].source_address_translation.type must be none, snat, automap or lsn")
        pool = _name(vs["pool"], "pool") if vs.get("pool") else None
        if pool and pools_seen and pool not in pools_seen:
            out.setdefault("warnings", []).append(f"Virtual server {vs.get('name')} references pool {pool}, which is not in the metadata.")
        out["virtual_servers"].append({
            "name": _name(vs.get("name"), f"virtual_servers[{i}].name"), "address": addr, "port": port,
            "protocol": str(vs.get("protocol") or "tcp").lower()[:8], "pool": pool,
            "source_address_translation": {"type": sat_type, "pool": _name(sat["pool"], "snat pool") if sat.get("pool") else None},
            "profiles": [_name(p, "profile") for p in (vs.get("profiles") or [])][:40],
            "persistence": _name(vs["persistence"], "persistence") if vs.get("persistence") else None,
            "vlans": [_name(v, "vlan") for v in (vs.get("vlans") or [])][:20],
            "irules": [_name(r, "irule") for r in (vs.get("irules") or vs.get("rules") or [])][:40],
        })
        count += 1
    if count > MAX_OBJECTS:
        raise bad_request(f"Configuration metadata has more than {MAX_OBJECTS} objects")
    if not out["virtual_servers"] and not out["pools"] and not out["self_ips"] and not out["snat_addresses"]:
        raise bad_request("Configuration metadata contains no virtual servers, pools, self IPs or SNAT addresses")
    return out


# ---- tmsh / bigip.conf subset ---------------------------------------------------------------
_TMSH_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\n]|[^\s{}]+')


def _tmsh_tree(text: str) -> list:
    """Parse brace-structured tmsh text into nested lists: [tokens..., [children]]."""
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    tokens = _TMSH_TOKEN.findall("\n".join(lines))
    pos = 0

    def block() -> list:
        nonlocal pos
        items: list = []
        stmt: list = []
        while pos < len(tokens):
            t = tokens[pos]
            pos += 1
            if t == "\n":
                if stmt:
                    items.append(stmt)
                stmt = []
            elif t == "{":
                stmt.append(block())
                items.append(stmt)
                stmt = []
            elif t == "}":
                if stmt:
                    items.append(stmt)
                return items
            else:
                stmt.append(t.strip('"'))
        if stmt:
            items.append(stmt)
        return items

    return block()


def _kv(children: list) -> dict:
    """Key/value pairs of a block; one-line blocks like '{ pool X type snat }' hold several pairs in one statement."""
    d: dict = {}
    for st in children:
        words = [w for w in st if isinstance(w, str)]
        if isinstance(st[-1], list) and len(words) == 1:
            continue
        for i in range(0, len(words) - 1, 2):
            d.setdefault(words[i], words[i + 1])
    return d


def parse_tmsh(text: str) -> dict:
    """Extract virtual servers, pools, SNAT pools, self IPs, VLANs and routes from 'tmsh list' / bigip.conf text.

    Only these object types are read; everything else (iRule bodies, keys, passwords, profiles' settings) is ignored."""
    data: dict = {"virtual_servers": [], "pools": [], "snat_pools": [], "self_ips": [], "vlans": [], "routes": []}
    for st in _tmsh_tree(text):
        if len(st) < 3 or not isinstance(st[-1], list):
            continue
        head, body = [x for x in st[:-1] if isinstance(x, str)], st[-1]
        kind = " ".join(head[:2])
        name = head[2] if len(head) > 2 else None
        if not name:
            continue
        kv = _kv(body)
        if kind == "ltm virtual":
            vs = {"name": name, "destination": kv.get("destination", ""), "pool": kv.get("pool"),
                  "protocol": kv.get("ip-protocol", "tcp"), "profiles": [], "vlans": [], "irules": []}
            for sub in body:
                if len(sub) >= 2 and isinstance(sub[-1], list):
                    key = sub[0]
                    names = [c[0] for c in sub[-1] if c and isinstance(c[0], str)]
                    if key == "profiles":
                        vs["profiles"] = names
                    elif key == "vlans":
                        vs["vlans"] = names
                    elif key == "rules":
                        vs["irules"] = names
                    elif key == "persist":
                        vs["persistence"] = names[0] if names else None
                    elif key == "source-address-translation":
                        sat = _kv(sub[-1])
                        vs["source_address_translation"] = {"type": sat.get("type", "none"), "pool": sat.get("pool")}
            data["virtual_servers"].append(vs)
        elif kind == "ltm pool":
            pool = {"name": name, "monitor": kv.get("monitor"), "lb_method": kv.get("load-balancing-mode"), "members": []}
            for sub in body:
                if sub and sub[0] == "members" and isinstance(sub[-1], list):
                    for m in sub[-1]:
                        if not m or not isinstance(m[0], str):
                            continue
                        mname = m[0]
                        inner = _kv(m[-1]) if isinstance(m[-1], list) else {}
                        port = mname.rsplit(":", 1)[-1] if ":" in mname and mname.count(":") == 1 else mname.rsplit(".", 1)[-1]
                        addr = inner.get("address") or mname.rsplit("/", 1)[-1].rsplit(":" if mname.count(":") == 1 else ".", 1)[0]
                        pool["members"].append({"address": addr, "port": port, "name": mname})
            data["pools"].append(pool)
        elif kind == "ltm snatpool":
            members = []
            for sub in body:
                if sub and sub[0] == "members" and isinstance(sub[-1], list):
                    members = [c[0].rsplit("/", 1)[-1] for c in sub[-1] if c and isinstance(c[0], str)]
            data["snat_pools"].append({"name": name, "members": members})
        elif kind == "net self":
            data["self_ips"].append({"name": name, "address": kv.get("address", "").split("/")[0], "vlan": kv.get("vlan"),
                                     "floating": kv.get("floating") == "enabled"})
        elif kind == "net vlan":
            data["vlans"].append({"name": name, "tag": kv.get("tag")})
        elif kind == "net route":
            gw = kv.get("gw")
            data["routes"].append({"name": name, "network": "0.0.0.0/0" if kv.get("network") == "default" else kv.get("network", ""),
                                   "gateway": gw})
    return data


def import_config(principal: Principal, data: dict | str, *, name: str, source: str = "manual", training: bool = False,
                  upsert: bool = False, description: str | None = None) -> dict:
    """Store sanitized BIG-IP metadata. ``data`` is a JSON object or tmsh/bigip.conf text."""
    if training:
        principal.require("mission:play")
    else:
        principal.require("f5config:write")
    if isinstance(data, str):
        if len(data.encode()) > MAX_CONFIG_BYTES:
            raise bad_request("Configuration text is larger than 2 MiB")
        stripped = data.lstrip()
        if stripped.startswith("{"):
            try:
                data = json.loads(data)
            except json.JSONDecodeError as exc:
                raise bad_request(f"Invalid JSON: {exc.msg}") from exc
            fmt = "json"
        else:
            data = parse_tmsh(data)
            fmt = "tmsh"
    else:
        fmt = "json" if source != "manual" else "manual"
    name = _name(name, "name")
    normalized = normalize_config(data)
    tdb = TenantDB(principal.tenant_id)
    now = utcnow()
    doc = {**normalized, "name": name, "source": source, "format": fmt, "training": training,
           "synthetic": bool(isinstance(data, dict) and data.get("synthetic")), "description": (description or "")[:500],
           "updated_at": now, "updated_by": principal.user_id}
    existing = tdb.f5_configuration_metadata.find_one({"name": name})
    if existing:
        if not upsert:
            raise ApiError(409, "conflict", f"BIG-IP metadata named '{name}' already exists")
        tdb.f5_configuration_metadata.update_one({"_id": existing["_id"]}, {"$set": doc})
        doc["_id"] = existing["_id"]
    else:
        doc.update(_id=new_id("f5c"), created_at=now, created_by=principal.user_id)
        tdb.f5_configuration_metadata.insert_one(doc)
    audit(principal, "f5config.import", "f5_config", doc["_id"], {"name": name, "format": fmt,
                                                                  "virtual_servers": len(normalized["virtual_servers"])})
    return clean(tdb.f5_configuration_metadata.find_one({"_id": doc["_id"]}))


def list_configs(principal: Principal) -> list[dict]:
    principal.require("f5config:read")
    cur = TenantDB(principal.tenant_id).f5_configuration_metadata.find({}).sort("updated_at", -1).limit(200)
    return [{**clean(d, drop=("tenant_id", "routes", "vlans")), "counts": {k: len(d.get(k) or []) for k in
                                                               ("virtual_servers", "pools", "snat_addresses", "self_ips")}}
            for d in cur]


def get_config(principal: Principal, config_id: str) -> dict:
    principal.require("f5config:read")
    doc = TenantDB(principal.tenant_id).f5_configuration_metadata.find_one({"_id": config_id})
    if not doc:
        raise not_found("BIG-IP configuration metadata")
    return clean(doc)


def delete_config(principal: Principal, config_id: str) -> None:
    principal.require("f5config:write")
    res = TenantDB(principal.tenant_id).f5_configuration_metadata.delete_one({"_id": config_id})
    if not res.deleted_count:
        raise not_found("BIG-IP configuration metadata")
    audit(principal, "f5config.delete", "f5_config", config_id)


# ------------------------------------------------------------------ correlation
class _Cfg:
    def __init__(self, doc: dict | None):
        self.doc = doc
        self.vs = {(v["address"], v["port"]): v for v in (doc or {}).get("virtual_servers", [])}
        self.pools = {p["name"]: p for p in (doc or {}).get("pools", [])}
        self.snat_pools = {p["name"]: p["members"] for p in (doc or {}).get("snat_pools", [])}
        self.snats = set((doc or {}).get("snat_addresses", []))
        self.selfs = {s["address"] for s in (doc or {}).get("self_ips", [])}

    def vs_for(self, ip: str, port: int) -> dict | None:
        return self.vs.get((ip, port)) or self.vs.get((ip, 0))

    def members(self, vs: dict) -> set[tuple[str, int]]:
        pool = self.pools.get(vs.get("pool") or "")
        return {(m["address"], m["port"]) for m in pool["members"]} if pool else set()

    def pool_of_member(self, ip: str, port: int) -> str | None:
        for p in self.pools.values():
            if any(m["address"] == ip and m["port"] == port for m in p["members"]):
                return p["name"]
        return None

    def expected_sources(self, vs: dict, client_ip: str) -> set[str] | None:
        """Addresses the BIG-IP may use as source on the server side for this virtual server (None = unknown)."""
        sat = vs.get("source_address_translation") or {}
        t = sat.get("type", "none")
        if t == "snat":
            return set(self.snat_pools.get(sat.get("pool") or "", [])) or (self.snats or None)
        if t == "automap":
            return self.selfs or None
        if t == "none":
            return {client_ip}
        return None


def _ep(ip: str, port: int) -> str:
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _strip_mapped(addr: str | None) -> str | None:
    if not addr:
        return None
    a = addr.lower()
    return a[7:] if a.startswith("::ffff:") else a


def _client_anchor_ts(fl: dict) -> int:
    fd = (fl.get("first_data") or {}).get("c2s")
    if fd:
        return fd["ts_ns"]
    hs = (fl.get("handshake") or {}).get("ack")
    return hs["ts_ns"] if hs else fl["first_ts_ns"]


def _first_rst(fl: dict) -> dict | None:
    rsts = fl.get("rsts") or []
    return min(rsts, key=lambda r: r["ts_ns"]) if rsts else None


def _load_flows(tdb: TenantDB, capture_id: str) -> list[dict]:
    return list(tdb.flows.find({"capture_id": capture_id, "transport": "tcp"}, FLOW_FIELDS).sort("first_ts_ns", 1).limit(200000))


def _orient_trailer_pair(a: dict, b: dict, cfg: _Cfg) -> tuple[dict, dict]:
    """Return (client_side, server_side) for two legs linked by F5 trailer IDs."""
    for x, y in ((a, b), (b, a)):
        if cfg.vs_for(x["server_ip"], x["server_port"]) and not cfg.vs_for(y["server_ip"], y["server_port"]):
            return x, y
    for x, y in ((a, b), (b, a)):
        peer = (y.get("f5") or {}).get("peer") or {}
        if _strip_mapped(peer.get("remote_addr")) == x["client_ip"] and str(peer.get("remote_port")) == str(x["client_port"]):
            return x, y
    return (a, b) if a["first_ts_ns"] <= b["first_ts_ns"] else (b, a)


def _pair_doc(c: dict, s: dict, method: str, confidence: str, cfg: _Cfg, notes: list[str], same_capture: bool) -> dict:
    vs = cfg.vs_for(c["server_ip"], c["server_port"])
    pool = cfg.pool_of_member(s["server_ip"], s["server_port"])
    if vs and vs.get("pool") and pool and pool != vs["pool"]:
        notes.append(f"server-side destination is in {pool}, not the virtual server's default pool {vs['pool']} (iRule or policy?)")
    elif vs and cfg.pools and not pool:
        notes.append("server-side destination is not a member of any configured pool")
    if s["client_ip"] != c["client_ip"]:
        notes.append(f"source translated {c['client_ip']} → {s['client_ip']}")
    c_rst, s_rst = _first_rst(c), _first_rst(s)
    first_reset_side = None
    if c_rst and s_rst:
        first_reset_side = "server" if s_rst["ts_ns"] < c_rst["ts_ns"] else "client"
    elif s_rst:
        first_reset_side = "server"
    elif c_rst:
        first_reset_side = "client"
    reset = None
    if first_reset_side == "server" and s_rst:
        who = _ep(s["server_ip"], s["server_port"]) if s_rst["dir"] == "s2c" else f"BIG-IP ({_ep(s['client_ip'], s['client_port'])})"
        reset = {"side": "server", "sender": who, "frame": s_rst["frame"], "ts_ns": s_rst["ts_ns"],
                 "capture": "server" if not same_capture else "same", "f5_rst_cause": s_rst.get("f5_rst_cause")}
    elif first_reset_side == "client" and c_rst:
        who = f"BIG-IP VIP {_ep(c['server_ip'], c['server_port'])}" if c_rst["dir"] == "s2c" and vs else (
            _ep(c["server_ip"], c["server_port"]) if c_rst["dir"] == "s2c" else _ep(c["client_ip"], c["client_port"]))
        reset = {"side": "client", "sender": who, "frame": c_rst["frame"], "ts_ns": c_rst["ts_ns"],
                 "capture": "client" if not same_capture else "same", "f5_rst_cause": c_rst.get("f5_rst_cause")}
    if reset and reset.get("f5_rst_cause"):
        notes.append(f"BIG-IP reset cause: {reset['f5_rst_cause']}")
    if s.get("state") == "syn-unanswered":
        notes.append("pool member never answered the server-side SYN(s)")
    elif s.get("handshake") and s["handshake"].get("synack_count") == 0 and s_rst and s_rst["dir"] == "s2c":
        notes.append("pool member refused the connection (RST to SYN)")
    return {
        "client_flow": c["local_id"], "client_flow_id": c["_id"], "server_flow": s["local_id"], "server_flow_id": s["_id"],
        "client": _ep(c["client_ip"], c["client_port"]), "vip": _ep(c["server_ip"], c["server_port"]),
        "snat": _ep(s["client_ip"], s["client_port"]), "member": _ep(s["server_ip"], s["server_port"]),
        "virtual": (vs or {}).get("name") or (c.get("f5") or {}).get("vip"), "pool": pool or (vs or {}).get("pool"),
        "method": method, "confidence": confidence, "notes": notes,
        "start_delta_ms": round((s["first_ts_ns"] - _client_anchor_ts(c)) / 1e6, 3),
        "first_reset_side": first_reset_side, "reset": reset,
        "client_state": c.get("state"), "server_state": s.get("state"),
        "client_last_ts_ns": c["last_ts_ns"], "server_last_ts_ns": s["last_ts_ns"],
    }


def _match_trailers(client_flows: list[dict], server_flows: list[dict], cfg: _Cfg, same: bool) -> list[tuple[dict, dict]]:
    by_fid: dict[str, dict] = {}
    for fl in server_flows:
        for fid in (fl.get("f5") or {}).get("flow_ids", []):
            by_fid.setdefault(fid, fl)
    pairs, used = [], set()
    for fl in client_flows:
        f5 = fl.get("f5") or {}
        for pid in f5.get("peer_ids", []):
            other = by_fid.get(pid)
            if not other or other["_id"] == fl["_id"] or other["_id"] in used or fl["_id"] in used:
                continue
            c, s = _orient_trailer_pair(fl, other, cfg)
            used.update({fl["_id"], other["_id"]})
            pairs.append((c, s))
            break
    return pairs


def _match_by_metadata(client_flows: list[dict], server_flows: list[dict], cfg: _Cfg | None, used: set[str]) -> list[tuple[dict, dict, int]]:
    """Greedy one-to-one matching on (configured pool/SNAT constraints) + start-time proximity."""
    cands: list[tuple[int, int, dict, dict]] = []
    for c in client_flows:
        if c["_id"] in used:
            continue
        vs = cfg.vs_for(c["server_ip"], c["server_port"]) if cfg else None
        if cfg and cfg.vs and not vs:
            continue
        members = cfg.members(vs) if (cfg and vs) else set()
        sources = cfg.expected_sources(vs, c["client_ip"]) if (cfg and vs) else None
        anchor = _client_anchor_ts(c)
        for s in server_flows:
            if s["_id"] in used or s["_id"] == c["_id"]:
                continue
            if members and (s["server_ip"], s["server_port"]) not in members:
                continue
            if sources is not None and s["client_ip"] not in sources:
                continue
            if not members and (s["server_ip"], s["server_port"]) == (c["server_ip"], c["server_port"]):
                continue
            delta = s["first_ts_ns"] - anchor
            if -WINDOW_BEFORE_NS <= delta <= WINDOW_AFTER_NS:
                cands.append((abs(delta), delta, c, s))
    cands.sort(key=lambda x: x[0])
    out = []
    taken: set[str] = set(used)
    for _, delta, c, s in cands:
        if c["_id"] in taken or s["_id"] in taken:
            continue
        taken.update({c["_id"], s["_id"]})
        out.append((c, s, delta))
    return out


def _sizes_agree(c: dict, s: dict) -> bool:
    a, b = c.get("payload_s2c") or 0, s.get("payload_s2c") or 0
    return a > 0 and b > 0 and abs(a - b) <= max(64, 0.1 * max(a, b))


def correlate(principal: Principal, capture_id: str, other_capture_id: str | None = None, config_id: str | None = None) -> dict:
    principal.require("correlation:run")
    tdb = TenantDB(principal.tenant_id)
    cap_a = get_capture(principal, capture_id)
    cap_b = get_capture(principal, other_capture_id) if other_capture_id else None
    for c in filter(None, (cap_a, cap_b)):
        if c["status"] != "analyzed":
            raise ApiError(409, "not_analyzed", f"Capture {c['_id']} is '{c['status']}'; analyse it first")
    if cap_b and cap_a.get("capture_point") == "server-side" and cap_b.get("capture_point") != "server-side":
        cap_a, cap_b = cap_b, cap_a
    if cap_b and bool(cap_a.get("training")) != bool(cap_b.get("training")):
        raise bad_request("Cannot correlate a synthetic training capture with production evidence")
    config_id = config_id or cap_a.get("f5_config_id") or (cap_b or {}).get("f5_config_id")
    cfg_doc = None
    if config_id:
        cfg_doc = tdb.f5_configuration_metadata.find_one({"_id": config_id})
        if not cfg_doc:
            raise not_found("BIG-IP configuration metadata")
    cfg = _Cfg(cfg_doc)
    same = cap_b is None
    flows_a = _load_flows(tdb, cap_a["_id"])
    flows_b = flows_a if same else _load_flows(tdb, cap_b["_id"])

    evidence: list[str] = []
    trailer_a = sum(1 for f in flows_a if (f.get("f5") or {}).get("flow_ids"))
    trailer_b = 0 if same else sum(1 for f in flows_b if (f.get("f5") or {}).get("flow_ids"))
    if trailer_a or trailer_b:
        evidence.append(f"F5 Ethernet trailers on {trailer_a + trailer_b} conversation(s) (capture taken on a BIG-IP)")
    vip_hits = sorted({_ep(f["server_ip"], f["server_port"]) for f in flows_a if cfg.vs_for(f["server_ip"], f["server_port"])})
    if vip_hits:
        evidence.append(f"traffic to configured virtual server(s) {', '.join(vip_hits[:5])} (operator-supplied metadata)")
    if cap_b and (cap_a.get("capture_point") or cap_b.get("capture_point")):
        evidence.append(f"operator labelled the captures as {cap_a.get('capture_point') or 'unlabelled'} / "
                        f"{cap_b.get('capture_point') or 'unlabelled'}")

    pairs: list[dict] = []
    used: set[str] = set()
    for c, s in _match_trailers(flows_a, flows_b, cfg, same):
        notes = ["flow ID ↔ peer ID match in F5 trailer"]
        pairs.append(_pair_doc(c, s, "f5-trailer", "high", cfg, notes, same))
        used.update({c["_id"], s["_id"]})

    offset_ms = None
    if cfg_doc or (cap_b is not None):
        client_side = [f for f in flows_a if f["_id"] not in used]
        server_side = [f for f in flows_b if f["_id"] not in used]
        if same:
            # Single capture without trailers: only metadata can say which legs are client-side.
            if not cfg.vs:
                client_side = []
            else:
                client_side = [f for f in client_side if cfg.vs_for(f["server_ip"], f["server_port"])]
                server_side = [f for f in server_side if not cfg.vs_for(f["server_ip"], f["server_port"])]
        matched = _match_by_metadata(client_side, server_side, cfg if cfg_doc else None, used)
        if matched:
            offset_ms = round(median(d for _, _, d in matched) / 1e6, 3)
        for c, s, delta in matched:
            notes = [f"server-side connection opened {delta / 1e6:.1f} ms after the client's first payload"]
            if cfg_doc:
                method, conf = "config+timing", "medium"
                notes.insert(0, "virtual server, pool member and source address agree with the metadata")
            else:
                method, conf = "timing", "low"
            if _sizes_agree(c, s):
                notes.append(f"response sizes agree ({c.get('payload_s2c')} vs {s.get('payload_s2c')} bytes)")
                if conf == "medium":
                    conf = "high"
            pairs.append(_pair_doc(c, s, method, conf, cfg, notes, same))
            used.update({c["_id"], s["_id"]})

    pairs.sort(key=lambda p: p["client_last_ts_ns"])
    client_ids = {p["client_flow_id"] for p in pairs}
    server_ids = {p["server_flow_id"] for p in pairs}
    if same:
        pool_dests = {(m["address"], m["port"]) for p in cfg.pools.values() for m in p["members"]}
        relevant_client = [f for f in flows_a if cfg.vs_for(f["server_ip"], f["server_port"]) or (f.get("f5") or {}).get("flow_ids")]
        unmatched_client = [f for f in relevant_client if f["_id"] not in client_ids and f["_id"] not in server_ids
                            and (f["server_ip"], f["server_port"]) not in pool_dests]
        unmatched_server = [f for f in flows_a if (f["server_ip"], f["server_port"]) in pool_dests and f["_id"] not in server_ids]
    else:
        unmatched_client = [f for f in flows_a if f["_id"] not in client_ids
                            and (not cfg.vs or cfg.vs_for(f["server_ip"], f["server_port"]))]
        unmatched_server = [f for f in flows_b if f["_id"] not in server_ids]

    observations = _observations(pairs, unmatched_client, unmatched_server, cfg, cfg_doc, same, offset_ms)
    limitations = list(CORRELATION_LIMITATIONS)
    if not evidence:
        limitations.insert(0, "Nothing in these captures proves a BIG-IP is in path (no F5 trailers, no matching configuration "
                              "metadata, no operator labels). Any pairing below is a timing hypothesis only.")
    if not cfg_doc and not (trailer_a or trailer_b):
        limitations.append("No BIG-IP metadata was supplied, so virtual server and pool names are unknown.")

    doc = {
        "_id": new_id("cor"), "client_capture_id": cap_a["_id"], "server_capture_id": cap_b["_id"] if cap_b else None,
        "config_id": cfg_doc["_id"] if cfg_doc else None, "config_name": cfg_doc["name"] if cfg_doc else None,
        "training": bool(cap_a.get("training")), "bigip_evidence": evidence, "pairs": pairs,
        "unmatched_client": len(unmatched_client), "unmatched_server": len(unmatched_server),
        "unmatched_client_flows": [f["local_id"] for f in unmatched_client[:50]],
        "unmatched_server_flows": [f["local_id"] for f in unmatched_server[:50]],
        "methods": sorted({p["method"] for p in pairs}), "estimated_proxy_delay_ms": offset_ms,
        "observations": observations, "limitations": limitations,
        "created_by": principal.user_id, "created_at": utcnow(),
    }
    tdb.correlations.insert_one(doc)
    audit(principal, "correlation.run", "correlation", doc["_id"],
          {"client_capture_id": doc["client_capture_id"], "server_capture_id": doc["server_capture_id"], "pairs": len(pairs)})
    gamification.on_correlation(principal.tenant_id, principal.user_id, doc["_id"], len(pairs))
    return clean(doc)


def _observations(pairs: list[dict], unmatched_client: list[dict], unmatched_server: list[dict], cfg: _Cfg, cfg_doc: dict | None,
                  same: bool, offset_ms: float | None) -> list[dict]:
    obs: list[dict] = []
    if not pairs:
        obs.append({"level": "info", "text": "No client-side/server-side flow pairs could be established.", "flows": []})
        return obs
    snat_pairs = [p for p in pairs if p["client"].rsplit(":", 1)[0] != p["snat"].rsplit(":", 1)[0]]
    if snat_pairs:
        addrs = sorted({p["snat"].rsplit(":", 1)[0] for p in snat_pairs})
        known = [a for a in addrs if a in cfg.snats or a in cfg.selfs]
        obs.append({"level": "info", "flows": [p["server_flow"] for p in snat_pairs][:20],
                    "text": f"Source address translation: {len(snat_pairs)} pair(s) reach the pool from {', '.join(addrs)} instead of the "
                            "client address" + (" (listed as SNAT/self IP in the metadata)" if known else "")
                            + ". Pool members and their logs see the translated address; use X-Forwarded-For or "
                              "the BIG-IP connection table to identify the client."})
    elif pairs:
        obs.append({"level": "info", "flows": [], "text": "Client addresses are preserved on the server side (no SNAT observed)."})
    dist: dict[str, int] = {}
    for p in pairs:
        dist[p["member"]] = dist.get(p["member"], 0) + 1
    obs.append({"level": "info", "flows": [],
                "text": "Pool member selection: " + ", ".join(f"{m} × {n}" for m, n in sorted(dist.items(), key=lambda x: -x[1]))})
    for p in pairs:
        if p["first_reset_side"] == "server" and p.get("reset"):
            r = p["reset"]
            obs.append({"level": "warn", "flows": [p["client_flow"], p["server_flow"]],
                        "text": f"Pair {p['client_flow']}↔{p['server_flow']}: the server side reset first ({r['sender']}, frame "
                                f"#{r['frame']}), then the client-side connection to {p['vip']} was reset. The failure started "
                                f"between the BIG-IP and pool member {p['member']}."
                                + (f" BIG-IP reset cause: {r['f5_rst_cause']}." if r.get("f5_rst_cause") else "")})
        if "pool member never answered the server-side SYN(s)" in p["notes"]:
            obs.append({"level": "warn", "flows": [p["server_flow"]],
                        "text": f"Pool member {p['member']} never answered the BIG-IP's SYNs for client {p['client']}. Check the "
                                "member's reachability, the health monitor, and routing/firewalls on the internal VLAN."})
        if "pool member refused the connection (RST to SYN)" in p["notes"]:
            obs.append({"level": "warn", "flows": [p["server_flow"]],
                        "text": f"Pool member {p['member']} refused the connection (RST to SYN): nothing listening on that port, "
                                "or a host firewall rejected it."})
    lingering = [p for p in pairs if p["server_last_ts_ns"] - p["client_last_ts_ns"] > 1_000_000_000 and p["client_state"] in ("closed", "reset")]
    if lingering:
        worst = max(p["server_last_ts_ns"] - p["client_last_ts_ns"] for p in lingering) / 1e9
        obs.append({"level": "info", "flows": [p["server_flow"] for p in lingering][:20],
                    "text": f"{len(lingering)} server-side connection(s) stayed open after their client-side connection closed (up to "
                            f"{worst:.1f} s). Consistent with OneConnect/connection reuse or a longer server-side idle timeout; "
                            "not proof of either."})
    for f in unmatched_client[:10]:
        obs.append({"level": "warn" if f.get("state") in ("reset", "syn-unanswered") else "info", "flows": [f["local_id"]],
                    "text": f"Client-side flow {f['local_id']} ({_ep(f['client_ip'], f['client_port'])} → {_ep(f['server_ip'], f['server_port'])}, "
                            f"{f.get('state')}) has no server-side counterpart in the data. Possible: the BIG-IP answered itself "
                            "(iRule, redirect, ASM block), no pool member was available, or the server side was not captured."})
    one_way = [f for f in unmatched_server if not f.get("packets_s2c")]
    if one_way and not same:
        obs.append({"level": "info", "flows": [f["local_id"] for f in one_way[:20]],
                    "text": f"{len(one_way)} unmatched server-side flow(s) carry packets in one direction only (unanswered SYNs, "
                            "asymmetric return path, or monitor traffic)."})
    if offset_ms is not None and not same:
        obs.append({"level": "info", "flows": [],
                    "text": f"Median time from the client's first payload to the server-side SYN: {offset_ms} ms (proxy decision time plus any "
                            "clock difference between the capture points)."})
    return obs


def get_correlation(principal: Principal, correlation_id: str) -> dict:
    principal.require("capture:read")
    doc = TenantDB(principal.tenant_id).correlations.find_one({"_id": correlation_id})
    if not doc:
        raise not_found("Correlation")
    return clean(doc)


def list_correlations(principal: Principal, capture_id: str | None = None, limit: int = 50) -> list[dict]:
    principal.require("capture:read")
    flt = {"$or": [{"client_capture_id": capture_id}, {"server_capture_id": capture_id}]} if capture_id else {}
    cur = TenantDB(principal.tenant_id).correlations.find(flt, {"pairs": 0, "observations": 0}).sort("created_at", -1).limit(limit)
    return [clean(d) for d in cur]
