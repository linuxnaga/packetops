"""Command Deck command handlers. Every command calls the real service layer."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from app.core.errors import ApiError
from app.core.security import Principal
from app.db import TenantDB, utcnow
from app.services import captures as cap_svc
from app.services import findings as find_svc
from app.services import flows as flow_svc
from app.services import gamification

from .parser import Arg, Command, ConsoleError, Opt, Registry


@dataclass
class Out:
    blocks: list[dict] = field(default_factory=list)

    def _line(self, level: str, text: str, refs: dict | None = None) -> Out:
        b = {"type": "line", "level": level, "text": text}
        if refs:
            b["refs"] = refs
        self.blocks.append(b)
        return self

    def ok(self, text, refs=None):
        return self._line("ok", f"[+] {text}", refs)

    def info(self, text, refs=None):
        return self._line("info", text, refs)

    def warn(self, text, refs=None):
        return self._line("warn", f"[!] {text}", refs)

    def err(self, text, refs=None):
        return self._line("error", f"[-] {text}", refs)

    def muted(self, text, refs=None):
        return self._line("muted", text, refs)

    def head(self, text):
        return self._line("head", text)

    def kv(self, items: list[tuple[str, object]], refs: dict | None = None):
        b = {"type": "kv", "items": [[k, "" if v is None else str(v)] for k, v in items]}
        if refs:
            b["refs"] = refs
        self.blocks.append(b)
        return self

    def table(self, columns: list[str], rows: list[list], refs: dict | None = None, total: int | None = None):
        b = {"type": "table", "columns": columns, "rows": [["" if c is None else str(c) for c in r] for r in rows]}
        if total is not None:
            b["total"] = total
        if refs:
            b["refs"] = refs
        self.blocks.append(b)
        return self

    def action(self, action: str, **data):
        self.blocks.append({"type": "action", "action": action, **data})
        return self

    def blank(self):
        return self._line("muted", "")


@dataclass
class Ctx:
    principal: Principal
    session: dict
    out: Out = field(default_factory=Out)

    @property
    def capture_id(self) -> str | None:
        return self.session.get("capture_id")

    def set_capture(self, capture_id: str | None) -> None:
        self.session["capture_id"] = capture_id


def _resolve_capture(ctx: Ctx, ref: str | None) -> dict:
    if not ref:
        raise ConsoleError("No capture selected. Use 'pcap list' then 'pcap use <capture_id>', or 'pcap upload'.",
                           ["pcap list", "pcap upload"])
    if ref.startswith("cap_"):
        return cap_svc.get_capture(ctx.principal, ref)
    tdb = TenantDB(ctx.principal.tenant_id)
    doc = tdb.captures.find_one({"filename": ref, "deleted_at": None}, sort=[("created_at", -1)])
    if not doc:
        raise ConsoleError(f"No capture named '{ref}'", ["pcap list"])
    return doc


def _analyzed(ctx: Ctx, ref: str | None = None) -> dict:
    cap = _resolve_capture(ctx, ref or ctx.capture_id)
    if cap["status"] != "analyzed":
        raise ConsoleError(f"Capture {cap['_id']} is '{cap['status']}', not analysed yet. Run 'pcap inspect' to analyse it.",
                           ["pcap inspect", "status"])
    return cap


def _ts(ns: int | None) -> str:
    if not ns:
        return "-"
    return dt.datetime.fromtimestamp(ns / 1e9, tz=dt.UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def _human_bytes(n: int | None) -> str:
    n = n or 0
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _finding_card(out: Out, f: dict, full: bool = False) -> None:
    sev = f["severity"].upper()
    frames = [p["frame"] for p in f.get("packets", [])][:12]
    out.warn(f"{f['short_id']} [{sev} | confidence {f['confidence']['level']}] {f['title']}",
             {"findings": [f["short_id"]], "flows": f.get("flows", [])[:5]})
    for t in f.get("tuples", [])[:2]:
        out.info(f"Flow: {t['src']}:{t['sport']} -> {t['dst']}:{t['dport']} ({t.get('proto', 'tcp')}"
                 + (f", {t['flow']})" if t.get("flow") else ")"), {"flows": [t["flow"]] if t.get("flow") else []})
    if frames:
        out.info("Evidence: " + ", ".join(f"#{n}" for n in frames), {"frames": frames})
    for o in f.get("observations", [])[: (10 if full else 2)]:
        out.info(f"Observation: {o['text']}", {"frames": o.get("frames", [])[:20]})
    out.info(f"Assessment: {f.get('assessment')}")
    if full:
        out.info(f"Probable cause (hypothesis): {f.get('probable_cause')}")
        for a in f.get("alternatives", [])[:5]:
            out.muted(f"  alternative: {a}")
        out.info(f"Confidence rationale: {f['confidence']['rationale']}")
        for m in f.get("missing_evidence", [])[:5]:
            out.muted(f"  missing evidence: {m}")
    if f.get("verification"):
        v = f["verification"][0]
        out.info(f"Next action: {v['purpose']} — `{v['command']}` ({v['where']})")
    if full:
        for v in f.get("verification", [])[1:6]:
            out.muted(f"  verify: {v['command']}  # {v['where']}")
        if f.get("f5_relevance"):
            out.muted(f"  BIG-IP context: {f['f5_relevance']}")


# ----------------------------------------------------------------- handlers
def cmd_help(ctx: Ctx, args: dict, opts: dict) -> None:
    from .engine import REGISTRY

    topic = args.get("command")
    if topic:
        matches = [c for c in REGISTRY.commands.values() if c.name.startswith(topic.lower())]
        if not matches:
            raise ConsoleError(f"No help for '{topic}'", REGISTRY.names()[:5])
        for c in matches:
            ctx.out.head(c.usage())
            ctx.out.info(c.summary)
            for a in c.args:
                ctx.out.muted(f"  <{a.name}> {a.help}")
            for o in c.options:
                ctx.out.muted(f"  --{o.name} {o.help}" + (f" (one of {', '.join(o.choices)})" if o.choices else ""))
            for e in c.examples:
                ctx.out.muted(f"  e.g. {e}")
        return
    ctx.out.head("PACKETOPS COMMAND DECK")
    cats: dict[str, list[Command]] = {}
    for c in REGISTRY.commands.values():
        cats.setdefault(c.category, []).append(c)
    for cat in ("general", "capture", "analysis", "f5", "findings", "missions", "reports"):
        if cat not in cats:
            continue
        ctx.out.info(cat.upper())
        ctx.out.table(["command", "description"], [[c.usage(), c.summary] for c in sorted(cats[cat], key=lambda c: c.name)])
    ctx.out.muted("Type 'help <command>' for details. Tab completes commands and ids.")


def cmd_status(ctx: Ctx, args: dict, opts: dict) -> None:
    p = ctx.principal
    prof = gamification.profile(p.tenant_id, p.user_id)
    ctx.out.head("OPERATOR STATUS")
    ctx.out.kv([("Operator", p.display_name), ("Roles", ", ".join(p.roles)), ("Level", f"{prof['level']} — {prof['title']}"),
                ("XP", f"{prof['xp']}" + (f" / next level at {prof['next_level_xp']}" if prof["next_level_xp"] else " (max level)")),
                ("Achievements", f"{sum(1 for a in prof['achievements'] if a['earned'])}/{len(prof['achievements'])}")])
    if ctx.capture_id:
        try:
            st = cap_svc.capture_status(p, ctx.capture_id)
            cap = cap_svc.get_capture(p, ctx.capture_id)
            job = st.get("job") or {}
            ctx.out.kv([("Selected capture", f"{cap['_id']} ({cap['filename']})"), ("Capture status", st["status"]),
                        ("Analysis", f"{job.get('stage', '-')} {job.get('progress', 0)}%" if job else "not started"),
                        ("Training data", "yes (synthetic)" if cap.get("training") else "no")])
        except ApiError:
            ctx.set_capture(None)
            ctx.out.warn("Previously selected capture is no longer available.")
    else:
        ctx.out.muted("No capture selected. Use 'pcap list' or 'pcap upload'.")
    run = TenantDB(p.tenant_id).mission_runs.find_one({"user_id": p.user_id, "status": "active"}, sort=[("started_at", -1)])
    if run:
        done = sum(1 for o in run["objectives"] if o.get("completed"))
        ctx.out.info(f"Active mission: {run['mission_id']} — {done}/{len(run['objectives'])} objectives complete")


def cmd_whoami(ctx: Ctx, args: dict, opts: dict) -> None:
    p = ctx.principal
    ctx.out.kv([("User", p.email), ("Tenant", p.tenant_id), ("Roles", ", ".join(p.roles)),
                ("Permissions", ", ".join(sorted(p.permissions)))])


def cmd_clear(ctx: Ctx, args: dict, opts: dict) -> None:
    ctx.out.action("clear")


def cmd_history(ctx: Ctx, args: dict, opts: dict) -> None:
    hist = ctx.session.get("history", [])[-30:]
    ctx.out.table(["#", "command"], [[i + 1, h] for i, h in enumerate(hist)])


def cmd_pcap_upload(ctx: Ctx, args: dict, opts: dict) -> None:
    ctx.principal.require("capture:upload")
    ctx.out.info("Select a .pcap or .pcapng file. It will be hashed (SHA-256), validated and stored as write-once evidence.")
    ctx.out.action("open_upload", accept=".pcap,.pcapng,.cap", then="pcap inspect")


def cmd_pcap_list(ctx: Ctx, args: dict, opts: dict) -> None:
    items, total = cap_svc.list_captures(ctx.principal, training=(opts.get("mode") == "training") if opts.get("mode") else None,
                                         limit=opts.get("limit") or 15)
    if not items:
        ctx.out.muted("No captures yet. Use 'pcap upload' or start a training mission ('mission list').")
        return
    rows = [[c["id"], c["filename"][:32], c["status"], c.get("stats", {}).get("packets", c.get("metadata", {}).get("packet_count")),
             c.get("stats", {}).get("findings", "-"), "training" if c.get("training") else "evidence",
             c["created_at"].strftime("%Y-%m-%d %H:%M") if hasattr(c["created_at"], "strftime") else c["created_at"]] for c in items]
    ctx.out.table(["capture_id", "file", "status", "packets", "findings", "mode", "uploaded"], rows, total=total,
                  refs={"captures": [c["id"] for c in items]})
    if ctx.capture_id:
        ctx.out.muted(f"Selected: {ctx.capture_id}")


def cmd_pcap_use(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _resolve_capture(ctx, args["capture"])
    ctx.set_capture(cap["_id"])
    ctx.out.ok(f"Selected capture {cap['_id']} ({cap['filename']}, status {cap['status']})", {"captures": [cap["_id"]]})


def cmd_pcap_inspect(ctx: Ctx, args: dict, opts: dict) -> None:
    p = ctx.principal
    cap = _resolve_capture(ctx, args.get("capture") or ctx.capture_id)
    ctx.set_capture(cap["_id"])
    meta = cap.get("metadata") or {}
    ctx.out.ok(f"Evidence file validated ({cap['format']} {meta.get('format_version', '')}, {meta.get('packet_count', '?')} packets, "
               f"{_human_bytes(cap['size_bytes'])})")
    ctx.out.ok(f"SHA-256 fingerprint calculated: {cap['sha256']}")
    if cap.get("training"):
        ctx.out.warn("SYNTHETIC TRAINING DATA — not production evidence")
    if cap["status"] != "analyzed":
        if cap["status"] in ("queued", "analyzing"):
            st = cap_svc.capture_status(p, cap["_id"])
            job = st.get("job") or {}
            ctx.out.info(f"[*] Analysis in progress: {job.get('stage')} {job.get('progress')}% — {job.get('message', '')}")
            ctx.out.action("watch_job", capture_id=cap["_id"], job_id=job.get("id"), then="pcap inspect")
            return
        p.require("analysis:run")
        job = cap_svc.start_analysis(p, cap["_id"], force=cap["status"] in ("failed", "cancelled"))
        cap = cap_svc.get_capture(p, cap["_id"])
        if cap["status"] != "analyzed":
            if job.get("status") == "failed":
                ctx.out.err(f"Analysis failed: {(job.get('error') or {}).get('message', 'see job diagnostics')}")
                return
            ctx.out.info(f"[*] Analysis job {job['id']} queued. Progress streams below; the summary prints when it completes.")
            ctx.out.action("watch_job", capture_id=cap["_id"], job_id=job["id"], then="pcap inspect")
            return
    stats = cap.get("stats") or {}
    an = cap.get("analysis") or {}
    ctx.out.ok(f"Protocol dissection completed ({an.get('tshark_version', 'tshark')}, engine {an.get('engine_version', '?')})")
    ctx.out.ok(f"TCP conversations reconstructed ({stats.get('tcp_conversations', 0)})")
    ctx.out.ok(f"TLS handshakes examined ({stats.get('tls_handshakes', 0)})")
    ctx.out.ok(f"DNS transactions matched ({stats.get('dns_queries', 0)} queries)")
    ctx.out.head("ANALYSIS SUMMARY")
    sev = stats.get("findings_by_severity", {})
    ctx.out.kv([
        ("Capture", f"{cap['_id']} ({cap['filename']})"),
        ("Packets analyzed", stats.get("packets")),
        ("Capture duration", f"{stats.get('duration_s', 0):.3f} s ({_ts(meta.get('first_ts_ns'))} → {_ts(meta.get('last_ts_ns'))})"),
        ("Link types", ", ".join(meta.get("link_types", []))),
        ("TCP conversations", stats.get("tcp_conversations")),
        ("UDP conversations", stats.get("udp_conversations")),
        ("Retransmission events", stats.get("retransmissions")),
        ("SYN retransmissions", stats.get("syn_retransmissions")),
        ("Incomplete handshakes", stats.get("incomplete_handshakes")),
        ("TCP resets", stats.get("resets")),
        ("TLS alerts", stats.get("tls_alerts")),
        ("HTTP requests", stats.get("http_requests")),
        ("DNS unanswered", stats.get("dns_unanswered")),
        ("Potential issues", f"{stats.get('findings', 0)} (high {sev.get('high', 0)}, medium {sev.get('medium', 0)}, "
                             f"low {sev.get('low', 0)}, info {sev.get('info', 0)})"),
    ])
    for lim in (cap.get("limitations") or [])[:6]:
        (ctx.out.warn if lim["severity"] == "warning" else ctx.out.muted)(f"Limitation: {lim['text']}")
    ctx.out.muted("Next: 'findings list', 'tcp handshakes', 'flows list'.")


def cmd_pcap_stats(ctx: Ctx, args: dict, opts: dict) -> None:
    from app.services.stats import capture_summary

    cap = _analyzed(ctx)
    s = capture_summary(ctx.principal, cap["_id"])
    st = cap.get("stats") or {}
    ctx.out.head(f"CAPTURE STATISTICS — {cap['filename']}")
    ctx.out.kv([("Packets", st.get("packets")), ("Bytes", _human_bytes(st.get("bytes"))), ("Duration", f"{st.get('duration_s')} s"),
                ("TCP / UDP / other conversations", f"{s['tcp_conversations']} / {s['udp_conversations']} / {s['other_conversations']}"),
                ("IPv4 / IPv6 packets", f"{s['ip_versions'].get('4', 0)} / {s['ip_versions'].get('6', 0)}"),
                ("VLAN IDs", ", ".join(s["vlans"]) or "none"), ("Encapsulation", ", ".join(f"{k}:{v}" for k, v in s["encapsulation"].items()) or "none"),
                ("Expert info", ", ".join(f"{k}:{v}" for k, v in s["expert"].items()) or "none"),
                ("F5 trailer frames", s["f5"]["trailer_frames"])])
    ctx.out.info("TOP ENDPOINTS")
    ctx.out.table(["ip", "pkts tx", "bytes tx", "pkts rx", "bytes rx"],
                  [[e["ip"], e["packets_tx"], _human_bytes(e["bytes_tx"]), e["packets_rx"], _human_bytes(e["bytes_rx"])] for e in s["endpoints"][:10]])


def cmd_pcap_protocols(ctx: Ctx, args: dict, opts: dict) -> None:
    from app.services.stats import capture_summary

    cap = _analyzed(ctx)
    s = capture_summary(ctx.principal, cap["_id"])
    total = sum(p["packets"] for p in s["protocols"]) or 1
    ctx.out.head("PROTOCOL DISTRIBUTION (highest layer per packet)")
    ctx.out.table(["protocol", "packets", "share"],
                  [[p["name"], p["packets"], f"{100 * p['packets'] / total:.1f}%"] for p in s["protocols"][:25]])
    ctx.out.muted("Layers present: " + ", ".join(f"{p['name']}({p['packets']})" for p in s["layers"][:30]))


def cmd_flows_list(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    items, total = flow_svc.list_flows(ctx.principal, cap["_id"], state=opts.get("state"), ip=opts.get("ip"), port=opts.get("port"),
                                       transport=opts.get("transport"), limit=opts.get("limit") or 20)
    if not items:
        ctx.out.muted("No conversations match.")
        return
    rows = [[f["local_id"], f"{f['client_ip']}:{f['client_port']}", f"{f['server_ip']}:{f['server_port']}", f["state"], f["packets"],
             f"{f['duration_ms']:.0f} ms", f.get("retransmissions", 0) if f["transport"] == "tcp" else "-",
             ",".join(f.get("app_protocols", [])[:3]), ",".join(f.get("finding_ids", [])[:4])] for f in items]
    ctx.out.table(["flow", "client", "server", "state", "pkts", "duration", "retrans", "app", "findings"], rows, total=total,
                  refs={"flows": [f["local_id"] for f in items]})
    ctx.out.muted("Sorted by issue score. 'flow inspect <flow>' for detail, 'timeline show <flow>' for events.")


def cmd_flow_inspect(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    f = flow_svc.get_flow(ctx.principal, cap["_id"], args["flow"])
    ctx.out.head(f"FLOW {f['local_id']} — {f['client_ip']}:{f['client_port']} → {f['server_ip']}:{f['server_port']} ({f['transport']})")
    items = [("State", f["state"]), ("Frames", f"#{f['first_frame']} … #{f['last_frame']}"), ("Start", _ts(f["first_ts_ns"])),
             ("Duration", f"{f['duration_ms']} ms"), ("Packets c→s / s→c", f"{f['packets_c2s']} / {f['packets_s2c']}"),
             ("Bytes c→s / s→c", f"{_human_bytes(f['bytes_c2s'])} / {_human_bytes(f['bytes_s2c'])}"),
             ("Application", ", ".join(f.get("app_protocols", [])) or "-")]
    if f["transport"] == "tcp":
        hs = f["handshake"]
        items += [("Handshake", f"{'complete' if hs['complete'] else 'incomplete'}; SYN×{hs['syn_count']} SYN-ACK×{hs['synack_count']}"
                   + (f"; RTT {hs['rtt_ms']} ms" if hs.get("rtt_ms") else "")),
                  ("MSS client/server", f"{f['mss']['client']} / {f['mss']['server']}"),
                  ("Retransmissions", f["retransmissions"]), ("Resets", len(f.get("rsts", []))), ("Max idle", f"{f['max_idle_ms']} ms")]
        if f.get("direction_inferred"):
            items.append(("Note", "handshake not captured; client/server roles inferred from ports"))
        if f.get("tls"):
            t = f["tls"]
            ch, sh = t.get("client_hello") or {}, t.get("server_hello") or {}
            items += [("TLS SNI", ch.get("sni") or "-"), ("TLS negotiated", f"{sh.get('version') or '-'} {sh.get('cipher_suite') or ''}"),
                      ("TLS alerts", ", ".join(f"{a['description']}({a['level']})#{a['frame']}" for a in t.get("alerts", [])) or "none")]
        if f.get("http_requests"):
            items.append(("HTTP requests", f["http_requests"]))
        if f.get("f5"):
            items.append(("F5 trailer", f"flow ids {', '.join(f['f5'].get('flow_ids', []))}; peer {', '.join(f['f5'].get('peer_ids', []))}"
                          + (f"; virtual {f['f5']['vip']}" if f["f5"].get("vip") else "")))
    items.append(("Findings", ", ".join(f.get("finding_ids", [])) or "none"))
    ctx.out.kv(items, refs={"findings": f.get("finding_ids", []), "frames": [f["first_frame"], f["last_frame"]]})
    for h in (f.get("http") or [])[:8]:
        ctx.out.muted(f"  #{h['request_frame']} {h['method']} {h['host'] or ''}{h['path']} → {h['status'] or 'no response'}"
                      + (f" in {h['latency_ms']} ms" if h.get("latency_ms") is not None else ""), {"frames": [h["request_frame"]]})


def cmd_timeline(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    f = flow_svc.get_flow(ctx.principal, cap["_id"], args["flow"])
    ctx.out.head(f"TIMELINE {f['local_id']} — {f['client_ip']}:{f['client_port']} ⇄ {f['server_ip']}:{f['server_port']}")
    t0 = f["first_ts_ns"]
    events = f.get("timeline") or []
    if not events:
        ctx.out.muted("No key events recorded for this conversation (UDP conversations have no TCP state events).")
        return
    ctx.out.table(["t+ms", "frame", "dir", "event"],
                  [[f"{(e['ts_ns'] - t0) / 1e6:.3f}", f"#{e['frame']}", {"c2s": "→", "s2c": "←"}.get(e["dir"], e["dir"]), e["event"]]
                   for e in events], refs={"frames": [e["frame"] for e in events]})


def _rule_findings(ctx: Ctx, cap_id: str, prefixes: tuple[str, ...]) -> list[dict]:
    items, _ = find_svc.list_findings(ctx.principal, capture_id=cap_id, limit=200)
    out = []
    for f in items:
        if f["rule_id"].startswith(prefixes):
            out.append(find_svc.get_finding(ctx.principal, f["id"]))
    return out


def cmd_tcp_handshakes(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    tdb = TenantDB(ctx.principal.tenant_id)
    base = {"capture_id": cap["_id"], "transport": "tcp"}
    total = tdb.flows.count_documents({**base, "handshake.syn_count": {"$gt": 0}})
    complete = tdb.flows.count_documents({**base, "handshake.complete": True})
    rtts = [d["handshake"]["rtt_ms"] for d in tdb.flows.find({**base, "handshake.rtt_ms": {"$ne": None}}, {"handshake.rtt_ms": 1}).limit(5000)]
    ctx.out.head("TCP HANDSHAKES")
    ctx.out.kv([("Connection attempts (SYN seen)", total), ("Completed handshakes", complete),
                ("Incomplete", total - complete), ("Median SYN→SYN-ACK", f"{sorted(rtts)[len(rtts) // 2]:.1f} ms" if rtts else "n/a")])
    found = _rule_findings(ctx, cap["_id"], ("TCP-001", "TCP-002", "TCP-007", "TCP-011"))
    if not found:
        ctx.out.ok("No handshake failures or slow handshakes detected.")
        return
    ctx.out.warn("Potential handshake failures identified")
    for f in found:
        ctx.out.blank()
        _finding_card(ctx.out, f)


def cmd_tcp_retrans(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    items, _ = flow_svc.list_flows(ctx.principal, cap["_id"], transport="tcp", sort="retransmissions", limit=opts.get("limit") or 10)
    items = [f for f in items if f.get("retransmissions")]
    st = cap.get("stats") or {}
    ctx.out.head("TCP RETRANSMISSIONS")
    ctx.out.kv([("Data retransmissions", st.get("retransmissions", 0)), ("SYN retransmissions", st.get("syn_retransmissions", 0))])
    if items:
        ctx.out.table(["flow", "client", "server", "retrans", "packets"],
                      [[f["local_id"], f"{f['client_ip']}:{f['client_port']}", f"{f['server_ip']}:{f['server_port']}", f["retransmissions"],
                        f["packets"]] for f in items], refs={"flows": [f["local_id"] for f in items]})
    found = _rule_findings(ctx, cap["_id"], ("TCP-003", "TCP-004", "TCP-008"))
    for f in found:
        ctx.out.blank()
        _finding_card(ctx.out, f)
    ctx.out.muted("Note: a retransmission shows the sender did not get a timely ACK; it does not by itself prove packet loss.")
    if not items and not found:
        ctx.out.ok("No data retransmissions observed.")


def cmd_tcp_resets(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    tdb = TenantDB(ctx.principal.tenant_id)
    flows = list(tdb.flows.find({"capture_id": cap["_id"], "rsts.0": {"$exists": True}},
                                {"local_id": 1, "client_ip": 1, "client_port": 1, "server_ip": 1, "server_port": 1, "rsts": 1,
                                 "handshake.complete": 1}).limit(opts.get("limit") or 20))
    ctx.out.head("TCP RESETS")
    if not flows:
        ctx.out.ok("No TCP resets in this capture.")
        return
    rows = []
    for f in flows:
        for r in f["rsts"][:3]:
            sender = f"{f['client_ip']}:{f['client_port']}" if r["dir"] == "c2s" else f"{f['server_ip']}:{f['server_port']}"
            phase = "after data" if r["after_data"] else ("after handshake" if r["after_handshake"] else "during setup")
            rows.append([f["local_id"], f"#{r['frame']}", sender, phase, r.get("pending_http") or 0, r.get("f5_rst_cause") or "-"])
    ctx.out.table(["flow", "frame", "sent by", "phase", "pending http", "BIG-IP cause"], rows,
                  refs={"flows": [f["local_id"] for f in flows], "frames": [r["frame"] for f in flows for r in f["rsts"][:3]]})
    for f in _rule_findings(ctx, cap["_id"], ("TCP-002", "TCP-006", "TCP-010", "F5-001")):
        ctx.out.blank()
        _finding_card(ctx.out, f)


def cmd_tls_inspect(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    tdb = TenantDB(ctx.principal.tenant_id)
    flows = list(tdb.flows.find({"capture_id": cap["_id"], "tls": {"$ne": None}},
                                {"local_id": 1, "server_ip": 1, "server_port": 1, "tls": 1}).limit(opts.get("limit") or 25))
    ctx.out.head("TLS HANDSHAKES")
    if not flows:
        ctx.out.muted("No TLS handshakes observed.")
        return
    rows = []
    for f in flows:
        t = f["tls"]
        ch, sh = t.get("client_hello") or {}, t.get("server_hello") or {}
        cert = (t.get("certificates") or [{}])[0]
        rows.append([f["local_id"], f"{f['server_ip']}:{f['server_port']}", ch.get("sni") or "-", sh.get("version") or "no ServerHello",
                     sh.get("cipher_suite") or "-", sh.get("alpn") or "-",
                     ",".join(a["description"] for a in t.get("alerts", [])) or "-",
                     (cert.get("subject_cn") or "-") + (f" (exp {cert['not_after'][:10]})" if cert.get("not_after") else "")])
    ctx.out.table(["flow", "server", "SNI", "version", "cipher", "ALPN", "alerts", "certificate"], rows,
                  refs={"flows": [f["local_id"] for f in flows]})
    ctx.out.muted("TLS 1.3 certificates and post-handshake alerts are encrypted and not visible without keys.")
    for f in _rule_findings(ctx, cap["_id"], ("TLS-",)):
        ctx.out.blank()
        _finding_card(ctx.out, f)


def cmd_dns_inspect(ctx: Ctx, args: dict, opts: dict) -> None:
    from app.services.stats import capture_summary

    cap = _analyzed(ctx)
    s = capture_summary(ctx.principal, cap["_id"])
    d = s["dns"]
    ctx.out.head("DNS TRANSACTIONS")
    ctx.out.kv([("Queries", d.get("queries", 0)), ("Responses", d.get("responses", 0)), ("Unanswered", d.get("unanswered", 0)),
                ("Pending at capture end", d.get("pending_at_capture_end", 0)), ("Duplicate queries (same txid)", d.get("duplicate_queries", 0)),
                ("Response codes", ", ".join(f"{k}:{v}" for k, v in d.get("rcodes", {}).items()) or "-")])
    txns = s.get("dns_transactions", [])[: opts.get("limit") or 20]
    if txns:
        ctx.out.table(["query", "txid", "client", "server", "name", "type", "rcode", "latency"],
                      [[f"#{t['query_frame']}", t["txid_hex"], t["client"], t["server"], t["qname"], t["qtype"], t["rcode_name"] or "NO RESPONSE",
                        f"{t['latency_ms']} ms" if t["latency_ms"] is not None else "-"] for t in txns],
                      refs={"frames": [t["query_frame"] for t in txns]})
    for f in _rule_findings(ctx, cap["_id"], ("DNS-",)):
        ctx.out.blank()
        _finding_card(ctx.out, f)


def cmd_http_inspect(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    tdb = TenantDB(ctx.principal.tenant_id)
    flows = list(tdb.flows.find({"capture_id": cap["_id"], "http.0": {"$exists": True}}, {"local_id": 1, "http": 1}).limit(100))
    rows = []
    for f in flows:
        for h in f["http"]:
            rows.append([f"#{h['request_frame']}", f["local_id"], h["method"], (h["host"] or "") + h["path"][:60], h["status"] or "no response",
                         f"{h['ttfb_ms']}" if h.get("ttfb_ms") is not None else "-", f"{h['latency_ms']}" if h.get("latency_ms") is not None else "-"])
    ctx.out.head("HTTP TRANSACTIONS (cleartext)")
    if not rows:
        ctx.out.muted("No cleartext HTTP. HTTPS content requires decryption keys.")
    else:
        limit = opts.get("limit") or 25
        ctx.out.table(["request", "flow", "method", "url", "status", "ttfb ms", "total ms"], rows[:limit], total=len(rows),
                      refs={"frames": [int(r[0][1:]) for r in rows[:limit] if r[0] != "#0"], "flows": [f["local_id"] for f in flows]})
    for f in _rule_findings(ctx, cap["_id"], ("HTTP-", "F5-002")):
        ctx.out.blank()
        _finding_card(ctx.out, f)


def cmd_findings_list(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    items, total = find_svc.list_findings(ctx.principal, capture_id=cap["_id"], severity=opts.get("severity"), status=opts.get("status"),
                                          limit=opts.get("limit") or 30)
    if not items:
        ctx.out.ok("No findings for this capture" + (" with these filters." if opts.get("severity") or opts.get("status") else "."))
        return
    ctx.out.table(["id", "severity", "confidence", "rule", "status", "title"],
                  [[f["short_id"], f["severity"], f["confidence"]["level"], f["rule_id"], f["status"], f["title"]] for f in items],
                  total=total, refs={"findings": [f["short_id"] for f in items]})
    ctx.out.muted("Severity (impact) and confidence (strength of evidence) are rated separately. 'finding inspect <id>' for detail.")


def cmd_finding_inspect(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    f = find_svc.get_finding(ctx.principal, args["finding"], cap["_id"])
    ctx.out.head(f"FINDING {f['short_id']} — {f['rule_id']} v{f['rule_version']}")
    ctx.out.info(f"Summary: {f['summary']}")
    _finding_card(ctx.out, f, full=True)
    ctx.out.muted(f"Status: {f['status']}" + (f", assigned to {f['assignee']}" if f.get("assignee") else "")
                  + ". 'evidence show " + f["short_id"] + "' lists the cited packets.")


def cmd_finding_status(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    f = find_svc.update_finding(ctx.principal, args["finding"], status=args["status"], note=args.get("note"), capture_id=cap["_id"])
    ctx.out.ok(f"{f['short_id']} is now '{f['status']}'")
    if f["status"] == "confirmed":
        ctx.out.muted("Root-cause confirmation recorded with your verification note.")


def cmd_evidence_show(ctx: Ctx, args: dict, opts: dict) -> None:
    cap = _analyzed(ctx)
    ev = find_svc.finding_evidence(ctx.principal, args["finding"], cap["_id"])
    f = ev["finding"]
    ctx.out.head(f"EVIDENCE FOR {f['short_id']} — {f['title']}")
    ctx.out.info(f"Rule {f['rule_id']} v{f['rule_version']}: {(ev.get('rule') or {}).get('detection_logic', '')}")
    if ev["packets"]:
        ctx.out.table(["frame", "role", "time (s)", "source", "destination", "proto", "info"],
                      [[f"#{p['number']}", p.get("role") or "", f"{p['rel_s']:.6f}", f"{p['src']}:{p['sport'] or ''}",
                        f"{p['dst']}:{p['dport'] or ''}", p["protocol"], (p.get("info") or "")[:80]] for p in ev["packets"]],
                      refs={"frames": [p["number"] for p in ev["packets"]]})
    for o in ev["observations"]:
        ctx.out.info(f"• {o['text']}", {"frames": o.get("frames", [])[:20]})
    for m in ev["missing_evidence"]:
        ctx.out.muted(f"missing: {m}")
    ctx.out.action("open_evidence", capture_id=cap["_id"], finding=f["short_id"], frames=[p["number"] for p in ev["packets"]][:50])


def cmd_mission_list(ctx: Ctx, args: dict, opts: dict) -> None:
    from app.services.missions import list_missions

    ms = list_missions(ctx.principal)
    ctx.out.head("TRAINING MISSIONS (synthetic captures, separate from production evidence)")
    ctx.out.table(["mission", "title", "difficulty", "xp", "status"],
                  [[m["id"], m["title"], m["difficulty"], m["xp"], m["status"]] for m in ms])
    ctx.out.muted("Start one with 'mission start <mission>'.")


def cmd_mission_start(ctx: Ctx, args: dict, opts: dict) -> None:
    from app.services.missions import start_mission

    run = start_mission(ctx.principal, args["mission"])
    ctx.set_capture(run["capture_id"])
    ctx.out.ok(f"Mission '{run['title']}' started")
    ctx.out.warn("Training capture loaded — SYNTHETIC DATA, labelled and isolated from production investigations")
    ctx.out.info(run["briefing"])
    ctx.out.head("OBJECTIVES")
    for i, o in enumerate(run["objectives"], 1):
        ctx.out.info(f"{i}. [{'x' if o.get('completed') else ' '}] {o['prompt']}")
    ctx.out.muted("Investigate with the normal commands, then answer with: mission submit <objective#> <answer>")


def cmd_mission_status(ctx: Ctx, args: dict, opts: dict) -> None:
    from app.services.missions import active_run

    run = active_run(ctx.principal)
    if not run:
        ctx.out.muted("No active mission. 'mission list' to choose one.")
        return
    ctx.out.head(f"MISSION {run['mission_id']} — {run['title']}")
    for i, o in enumerate(run["objectives"], 1):
        ctx.out.info(f"{i}. [{'x' if o.get('completed') else ' '}] {o['prompt']}" + (f"  (attempts: {o.get('attempts', 0)})" if o.get("attempts") else ""))


def cmd_mission_submit(ctx: Ctx, args: dict, opts: dict) -> None:
    from app.services.missions import submit_answer

    res = submit_answer(ctx.principal, args["objective"], args["answer"])
    if res["correct"]:
        ctx.out.ok(f"Objective {args['objective']} verified against the analysis results.")
        if res.get("explanation"):
            ctx.out.muted(res["explanation"])
    else:
        ctx.out.err(f"Not confirmed by the evidence. {res.get('hint') or ''}")
    if res.get("mission_completed"):
        ctx.out.ok(f"MISSION COMPLETE — +{res.get('xp_awarded', 0)} XP" if res.get("xp_awarded") else "MISSION COMPLETE")
        for a in res.get("achievements", []):
            ctx.out.ok(f"Achievement unlocked: {a}")


def cmd_f5_correlate(ctx: Ctx, args: dict, opts: dict) -> None:
    from app.services.f5 import correlate

    cap = _analyzed(ctx)
    other = opts.get("with")
    if other:
        other = _resolve_capture(ctx, other)["_id"]
    res = correlate(ctx.principal, cap["_id"], other_capture_id=other, config_id=opts.get("config"))
    ctx.out.head("BIG-IP TRAFFIC-FLOW CORRELATION")
    ctx.out.kv([("Client-side capture", res["client_capture_id"]), ("Server-side capture", res.get("server_capture_id") or "-"),
                ("Configuration metadata", res.get("config_name") or "none supplied"),
                ("Evidence of BIG-IP", "; ".join(res["bigip_evidence"]) or "none — BIG-IP presence not established"),
                ("Matched flow pairs", len(res["pairs"])), ("Unmatched client-side flows", res["unmatched_client"]),
                ("Unmatched server-side flows", res["unmatched_server"])])
    if res["pairs"]:
        ctx.out.table(["client-side", "server-side", "method", "confidence", "virtual / pool member", "notes"],
                      [[f"{p['client_flow']} {p['client']} → {p['vip']}", f"{p['server_flow']} {p['snat']} → {p['member']}", p["method"],
                        p["confidence"], f"{p.get('virtual') or '-'} / {p.get('pool') or '-'}", "; ".join(p.get("notes", []))[:80]]
                       for p in res["pairs"][:25]])
    for o in res.get("observations", []):
        (ctx.out.warn if o.get("level") == "warn" else ctx.out.info)(o["text"], {"flows": o.get("flows", [])})
    for lim in res.get("limitations", []):
        ctx.out.muted(f"limitation: {lim}")
    ctx.out.muted(f"Correlation {res['id']} saved.")


def cmd_report_generate(ctx: Ctx, args: dict, opts: dict) -> None:
    from app.services.reports import create_report

    cap = _analyzed(ctx)
    rep = create_report(ctx.principal, cap["_id"], fmt=opts.get("format") or "html")
    ctx.out.ok(f"Report {rep['id']} generated ({rep['format'].upper()}, {rep['finding_count']} findings, {rep['evidence_count']} evidence references)")
    ctx.out.action("download", url=f"/api/v1/reports/{rep['id']}/download", label=rep["filename"])


def cmd_export_findings(ctx: Ctx, args: dict, opts: dict) -> None:
    ctx.principal.require("export:data")
    cap = _analyzed(ctx)
    fmt = opts.get("format") or "json"
    ctx.out.ok(f"Findings export prepared ({fmt.upper()}); payloads and sensitive fields are excluded by default.")
    ctx.out.action("download", url=f"/api/v1/captures/{cap['_id']}/findings/export?format={fmt}", label=f"findings-{cap['_id']}.{fmt}")


def build_registry() -> Registry:
    r = Registry()
    C = Command
    lim = Opt("limit", "int", help="maximum rows")
    r.register(C(("help",), "Show commands, or details for one command", cmd_help,
                 [Arg("command", "text", required=False, rest=True)], examples=["help tcp handshakes"]))
    r.register(C(("status",), "Operator level, selected capture, analysis and mission status", cmd_status))
    r.register(C(("whoami",), "Show your identity, tenant and permissions", cmd_whoami))
    r.register(C(("clear",), "Clear the screen", cmd_clear))
    r.register(C(("history",), "Show recent commands", cmd_history))
    r.register(C(("pcap", "upload"), "Upload a PCAP/PCAPNG file as evidence", cmd_pcap_upload, permission="capture:upload", category="capture"))
    r.register(C(("pcap", "list"), "List captures in your tenant", cmd_pcap_list,
                 options=[lim, Opt("mode", choices=["evidence", "training"])], category="capture"))
    r.register(C(("pcap", "use"), "Select the capture that other commands work on", cmd_pcap_use,
                 [Arg("capture", "capture", prompt="Which capture? (id or filename)")], category="capture"))
    r.register(C(("pcap", "inspect"), "Validate, analyse (if needed) and summarise a capture", cmd_pcap_inspect,
                 [Arg("capture", "capture", session_default="capture_id", prompt="Which capture should be inspected?")],
                 category="capture", examples=["pcap inspect capture.pcapng"]))
    r.register(C(("pcap", "stats"), "Capture statistics and top endpoints", cmd_pcap_stats, category="capture", needs_capture=True))
    r.register(C(("pcap", "protocols"), "Protocol distribution", cmd_pcap_protocols, category="capture", needs_capture=True))
    r.register(C(("flows", "list"), "List conversations, most suspicious first", cmd_flows_list,
                 options=[lim, Opt("state", choices=["established", "closed", "reset", "syn-unanswered", "handshake-incomplete",
                                                     "half-closed", "mid-stream", "udp"]),
                          Opt("ip", "ip"), Opt("port", "int"), Opt("transport", choices=["tcp", "udp"])], category="analysis"))
    r.register(C(("flow", "inspect"), "Details of one conversation", cmd_flow_inspect,
                 [Arg("flow", "flow", prompt="Which flow? (e.g. t3)")], category="analysis"))
    r.register(C(("timeline", "show"), "Key packet events of a conversation", cmd_timeline,
                 [Arg("flow", "flow", prompt="Timeline for which flow?")], category="analysis"))
    r.register(C(("tcp", "handshakes"), "Handshake statistics and failures", cmd_tcp_handshakes, category="analysis"))
    r.register(C(("tcp", "retransmissions"), "Retransmissions per conversation", cmd_tcp_retrans, options=[lim], category="analysis"))
    r.register(C(("tcp", "resets"), "TCP resets and who sent them", cmd_tcp_resets, options=[lim], category="analysis"))
    r.register(C(("tls", "inspect"), "TLS handshakes, versions, certificates and alerts", cmd_tls_inspect, options=[lim], category="analysis"))
    r.register(C(("dns", "inspect"), "DNS transactions, latency and errors", cmd_dns_inspect, options=[lim], category="analysis"))
    r.register(C(("http", "inspect"), "HTTP requests, status codes and timing", cmd_http_inspect, options=[lim], category="analysis"))
    r.register(C(("f5", "correlate"), "Correlate client-side and server-side flows through a BIG-IP", cmd_f5_correlate,
                 options=[Opt("with", "capture", help="server-side capture id"), Opt("config", "word", help="BIG-IP metadata id")],
                 permission="correlation:run", category="f5", examples=["f5 correlate --with cap_… --config f5c_…"]))
    r.register(C(("findings", "list"), "Findings for the selected capture", cmd_findings_list,
                 options=[lim, Opt("severity", choices=["critical", "high", "medium", "low", "info"]),
                          Opt("status", choices=list(find_svc.STATUSES))], category="findings"))
    r.register(C(("finding", "inspect"), "Full finding: evidence, hypothesis, alternatives, verification", cmd_finding_inspect,
                 [Arg("finding", "finding", prompt="Which finding? (e.g. F1)")], category="findings"))
    r.register(C(("finding", "status"), "Set finding status (confirm requires a verification note)", cmd_finding_status,
                 [Arg("finding", "finding", prompt="Which finding?"),
                  Arg("status", "word", choices=list(find_svc.STATUSES), prompt="New status?"),
                  Arg("note", "text", required=False, rest=True)], permission="finding:update", category="findings",
                 examples=['finding status F1 confirmed "Verified with tmsh show ltm pool: all members down"']))
    r.register(C(("evidence", "show"), "Packets and observations behind a finding", cmd_evidence_show,
                 [Arg("finding", "finding", prompt="Evidence for which finding?")], category="findings"))
    r.register(C(("mission", "list"), "List training missions", cmd_mission_list, category="missions"))
    r.register(C(("mission", "start"), "Start a training mission", cmd_mission_start,
                 [Arg("mission", "mission", prompt="Which mission? (see 'mission list')")], permission="mission:play", category="missions",
                 examples=["mission start tcp-handshake"]))
    r.register(C(("mission", "status"), "Objectives of the active mission", cmd_mission_status, category="missions"))
    r.register(C(("mission", "submit"), "Answer a mission objective", cmd_mission_submit,
                 [Arg("objective", "int", prompt="Objective number?"), Arg("answer", "text", rest=True, prompt="Your answer?")],
                 permission="mission:play", category="missions"))
    r.register(C(("report", "generate"), "Generate an evidence-linked report", cmd_report_generate,
                 options=[Opt("format", choices=["html", "pdf", "json"])], permission="report:create", category="reports"))
    r.register(C(("export", "findings"), "Export findings (JSON or CSV)", cmd_export_findings,
                 options=[Opt("format", choices=["json", "csv"])], permission="export:data", category="reports"))
    return r


def session_expiry() -> dt.datetime:
    return utcnow() + dt.timedelta(hours=12)
