"""Evidence-linked forensic reports (JSON, HTML, PDF).

Every statement in a report comes from stored analysis results: capture
metadata, deterministic findings with their evidence frames, correlation
results, and (when present) an AI synthesis that is labelled as such and was
validated against the evidence before it was stored. Reports never include
packet payloads.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import tempfile
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from app.analysis.pipeline import ENGINE_VERSION
from app.analysis.rules import get_rule
from app.core.config import get_settings
from app.core.errors import ApiError, not_found
from app.core.security import Principal
from app.db import TenantDB, clean, new_id, utcnow
from app.services import gamification
from app.services.audit import audit
from app.services.captures import get_capture
from app.storage import get_storage, tenant_key

FORMATS = {"json": "application/json", "html": "text/html; charset=utf-8", "pdf": "application/pdf"}
SEVERITIES = ("critical", "high", "medium", "low", "info")
_env = Environment(loader=PackageLoader("app", "templates"), autoescape=select_autoescape(["html"]), trim_blocks=True,
                   lstrip_blocks=True)

METHODOLOGY = [
    "The capture file was streamed to storage, its SHA-256 digest computed, and its PCAP/PCAPNG structure validated block by "
    "block (link types, interfaces, timestamps, truncation).",
    "Packets were dissected with tshark in a resource-limited, network-isolated worker using a fixed field list; no display "
    "filter or user input was passed to tshark.",
    "Conversations were reconstructed per TCP/UDP 5-tuple; TCP analysis flags (retransmission, duplicate ACK, zero window, "
    "out-of-order) come from the Wireshark TCP engine.",
    "Versioned detection rules evaluated the reconstructed conversations. Each finding records the rule version, the "
    "frames it is based on, its confidence, alternatives and limitations.",
    "Severity describes impact; confidence describes the strength of the evidence. They are assigned independently.",
]


def _ts(ns: int | None) -> str:
    if not ns:
        return "-"
    return dt.datetime.fromtimestamp(ns / 1e9, tz=dt.UTC).strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def _exec_summary(cap: dict, findings: list[dict], correlations: list[dict]) -> list[str]:
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    stats = cap.get("stats") or {}
    lines = [f"Capture {cap['filename']} contains {stats.get('packets', 0)} packets over {stats.get('duration_s', 0)} s "
             f"({stats.get('tcp_conversations', 0)} TCP and {stats.get('udp_conversations', 0)} UDP conversations)."]
    if not findings:
        lines.append("No detection rule produced a finding. This does not prove the absence of a problem; see Limitations.")
    else:
        parts = [f"{n} {s}" for s, n in counts.items() if n]
        lines.append(f"{len(findings)} finding(s): {', '.join(parts)}.")
        for f in findings[:3]:
            lines.append(f"[{f['short_id']}] {f['title']} — {f['summary']} (confidence {f['confidence']['level']}; "
                         f"evidence frames {', '.join('#' + str(p['frame']) for p in f.get('packets', [])[:6]) or 'n/a'}).")
    for c in correlations[:2]:
        lines.append(f"BIG-IP correlation {c['id']}: {len(c.get('pairs', []))} client/server flow pair(s) "
                     f"via {', '.join(c.get('methods', [])) or 'no method'}.")
    return lines


def build_report_data(principal: Principal, capture_id: str) -> dict:
    principal.require("report:read")
    cap = get_capture(principal, capture_id)
    if cap["status"] != "analyzed":
        raise ApiError(409, "not_analyzed", f"Capture is '{cap['status']}'; analyse it before generating a report")
    tdb = TenantDB(principal.tenant_id)
    findings = [clean(f) for f in tdb.findings.find({"capture_id": capture_id}).sort("seq", 1)]
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]))
    summary = tdb.packet_summaries.find_one({"capture_id": capture_id}, {"protocols": 1, "endpoints": 1, "f5": 1, "dns": 1}) or {}
    correlations = [clean(c) for c in tdb.correlations.find(
        {"$or": [{"client_capture_id": capture_id}, {"server_capture_id": capture_id}]}).sort("created_at", -1).limit(3)]
    ai = tdb.ai_syntheses.find_one({"capture_id": capture_id, "validation.passed": True}, sort=[("created_at", -1)])
    rules_used = sorted({(f["rule_id"], f["rule_version"]) for f in findings})
    meta = cap.get("metadata") or {}
    evidence_count = sum(len(f.get("packets", [])) for f in findings)
    rule_limitations = []
    for rid, _ in rules_used:
        r = get_rule(rid)
        if r:
            rule_limitations.append({"rule_id": rid, "title": r.title, "limitations": r.limitations})
    return {
        "schema": "packetops.report/v1",
        "generated_at": utcnow().isoformat(),
        "generated_by": principal.email,
        "synthetic_training_data": bool(cap.get("training")),
        "capture": {
            "id": cap["_id"], "filename": cap["filename"], "sha256": cap["sha256"], "size_bytes": cap["size_bytes"],
            "format": cap["format"], "uploaded_at": str(cap.get("created_at")), "capture_point": cap.get("capture_point"),
            "description": cap.get("description"), "first_packet": _ts(meta.get("first_ts_ns")), "last_packet": _ts(meta.get("last_ts_ns")),
            "link_types": meta.get("link_types"), "interfaces": [i.get("name") or i.get("description") for i in meta.get("interfaces", [])],
            "comments": meta.get("comments", [])[:10], "truncated_packets": meta.get("truncated_packets"),
            "stats": cap.get("stats"),
        },
        "executive_summary": _exec_summary(cap, findings, correlations),
        "methodology": METHODOLOGY,
        "limitations": [lim["text"] for lim in cap.get("limitations", [])],
        "rule_limitations": rule_limitations,
        "findings": [{
            "id": f["short_id"], "rule_id": f["rule_id"], "rule_version": f["rule_version"], "title": f["title"],
            "severity": f["severity"], "confidence": f["confidence"], "status": f["status"], "summary": f["summary"],
            "observations": f["observations"], "assessment": f["assessment"], "probable_cause": f["probable_cause"],
            "alternatives": f["alternatives"], "verification": f["verification"], "remediation": f["remediation"],
            "missing_evidence": f["missing_evidence"], "limitations": f["limitations"], "f5_relevance": f.get("f5_relevance"),
            "evidence": [{"frame": p["frame"], "time": _ts(p.get("ts_ns")), "role": p.get("role")} for p in f.get("packets", [])],
            "flows": f.get("flows", []), "tuples": f.get("tuples", []),
            "timeline": [{"time": _ts(e["ts_ns"]), "frame": e.get("frame"), "event": e["event"]} for e in f.get("timeline", [])[:40]],
            "notes": [{"by": n.get("author_email"), "at": str(n.get("at")), "text": n.get("text")} for n in f.get("notes", [])],
        } for f in findings],
        "protocols": (summary.get("protocols") or [])[:15],
        "top_endpoints": (summary.get("endpoints") or [])[:10],
        "f5": {
            "trailer_frames": (summary.get("f5") or {}).get("trailer_frames", 0),
            "virtual_servers_in_trailers": (summary.get("f5") or {}).get("virtual_servers", {}),
            "correlations": [{"id": c["id"], "client_capture_id": c["client_capture_id"], "server_capture_id": c.get("server_capture_id"),
                              "config_name": c.get("config_name"), "bigip_evidence": c.get("bigip_evidence", []),
                              "pairs": [{k: p.get(k) for k in ("client_flow", "client", "vip", "server_flow", "snat", "member", "virtual",
                                                               "pool", "method", "confidence", "first_reset_side")} for p in c.get("pairs", [])[:50]],
                              "observations": [o["text"] for o in c.get("observations", [])], "limitations": c.get("limitations", [])}
                             for c in correlations],
        },
        "ai_synthesis": ({"provider": ai["provider"], "model": ai.get("model"), "created_at": str(ai["created_at"]),
                          "text": ai["synthesis"], "validation": ai["validation"]} if ai else None),
        "reproducibility": {
            "sha256": cap["sha256"], "engine_version": (cap.get("analysis") or {}).get("engine_version", ENGINE_VERSION),
            "dissector": (cap.get("analysis") or {}).get("tshark_version"), "analysis_job_id": (cap.get("analysis") or {}).get("job_id"),
            "rules": [{"rule_id": r, "version": v} for r, v in rules_used],
            "steps": ["Verify the file digest: sha256sum " + cap["filename"],
                      "Re-run analysis on the same engine version: POST /api/v1/captures/{id}/analyze {\"force\": true}",
                      "Inspect any evidence frame in Wireshark: frame.number == <frame>"],
        },
        "evidence_count": evidence_count,
    }


def render_html(data: dict) -> str:
    return _env.get_template("report.html").render(r=data)


def render_pdf(data: dict, dest: Path) -> None:
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10, textColor=colors.HexColor("#444444"))
    h1, h2, h3 = ss["Heading1"], ss["Heading2"], ss["Heading3"]
    mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=7.5, leading=9)
    P = lambda t, st=body: Paragraph(escape(str(t)), st)  # noqa: E731
    story: list = []
    cap = data["capture"]
    story.append(Paragraph("F5 PacketOps — Forensic Report", h1))
    if data["synthetic_training_data"]:
        story.append(Paragraph("<b>SYNTHETIC TRAINING DATA — not evidence from a real network.</b>",
                               ParagraphStyle("warn", parent=body, textColor=colors.HexColor("#9a3412"))))
    story.append(P(f"Generated {data['generated_at']} by {data['generated_by']}", small))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Executive summary", h2))
    for line in data["executive_summary"]:
        story.append(P(line))
    story.append(Paragraph("Capture", h2))
    rows = [["File", cap["filename"]], ["SHA-256", cap["sha256"]], ["Size", f"{cap['size_bytes']} bytes ({cap['format']})"],
            ["First / last packet", f"{cap['first_packet']} / {cap['last_packet']}"], ["Capture point", cap.get("capture_point") or "-"],
            ["Packets", str((cap.get("stats") or {}).get("packets"))]]
    t = Table([[P(a, small), P(b, mono if a == "SHA-256" else small)] for a, b in rows], colWidths=[35 * mm, 135 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
    story.append(Paragraph("Methodology", h2))
    for m in data["methodology"]:
        story.append(P("• " + m))
    story.append(Paragraph("Limitations", h2))
    for lim in data["limitations"] or ["No capture-level limitations were recorded."]:
        story.append(P("• " + lim))
    story.append(PageBreak())
    story.append(Paragraph("Findings", h2))
    if not data["findings"]:
        story.append(P("No findings."))
    for f in data["findings"]:
        story.append(Paragraph(escape(f"{f['id']} · {f['title']}"), h3))
        story.append(P(f"Severity {f['severity'].upper()} · confidence {f['confidence']['level']} ({f['confidence']['score']}) · "
                       f"rule {f['rule_id']} v{f['rule_version']} · status {f['status']}", small))
        story.append(P(f["summary"]))
        story.append(P("Observed facts:", small))
        for o in f["observations"]:
            frames = ", ".join(f"#{x}" for x in o.get("frames", [])[:12])
            story.append(P(f"• {o['text']}" + (f" [frames {frames}]" if frames else "")))
        story.append(P(f"Interpretation: {f['assessment']}"))
        story.append(P(f"Probable cause (hypothesis): {f['probable_cause']}"))
        if f["alternatives"]:
            story.append(P("Alternative explanations:", small))
            for a in f["alternatives"]:
                story.append(P("– " + a, small))
        if f["evidence"]:
            ev = [["Frame", "Time", "Role"]] + [[str(e["frame"]), e["time"], e.get("role") or ""] for e in f["evidence"][:30]]
            et = Table(ev, colWidths=[18 * mm, 70 * mm, 80 * mm])
            et.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 7), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee"))]))
            story.append(et)
        for v in f["verification"][:6]:
            story.append(P(f"Verify ({v.get('where')}): {v.get('purpose')}", small))
            story.append(Preformatted(v.get("command", ""), mono, maxLineLength=110))
        for r in f["remediation"][:4]:
            story.append(P(f"Remediation: {r.get('action')} — risk: {r.get('risk')}", small))
        if f["missing_evidence"]:
            story.append(P("Missing evidence: " + "; ".join(f["missing_evidence"]), small))
        if f["limitations"]:
            story.append(P("Limitations: " + "; ".join(f["limitations"]), small))
        if f.get("f5_relevance"):
            story.append(P("BIG-IP relevance: " + f["f5_relevance"], small))
        story.append(Spacer(1, 3 * mm))
    if data["f5"]["correlations"] or data["f5"]["trailer_frames"]:
        story.append(Paragraph("BIG-IP analysis", h2))
        story.append(P(f"F5 Ethernet trailer frames: {data['f5']['trailer_frames']}"))
        for c in data["f5"]["correlations"]:
            story.append(P(f"Correlation {c['id']} (metadata: {c.get('config_name') or 'none'}); evidence of BIG-IP: "
                           + ("; ".join(c["bigip_evidence"]) or "none")))
            if c["pairs"]:
                rows = [["Client-side", "Server-side", "Method", "Conf."]] + [
                    [f"{p['client_flow']} {p['client']}→{p['vip']}", f"{p['server_flow']} {p['snat']}→{p['member']}", p["method"], p["confidence"]]
                    for p in c["pairs"][:30]]
                ct = Table([[P(x, small) for x in row] for row in rows], colWidths=[62 * mm, 62 * mm, 26 * mm, 18 * mm])
                ct.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey)]))
                story.append(ct)
            for o in c["observations"]:
                story.append(P("• " + o))
    if data["ai_synthesis"]:
        story.append(Paragraph("AI-assisted synthesis", h2))
        story.append(P(f"Generated by {data['ai_synthesis']['provider']} and validated against the evidence; it interprets the "
                       "deterministic findings above and adds no new facts.", small))
        for para in data["ai_synthesis"]["text"].split("\n"):
            if para.strip():
                story.append(P(para))
    story.append(Paragraph("Reproducibility", h2))
    rep = data["reproducibility"]
    story.append(P(f"Engine {rep['engine_version']}; dissector {rep['dissector']}; job {rep['analysis_job_id']}"))
    story.append(P("Rules: " + ", ".join(f"{r['rule_id']} v{r['version']}" for r in rep["rules"]) if rep["rules"] else "Rules: none fired"))
    for s in rep["steps"]:
        story.append(P("• " + s, small))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.drawString(15 * mm, 10 * mm, f"F5 PacketOps report · {cap['filename']} · sha256 {cap['sha256'][:16]}…"
                          + (" · SYNTHETIC TRAINING DATA" if data["synthetic_training_data"] else ""))
        canvas.drawRightString(195 * mm, 10 * mm, f"page {doc.page}")
        canvas.restoreState()

    SimpleDocTemplate(str(dest), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=18 * mm,
                      title=f"PacketOps report {cap['filename']}", author="F5 PacketOps").build(story, onFirstPage=footer, onLaterPages=footer)


def create_report(principal: Principal, capture_id: str, fmt: str = "html") -> dict:
    principal.require("report:create")
    if fmt not in FORMATS:
        raise ApiError(400, "invalid_format", f"format must be one of {', '.join(FORMATS)}")
    data = build_report_data(principal, capture_id)
    rid = new_id("rep")
    data["report_id"] = rid
    stem = Path(data["capture"]["filename"]).stem[:60] or "capture"
    filename = f"packetops-report-{stem}-{rid[-8:]}.{fmt}"
    work = Path(get_settings().work_dir)
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        path = Path(tmp) / filename
        if fmt == "json":
            path.write_text(json.dumps(data, indent=2, default=str))
        elif fmt == "html":
            path.write_text(render_html(data))
        else:
            render_pdf(data, path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        key = tenant_key(principal.tenant_id, "reports", rid, f"report.{fmt}")
        get_storage().put_file(key, path, FORMATS[fmt].split(";")[0])
        size = path.stat().st_size
    doc = {"_id": rid, "capture_id": capture_id, "format": fmt, "filename": filename, "storage_key": key, "size_bytes": size,
           "sha256": digest, "finding_count": len(data["findings"]), "evidence_count": data["evidence_count"],
           "training": data["synthetic_training_data"], "created_by": principal.user_id, "created_at": utcnow()}
    TenantDB(principal.tenant_id).reports.insert_one(doc)
    audit(principal, "report.create", "report", rid, {"capture_id": capture_id, "format": fmt})
    gamification.on_report_generated(principal.tenant_id, principal.user_id, doc)
    return clean(doc)


def list_reports(principal: Principal, capture_id: str | None = None, limit: int = 50) -> list[dict]:
    principal.require("report:read")
    flt = {"capture_id": capture_id} if capture_id else {}
    return [clean(d) for d in TenantDB(principal.tenant_id).reports.find(flt).sort("created_at", -1).limit(limit)]


def report_file(principal: Principal, report_id: str) -> tuple[Path, str, str]:
    principal.require("report:read")
    doc = TenantDB(principal.tenant_id).reports.find_one({"_id": report_id})
    if not doc:
        raise not_found("Report")
    path = get_storage().materialize(doc["storage_key"], Path(get_settings().cache_dir))
    audit(principal, "report.download", "report", report_id)
    return path, doc["filename"], FORMATS[doc["format"]]
