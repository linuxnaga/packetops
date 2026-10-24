"""AI copilot: synthesis over deterministic findings.

The rules produce the facts (findings with evidence frames, metrics, limits).
The model only connects them: how findings relate, which root-cause hypothesis
fits best, and in what order to verify. Its output is validated before it is
stored or shown:

* every IP address it mentions must appear in the evidence given to it,
* every frame number must be an evidence frame of a cited finding,
* every finding id must exist,
* no shell commands (verification commands come only from the rule library),
* placeholders that cannot be mapped back (invented identifiers) fail validation.

When no provider is configured or validation fails, a deterministic synthesis
built from the same findings is returned and labelled as such.
"""

from __future__ import annotations

import json
import logging
import re

from app.core.config import get_settings
from app.core.errors import ApiError
from app.core.security import Principal
from app.db import TenantDB, clean, new_id, utcnow
from app.services.audit import audit
from app.services.captures import get_capture

from .providers import ProviderUnavailable, get_provider
from .redaction import Redactor, find_ips

log = logging.getLogger(__name__)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MAX_FINDINGS = 25

SCHEMA = {
    "type": "object",
    "properties": {
        "headline": {"type": "string"},
        "narrative": {"type": "string"},
        "hypotheses": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "hypothesis": {"type": "string"},
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                "supporting_findings": {"type": "array", "items": {"type": "string"}},
                "supporting_frames": {"type": "array", "items": {"type": "integer"}},
                "evidence_against": {"type": "string"},
            },
            "required": ["hypothesis", "confidence", "supporting_findings", "supporting_frames", "evidence_against"],
            "additionalProperties": False,
        }},
        "verification_order": {"type": "array", "items": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}, "why_first": {"type": "string"}},
            "required": ["finding_id", "why_first"], "additionalProperties": False,
        }},
        "open_questions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["headline", "narrative", "hypotheses", "verification_order", "open_questions"],
    "additionalProperties": False,
}

SYSTEM = """You assist network engineers investigating packet captures, including traffic through F5 BIG-IP systems.
You receive deterministic findings produced by a rule engine from one capture. Each finding has an id (F1, F2, ...),
observed facts with evidence frame numbers, an interpretation, a probable cause, alternatives and limitations.

Your job is synthesis only:
- Explain how the findings relate to each other and what single story (or competing stories) best explains them.
- Rank root-cause hypotheses, cite the finding ids and evidence frame numbers that support each, and state what argues against it.
- Order the findings for verification (which check would discriminate between hypotheses fastest).
- List open questions that the capture cannot answer.

Rules:
- Use only the facts provided. Do not invent addresses, ports, frames, timings, device names, configuration or log lines.
- Identifiers such as IP_1, HOST_2 or PATH_3 are redacted values; use them exactly as given.
- Cite frames only from the evidence frames listed for a finding.
- Do not write shell, tmsh or tcpdump commands; verification commands are attached to the findings already.
- Do not claim a BIG-IP is in the path unless a finding or the capture facts say so.
- Do not change severities or confidence levels of findings; your hypothesis confidence is separate.
- Be concise and specific. Plain prose, no markdown headings."""


def _ips_in(text: str) -> set[str]:
    return find_ips(text)


def build_context(tdb: TenantDB, cap: dict) -> tuple[str, dict]:
    findings = sorted(tdb.findings.find({"capture_id": cap["_id"]}),
                      key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["seq"]))[:MAX_FINDINGS]
    stats = cap.get("stats") or {}
    lines = [f"Capture: {stats.get('packets', 0)} packets, {stats.get('duration_s', 0)} s, {stats.get('tcp_conversations', 0)} TCP / "
             f"{stats.get('udp_conversations', 0)} UDP conversations; capture point: {cap.get('capture_point') or 'not stated'}."]
    if cap.get("training"):
        lines.append("This is a synthetic training capture.")
    for lim in cap.get("limitations", [])[:8]:
        lines.append(f"Capture limitation: {lim['text']}")
    allowed_frames: dict[str, set[int]] = {}
    for f in findings:
        frames = {p["frame"] for p in f.get("packets", [])} | {fr for o in f.get("observations", []) for fr in o.get("frames", [])}
        allowed_frames[f["short_id"]] = frames
        lines.append("")
        lines.append(f"[{f['short_id']}] {f['title']} (rule {f['rule_id']}, severity {f['severity']}, confidence {f['confidence']['level']}, "
                     f"status {f['status']})")
        lines.append(f"Summary: {f['summary']}")
        for o in f.get("observations", [])[:8]:
            lines.append(f"Fact: {o['text']}")
        lines.append(f"Interpretation: {f['assessment']}")
        lines.append(f"Probable cause (rule engine): {f['probable_cause']}")
        if f.get("alternatives"):
            lines.append("Alternatives: " + " | ".join(f["alternatives"][:5]))
        if f.get("limitations"):
            lines.append("Limitations: " + " | ".join(f["limitations"][:4]))
        if f.get("f5_relevance"):
            lines.append(f"BIG-IP relevance: {f['f5_relevance']}")
        lines.append("Evidence frames: " + (", ".join(str(x) for x in sorted(frames)[:60]) or "none"))
    corr = tdb.correlations.find_one({"$or": [{"client_capture_id": cap["_id"]}, {"server_capture_id": cap["_id"]}]},
                                     sort=[("created_at", -1)])
    if corr:
        lines.append("")
        lines.append(f"BIG-IP correlation: {len(corr.get('pairs', []))} client/server pairs ({', '.join(corr.get('methods', []))}); "
                     f"evidence of BIG-IP: {'; '.join(corr.get('bigip_evidence', [])) or 'none'}.")
        for o in corr.get("observations", [])[:8]:
            lines.append(f"Correlation fact: {o['text']}")
    text = "\n".join(lines)
    allowed = {"ips": _ips_in(text), "frames": allowed_frames, "findings": {f["short_id"] for f in findings}}
    return text, {"allowed": allowed, "findings": findings}


SHELL_HINT = re.compile(r"(`[^`]+`|\b(?:tmsh|tcpdump|sudo|curl|openssl|ssh|bash)\s+-?\w)")


def validate(result: dict, allowed: dict) -> list[str]:
    problems: list[str] = []
    blob = json.dumps(result)
    for ip in _ips_in(blob) - allowed["ips"]:
        problems.append(f"mentions address {ip}, which is not in the evidence")
    known_frames = set().union(*allowed["frames"].values()) if allowed["frames"] else set()
    for h in result.get("hypotheses", []):
        for fid in h.get("supporting_findings", []):
            if fid not in allowed["findings"]:
                problems.append(f"cites unknown finding {fid}")
        cited = set().union(*(allowed["frames"].get(fid, set()) for fid in h.get("supporting_findings", []))) or known_frames
        for fr in h.get("supporting_frames", []):
            if fr not in cited:
                problems.append(f"cites frame #{fr}, which is not evidence of the cited findings")
    for v in result.get("verification_order", []):
        if v.get("finding_id") not in allowed["findings"]:
            problems.append(f"verification order names unknown finding {v.get('finding_id')}")
    for m in re.finditer(r"#(\d{1,9})\b", blob):
        if int(m.group(1)) not in known_frames:
            problems.append(f"mentions frame #{m.group(1)}, which is not an evidence frame")
    for m in re.finditer(r"\bF(\d{1,6})\b", blob):
        if f"F{m.group(1)}" not in allowed["findings"]:
            problems.append(f"mentions unknown finding F{m.group(1)}")
    if SHELL_HINT.search(blob):
        problems.append("contains shell or device commands")
    return sorted(set(problems))


def deterministic_synthesis(findings: list[dict]) -> dict:
    """A rule-based synthesis used when no model is configured or the model's output failed validation."""
    if not findings:
        return {"headline": "No findings to synthesise.", "narrative": "The rule engine produced no findings for this capture.",
                "hypotheses": [], "verification_order": [], "open_questions": []}
    top = findings[0]
    hyps = []
    for f in findings[:3]:
        hyps.append({"hypothesis": f["probable_cause"], "confidence": f["confidence"]["level"],
                     "supporting_findings": [f["short_id"]], "supporting_frames": [p["frame"] for p in f.get("packets", [])][:8],
                     "evidence_against": "; ".join(f.get("alternatives", [])[:2])})
    cats = sorted({f["category"] for f in findings})
    return {
        "headline": f"{len(findings)} finding(s) across {', '.join(cats)}; most severe: {top['title']}.",
        "narrative": " ".join(f"[{f['short_id']}] {f['summary']}" for f in findings[:5]),
        "hypotheses": hyps,
        "verification_order": [{"finding_id": f["short_id"], "why_first": f"{f['severity']} severity, {f['confidence']['level']} confidence"}
                               for f in findings[:5]],
        "open_questions": sorted({m for f in findings for m in f.get("missing_evidence", [])})[:6],
    }


def render_text(result: dict) -> str:
    parts = [result["headline"], "", result["narrative"]]
    if result.get("hypotheses"):
        parts.append("")
        for i, h in enumerate(result["hypotheses"], 1):
            frames = ", ".join(f"#{x}" for x in h.get("supporting_frames", [])[:10])
            parts.append(f"Hypothesis {i} ({h['confidence']} confidence): {h['hypothesis']} — supported by "
                         f"{', '.join(h.get('supporting_findings', []))}" + (f" (frames {frames})" if frames else "")
                         + (f". Against: {h['evidence_against']}" if h.get("evidence_against") else "."))
    if result.get("verification_order"):
        parts.append("")
        parts.append("Verify in this order: " + "; ".join(f"{v['finding_id']} ({v['why_first']})" for v in result["verification_order"]))
    if result.get("open_questions"):
        parts.append("")
        parts.append("Open questions: " + "; ".join(result["open_questions"]))
    return "\n".join(parts)


def synthesize(principal: Principal, capture_id: str) -> dict:
    principal.require("finding:read")
    cap = get_capture(principal, capture_id)
    if cap["status"] != "analyzed":
        raise ApiError(409, "not_analyzed", "Analyse the capture before asking the copilot")
    tdb = TenantDB(principal.tenant_id)
    context, info = build_context(tdb, cap)
    allowed, findings = info["allowed"], info["findings"]
    provider = get_provider()
    doc = {"_id": new_id("ai"), "capture_id": capture_id, "created_by": principal.user_id, "created_at": utcnow(),
           "provider": "deterministic", "model": None, "redacted": False, "validation": {"passed": True, "problems": []}}
    result = None
    if provider and findings:
        redactor = Redactor() if (provider.external or get_settings().llm_redact_addresses) else None
        prompt = redactor.redact(context) if redactor else context
        try:
            gen = provider.generate(SYSTEM, prompt + "\n\nReturn the synthesis as JSON matching the schema.", SCHEMA)
            raw = gen.text
            unknown: list[str] = []
            if redactor:
                raw, unknown = redactor.restore(raw)
            parsed = json.loads(raw)
            problems = validate(parsed, allowed) + [f"uses identifier {u} that was not in the evidence" for u in unknown]
            doc.update(provider=gen.provider, model=gen.model, redacted=bool(redactor))
            if problems:
                doc["validation"] = {"passed": False, "problems": problems[:20]}
                doc["rejected_output"] = parsed
                log.warning("copilot output failed validation", extra={"capture_id": capture_id, "problems": len(problems)})
            else:
                result = parsed
        except ProviderUnavailable as exc:
            doc["provider_error"] = str(exc)
        except (json.JSONDecodeError, TypeError) as exc:
            doc["validation"] = {"passed": False, "problems": [f"response was not valid JSON ({type(exc).__name__})"]}
    if result is None:
        result = deterministic_synthesis(findings)
        reason = doc.get("provider_error") or ("validation failed" if not doc["validation"]["passed"] else
                                               "no AI provider configured" if not provider else "no findings")
        doc["fallback"] = {"used": True, "reason": reason}
        if doc["provider"] != "deterministic":
            doc["ai_attempt"] = {"provider": doc["provider"], "model": doc["model"], "validation": doc["validation"]}
        doc.update(provider="deterministic", model=None, validation={"passed": True, "problems": [], "deterministic": True})
    doc.update(result=result, synthesis=render_text(result))
    tdb.ai_syntheses.insert_one(doc)
    audit(principal, "copilot.synthesize", "capture", capture_id, {"provider": doc["provider"], "fallback": doc.get("fallback")})
    return clean(doc)
