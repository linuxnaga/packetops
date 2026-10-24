"""Detection rule framework.

A rule is deterministic code that reads the aggregated capture state and
emits ``FindingDraft`` objects. Each rule documents its required evidence,
detection logic, known limitations, false-positive considerations and the
rationale for its severity, so an engineer can audit why a finding exists.

Rules separate *observations* (facts read from packets, each tied to frame
numbers) from the *assessment* (an interpretation the facts support) and
*probable cause* (a hypothesis, always with alternatives and missing evidence).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from .context import RuleContext

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class RuleMeta:
    rule_id: str
    version: str
    title: str
    category: str  # tcp, tls, dns, http, f5, capture
    default_severity: str
    required_evidence: list[str]
    detection_logic: str
    limitations: list[str]
    false_positives: list[str]
    severity_rationale: str
    parameters: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "title": self.title,
            "category": self.category,
            "default_severity": self.default_severity,
            "required_evidence": self.required_evidence,
            "detection_logic": self.detection_logic,
            "limitations": self.limitations,
            "false_positives": self.false_positives,
            "severity_rationale": self.severity_rationale,
            "parameters": self.parameters,
        }


@dataclass
class Confidence:
    level: str  # high, medium, low
    score: float
    rationale: str

    def to_dict(self) -> dict:
        return {"level": self.level, "score": round(self.score, 2), "rationale": self.rationale}


@dataclass
class Observation:
    text: str
    frames: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"text": self.text, "frames": self.frames[:50]}


@dataclass
class FindingDraft:
    rule: RuleMeta
    subject_key: str
    title: str
    severity: str
    confidence: Confidence
    summary: str
    observations: list[Observation]
    assessment: str
    probable_cause: str
    alternatives: list[str]
    verification: list[dict]
    remediation: list[dict]
    missing_evidence: list[str]
    packets: list[dict] = field(default_factory=list)  # {frame, ts_ns, role}
    flows: list[str] = field(default_factory=list)
    tuples: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    f5_relevance: str | None = None

    def to_dict(self) -> dict:
        seen: set[int] = set()
        packets = []
        for p in sorted(self.packets, key=lambda p: p["frame"]):
            if p["frame"] in seen or p["frame"] <= 0:
                continue
            seen.add(p["frame"])
            packets.append(p)
        return {
            "rule_id": self.rule.rule_id,
            "rule_version": self.rule.version,
            "category": self.rule.category,
            "subject_key": self.subject_key,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence.to_dict(),
            "summary": self.summary,
            "observations": [o.to_dict() for o in self.observations],
            "assessment": self.assessment,
            "probable_cause": self.probable_cause,
            "alternatives": self.alternatives,
            "verification": self.verification,
            "remediation": self.remediation,
            "missing_evidence": self.missing_evidence,
            "limitations": list(dict.fromkeys(self.rule.limitations + self.limitations)),
            "packets": packets[:200],
            "flows": list(dict.fromkeys(self.flows))[:100],
            "tuples": self.tuples[:50],
            "timeline": sorted(self.timeline, key=lambda e: (e["ts_ns"], e.get("frame", 0)))[:200],
            "metrics": self.metrics,
            "f5_relevance": self.f5_relevance,
        }


class Rule:
    meta: ClassVar[RuleMeta]

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:  # pragma: no cover - interface
        raise NotImplementedError
