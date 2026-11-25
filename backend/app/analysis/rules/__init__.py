"""Rule registry."""

from __future__ import annotations

import logging

from .base import SEVERITY_RANK, Rule, RuleMeta
from .context import RuleContext
from .dns import DNS_RULES
from .f5obs import F5_OBSERVABLE_RULES
from .http import HTTP_RULES
from .tcp import TCP_RULES
from .tls import TLS_RULES

log = logging.getLogger(__name__)

ALL_RULES: list[type[Rule]] = [*TCP_RULES, *TLS_RULES, *DNS_RULES, *HTTP_RULES, *F5_OBSERVABLE_RULES]
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


def rule_catalog() -> list[RuleMeta]:
    return [r.meta for r in ALL_RULES]


def get_rule(rule_id: str) -> RuleMeta | None:
    return next((r.meta for r in ALL_RULES if r.meta.rule_id == rule_id.upper()), None)


def run_rules(ctx: RuleContext) -> tuple[list[dict], list[dict]]:
    """Evaluate every rule. Returns (findings, rule_errors). A failing rule never aborts the analysis."""
    findings: list[dict] = []
    errors: list[dict] = []
    for rule_cls in ALL_RULES:
        try:
            for draft in rule_cls().evaluate(ctx):
                findings.append(draft.to_dict())
        except Exception as exc:  # noqa: BLE001 - isolate rule failures
            log.exception("rule %s failed", rule_cls.meta.rule_id)
            errors.append({"rule_id": rule_cls.meta.rule_id, "error": type(exc).__name__})
    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], CONFIDENCE_RANK[f["confidence"]["level"]],
                                 f["packets"][0]["frame"] if f["packets"] else 0))
    for i, f in enumerate(findings, start=1):
        f["seq"] = i
        f["short_id"] = f"F{i}"
    return findings, errors
