"""Golden tests: every synthetic scenario must produce exactly the evidence-backed results it was built to show."""

import json

import pytest

from app.db import TenantDB

from .conftest import FIXTURES

pytestmark = pytest.mark.integration
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text())


def _findings(principals, cap):
    return list(TenantDB(principals["acme:analyst"].tenant_id).findings.find({"capture_id": cap["_id"]}))


@pytest.mark.parametrize("scenario", [k for k, v in MANIFEST.items() if "rules_present" in v["expected"] or "rules_absent" in v["expected"]])
def test_expected_rules(scenario, analyzed, principals):
    exp = MANIFEST[scenario]["expected"]
    cap = analyzed[MANIFEST[scenario]["files"][0]]
    assert cap["status"] == "analyzed"
    rules = {f["rule_id"] for f in _findings(principals, cap)}
    for r in exp.get("rules_present", []):
        assert r in rules, f"{scenario}: expected {r}, got {sorted(rules)}"
    for r in exp.get("rules_absent", []):
        assert r not in rules, f"{scenario}: {r} must not fire on healthy traffic"


def test_baseline_has_no_high_findings(analyzed, principals):
    fs = _findings(principals, analyzed["baseline.pcapng"])
    assert not [f for f in fs if f["severity"] in ("critical", "high")]


def test_every_finding_is_evidence_backed(analyzed, principals):
    for name, cap in analyzed.items():
        for f in _findings(principals, cap):
            assert f["packets"], f"{name} {f['rule_id']} has no evidence frames"
            assert all(1 <= p["frame"] <= cap["stats"]["packets"] for p in f["packets"])
            for key in ("summary", "observations", "assessment", "probable_cause", "alternatives", "verification",
                        "remediation", "limitations", "confidence"):
                assert f.get(key), f"{name} {f['rule_id']} lacks {key}"
            assert "missing_evidence" in f


def test_specific_facts(analyzed, principals):
    hs = {f["rule_id"]: f for f in _findings(principals, analyzed["tcp-handshake.pcapng"])}
    assert hs["TCP-001"]["subject_key"] == "192.0.2.10:443"
    assert hs["TCP-001"]["metrics"]["syn_segments"] == MANIFEST["tcp-handshake"]["expected"]["unanswered_syn"]["syn_count"]
    dns = [f for f in _findings(principals, analyzed["dns-timeout.pcapng"]) if f["rule_id"] == "DNS-001"][0]
    assert dns["subject_key"].endswith(":api.example.com") and dns["metrics"]["queries"] == 4
    http = [f for f in _findings(principals, analyzed["http-latency.pcapng"]) if f["rule_id"] == "HTTP-002"][0]
    assert http["metrics"]["worst_path"].startswith("/api/orders")
    rst = [f for f in _findings(principals, analyzed["connection-reset.pcapng"]) if f["rule_id"] == "TCP-006"][0]
    t = rst["tuples"][0]
    assert f"{t['dst']}:{t['dport']}" == "192.0.2.50:8080" and rst["metrics"]["reset_by"] == "server"


def test_f5_trailer_reset_causes(analyzed, principals):
    causes = {f["subject_key"] for f in _findings(principals, analyzed["pool-member.pcapng"]) if f["rule_id"] == "F5-001"}
    assert "Server-side connection timed out" in causes
    assert any("refused" in c for c in causes)


def test_flows_and_packets_queryable(analyzed, principals):
    from app.services.flows import list_flows
    from app.services.packets import query_packets

    p = principals["acme:analyst"]
    cap = analyzed["baseline.pcapng"]
    flows, total = list_flows(p, cap["_id"])
    assert total == len(flows) >= 2
    res = query_packets(p, cap["_id"], display_filter="dns")
    assert res["items"] and all("dns" in (r.get("protocol") or "").lower() for r in res["items"])
