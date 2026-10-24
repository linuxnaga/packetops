"""BIG-IP correlation, configuration import, reports, AI copilot validation and a full training mission."""

import json

import pytest

from app.ai.copilot import validate
from app.ai.redaction import Redactor, find_ips
from app.services.f5 import parse_tmsh

from .conftest import FIXTURES

TMSH = """
ltm virtual /Common/vs_web {
    destination /Common/10.0.0.100:443
    ip-protocol tcp
    pool /Common/pool_web
    profiles { /Common/tcp { } /Common/http { } }
    source-address-translation { pool /Common/snat_web type snat }
    persist { /Common/cookie { default yes } }
    rules { /Common/irule_redirect }
}
ltm pool /Common/pool_web {
    members { /Common/10.2.2.20:8443 { address 10.2.2.20 } /Common/10.2.2.21:8443 { address 10.2.2.21 } }
    monitor /Common/https
}
ltm snatpool /Common/snat_web { members { /Common/10.2.2.5 } }
net self /Common/self_int { address 10.2.2.4/24 vlan /Common/internal }
"""


def test_parse_tmsh():
    data = parse_tmsh(TMSH)
    vs = data["virtual_servers"][0]
    assert vs["destination"].endswith("10.0.0.100:443") and vs["pool"] == "/Common/pool_web"
    assert vs["source_address_translation"] == {"type": "snat", "pool": "/Common/snat_web"}
    assert vs["persistence"] == "/Common/cookie" and vs["irules"] == ["/Common/irule_redirect"]
    assert [m["address"] for m in data["pools"][0]["members"]] == ["10.2.2.20", "10.2.2.21"]
    assert data["snat_pools"][0]["members"] == ["10.2.2.5"]
    assert data["self_ips"][0] == {"name": "/Common/self_int", "address": "10.2.2.4", "vlan": "/Common/internal", "floating": False}


def test_redaction_roundtrip():
    r = Redactor()
    text = "10.1.1.10:52002 → 10.0.0.100:80 GET /cart vs /Common/vs_app port 2001:db8::5 host app.example.com"
    red = r.redact(text)
    assert not find_ips(red) and "app.example.com" not in red and "/Common/vs_app" in red
    back, unknown = r.restore(red + " IP_99")
    assert back.startswith("10.1.1.10:52002") and unknown == ["IP_99"]


def test_validator_rejects_invented_evidence():
    allowed = {"ips": {"10.0.0.1"}, "frames": {"F1": {3, 4}}, "findings": {"F1"}}
    good = {"headline": "10.0.0.1 resets", "narrative": "See F1 frame #3", "hypotheses": [
        {"hypothesis": "x", "confidence": "high", "supporting_findings": ["F1"], "supporting_frames": [3], "evidence_against": ""}],
        "verification_order": [{"finding_id": "F1", "why_first": "y"}], "open_questions": []}
    assert validate(good, allowed) == []
    bad = json.loads(json.dumps(good))
    bad["narrative"] = "10.9.9.9 at #77 per F4; run `tmsh show sys connection`"
    bad["hypotheses"][0]["supporting_frames"] = [99]
    problems = " ".join(validate(bad, allowed))
    for needle in ("10.9.9.9", "#77", "F4", "#99", "commands"):
        assert needle in problems


@pytest.mark.integration
def test_snat_correlation_and_mission(principals):
    from app.console.engine import execute
    from app.services.missions import active_run

    p = principals["acme:investigator"]
    out = execute(p, "mission start snat-correlation")
    assert not out.get("error"), out
    run = active_run(p)
    corr = execute(p, f"f5 correlate --with {run['secondary_capture_id']}")
    assert not corr.get("error"), corr
    for i, ans in enumerate(["10.2.2.5", "10.2.2.21:8443", "3"], 1):
        res = execute(p, f"mission submit {i} {ans}")
        assert "verified" in res["blocks"][0]["text"], res
    assert any("MISSION COMPLETE" in b.get("text", "") for b in res["blocks"])
    after = execute(p, "mission submit 1 10.9.9.9")  # the run is finished; nothing active to answer
    assert after.get("error") and "No active mission" in after["blocks"][0]["text"]


@pytest.mark.integration
def test_trailer_correlation_and_capture_comparison(principals, analyzed):
    from app.services.f5 import correlate, import_config

    p = principals["acme:analyst"]
    cfg = import_config(p, json.loads((FIXTURES / "bigip-config.json").read_text()), name="test-bigip", upsert=True)
    res = correlate(p, analyzed["pool-member.pcapng"]["_id"], config_id=cfg["id"])
    assert len(res["pairs"]) == 3 and {x["method"] for x in res["pairs"]} == {"f5-trailer"}
    members = {x["member"]: x for x in res["pairs"]}
    assert members["10.2.2.22:8080"]["first_reset_side"] == "server"
    comp = correlate(p, analyzed["capture-comparison-client.pcapng"]["_id"], analyzed["capture-comparison-server.pcapng"]["_id"], cfg["id"])
    failing = [x for x in comp["pairs"] if x["first_reset_side"] == "server"]
    assert len(comp["pairs"]) == 2 and failing[0]["member"] == "10.2.2.21:8080"


@pytest.mark.integration
def test_no_bigip_assumed_without_evidence(principals, analyzed):
    from app.services.f5 import correlate

    p = principals["acme:analyst"]
    res = correlate(p, analyzed["baseline.pcapng"]["_id"])
    assert res["bigip_evidence"] == [] and res["pairs"] == []
    assert "Nothing in these captures proves a BIG-IP" in res["limitations"][0]


@pytest.mark.integration
@pytest.mark.parametrize("fmt", ["html", "pdf", "json"])
def test_reports(principals, analyzed, fmt):
    from app.services.reports import create_report, report_file

    p = principals["acme:analyst"]
    rep = create_report(p, analyzed["tls-failure.pcapng"]["_id"], fmt)
    path, name, media = report_file(p, rep["id"])
    data = path.read_bytes()
    assert rep["finding_count"] >= 3 and rep["evidence_count"] > 0
    if fmt == "pdf":
        assert data.startswith(b"%PDF")
    elif fmt == "json":
        doc = json.loads(data)
        assert doc["capture"]["sha256"] == analyzed["tls-failure.pcapng"]["sha256"] and doc["synthetic_training_data"] is True
    else:
        assert b"SYNTHETIC TRAINING DATA" in data and b"<script" not in data


@pytest.mark.integration
def test_html_report_escapes_untrusted_text(principals):
    from app.db import TenantDB
    from app.services.captures import get_capture, ingest_capture, iter_file, start_analysis
    from app.services.reports import create_report, report_file

    p = principals["acme:analyst"]
    cap = ingest_capture(p, iter_file(FIXTURES / "http-latency.pcapng"), "x.pcapng", description="<img src=x onerror=alert(1)>")
    start_analysis(p, cap["id"])
    TenantDB(p.tenant_id).findings.update_one({"capture_id": cap["id"]}, {"$set": {"title": "<script>alert(1)</script>"}})
    path, _, _ = report_file(p, create_report(p, cap["id"], "html")["id"])
    html = path.read_text()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert get_capture(p, cap["id"])["status"] == "analyzed"


@pytest.mark.integration
def test_copilot_deterministic_fallback(principals, analyzed):
    from app.ai.copilot import synthesize

    res = synthesize(principals["acme:analyst"], analyzed["dns-timeout.pcapng"]["_id"])
    assert res["provider"] == "deterministic" and res["fallback"]["reason"] == "no AI provider configured"
    assert "F1" in res["synthesis"]
