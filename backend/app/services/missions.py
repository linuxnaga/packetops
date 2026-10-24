"""Training missions on synthetic captures.

Missions run on clearly labelled synthetic captures (``training=True``) that are
kept apart from production evidence. Objective answers are checked against the
platform's own analysis of the mission capture (findings, metrics, correlation
results), so a mission can only be completed by reading the real evidence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path

from app.core.config import get_settings
from app.core.errors import ApiError, not_found
from app.core.security import Principal
from app.db import TenantDB, clean, new_id, utcnow
from app.services import gamification
from app.services.audit import audit
from app.services.captures import get_capture, ingest_capture, iter_file, start_analysis

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "training"


def _o(prompt: str, check: dict, hint: str, explanation: str = "") -> dict:
    return {"prompt": prompt, "check": check, "hint": hint, "explanation": explanation}


MISSIONS: dict[str, dict] = {
    "tcp-handshake": {
        "title": "TCP handshake failure", "difficulty": "beginner", "xp": 100, "files": ["tcp-handshake.pcapng"],
        "briefing": "Users report that app.example.com times out while www.example.com works. Find out which connection "
                    "attempts fail and how.",
        "objectives": [
            _o("Which destination (ip:port) never answered the client's SYNs?", {"type": "finding_subject", "rule": "TCP-001"},
               "Run 'tcp handshakes' and look for attempts with no SYN-ACK."),
            _o("How many SYN segments did the client send to that destination in total?",
               {"type": "finding_metric", "rule": "TCP-001", "metric": "syn_segments"}, "Count the original SYN plus its retransmissions."),
            _o("Which frame number contains the RST that refused the connection to port 8443?",
               {"type": "finding_frame", "rule": "TCP-002", "role": "RST"}, "'evidence show' on the TCP-002 finding lists the RST."),
        ],
    },
    "retransmission": {
        "title": "Retransmission and suspected packet loss", "difficulty": "beginner", "xp": 100, "files": ["retransmission.pcapng"],
        "briefing": "A download from 192.0.2.20 is slower than expected. Examine the retransmissions without over-claiming.",
        "objectives": [
            _o("Which frame is the fast retransmission?", {"type": "finding_frame", "rule": "TCP-004", "role": "fast retransmission"},
               "Fast retransmissions follow three or more duplicate ACKs; try 'tcp retransmissions'."),
            _o("How many duplicate ACKs did the client send?", {"type": "finding_metric", "rule": "TCP-004", "metric": "dup_acks"},
               "'finding inspect' on the duplicate-ACK finding shows the count."),
            _o("Does this capture alone prove where the packet was lost? (yes/no)", {"type": "concept", "answer": "no"},
               "Read the TCP-003 rule limitations.",
               "Retransmissions prove the sender lacked an acknowledgement; locating the loss needs a second capture point."),
        ],
    },
    "tls-failure": {
        "title": "TLS negotiation failure", "difficulty": "intermediate", "xp": 150, "files": ["tls-failure.pcapng"],
        "briefing": "portal.example.com fails for some clients. Two different TLS failures are in this capture.",
        "objectives": [
            _o("Which side sent the certificate_expired alert? (client/server)",
               {"type": "finding_metric", "rule": "TLS-001", "metric": "sender", "where": {"alert": "certificate_expired"}},
               "'tls inspect' shows alerts and who sent them."),
            _o("On what date (YYYY-MM-DD) did the server certificate expire?",
               {"type": "finding_metric", "rule": "TLS-005", "metric": "not_after", "transform": "date"},
               "The certificate is visible in cleartext in TLS 1.2; check the TLS-005 finding."),
            _o("Which protocol version did the refused client offer? (e.g. TLS 1.0)",
               {"type": "finding_metric", "rule": "TLS-004", "metric": "versions", "transform": "tls_version"},
               "Look at the ClientHello of the connection that received handshake_failure."),
        ],
    },
    "dns-timeout": {
        "title": "DNS timeout", "difficulty": "beginner", "xp": 100, "files": ["dns-timeout.pcapng"],
        "briefing": "An application cannot reach its API. The client's resolver behaviour is captured here.",
        "objectives": [
            _o("Which name was never resolved?", {"type": "finding_subject_part", "rule": "DNS-001", "part": 1}, "Run 'dns inspect'."),
            _o("How many queries were sent for that name?", {"type": "finding_metric", "rule": "DNS-001", "metric": "queries"},
               "Count the retries in the DNS-001 finding."),
            _o("Which response code did billing.example.com receive?", {"type": "finding_metric", "rule": "DNS-002", "metric": "rcode"},
               "The DNS-002 finding names the RCODE."),
        ],
    },
    "http-latency": {
        "title": "HTTP latency", "difficulty": "beginner", "xp": 100, "files": ["http-latency.pcapng"],
        "briefing": "shop.example.com feels slow and sometimes fails.",
        "objectives": [
            _o("Which request path was slowest?", {"type": "finding_metric", "rule": "HTTP-002", "metric": "worst_path", "transform": "path"},
               "'http inspect' lists TTFB and total time."),
            _o("Was most of the delay before the first response byte (server stall)? (yes/no)",
               {"type": "finding_metric", "rule": "HTTP-002", "metric": "server_stall", "transform": "bool"},
               "Compare TTFB with total time for the slow request."),
            _o("Which HTTP status code indicates the server-side error?", {"type": "finding_metric", "rule": "HTTP-001", "metric": "codes"},
               "Look for 5xx responses."),
        ],
    },
    "connection-reset": {
        "title": "Unexpected connection reset", "difficulty": "intermediate", "xp": 120, "files": ["connection-reset.pcapng"],
        "briefing": "The legacy login page fails immediately while the home page works.",
        "objectives": [
            _o("Which endpoint (ip:port) sent the reset?", {"type": "reset_sender", "rule": "TCP-006"}, "Run 'tcp resets'."),
            _o("Which frame number is the reset?", {"type": "finding_frame", "rule": "TCP-006", "role": "RST"}, "'evidence show' on the finding."),
            _o("How many HTTP requests were still waiting for a response when it was reset?",
               {"type": "finding_metric", "rule": "TCP-006", "metric": "pending_http_requests"}, "See the finding observations."),
        ],
    },
    "snat-correlation": {
        "title": "BIG-IP SNAT correlation", "difficulty": "advanced", "xp": 200,
        "files": ["snat-correlation-client.pcapng", "snat-correlation-server.pcapng"], "config": "bigip-config.json",
        "briefing": "You have a client-side capture in front of the VIP and a server-side capture on the internal VLAN, plus "
                    "sanitized BIG-IP metadata. Match the legs of each connection.",
        "objectives": [
            _o("Run 'f5 correlate --with <server capture>'. Which SNAT address did the BIG-IP use?",
               {"type": "correlation", "field": "snat"}, "The server-side capture id is shown when the mission starts."),
            _o("Which pool member (ip:port) served the client connection from port 50002?",
               {"type": "correlation", "field": "member_for_client_port", "client_port": 50002}, "Read the matched pairs table."),
            _o("How many client-side/server-side pairs were matched?", {"type": "correlation", "field": "pair_count"},
               "Shown in the correlation summary."),
        ],
    },
    "asymmetric-routing": {
        "title": "Asymmetric routing investigation", "difficulty": "intermediate", "xp": 120, "files": ["asymmetric-routing.pcapng"],
        "briefing": "A capture taken on one routing path shows a strange TLS session.",
        "objectives": [
            _o("How many bytes did the client acknowledge that never appeared in this capture?",
               {"type": "finding_metric", "rule": "TCP-009", "metric": "unseen_bytes_acked"}, "Check the TCP-009 finding."),
            _o("What is the best-supported explanation? (a) server down (b) return traffic takes another path (c) TLS failure",
               {"type": "choice_by_rule", "options": {"a": "TCP-001", "b": "TCP-009", "c": "TLS-001"}},
               "Which rule actually fired on this capture?"),
        ],
    },
    "capture-comparison": {
        "title": "Client-side/server-side capture comparison", "difficulty": "advanced", "xp": 200,
        "files": ["capture-comparison-client.pcapng", "capture-comparison-server.pcapng"], "config": "bigip-config.json",
        "briefing": "The client sees /api/checkout reset by the VIP. Use both captures to decide where the failure started.",
        "objectives": [
            _o("Which side reset first? (client/server)", {"type": "correlation", "field": "first_reset_side"},
               "Correlate the captures, then compare the RST timestamps of each pair."),
            _o("Which pool member (ip:port) reset its connection?", {"type": "correlation", "field": "reset_member"},
               "Look for the server-side flow that ended with a RST from the member."),
            _o("Which request path was in flight when the client was reset?",
               {"type": "finding_metric", "rule": "TCP-006", "metric": "pending_request_path", "transform": "path"},
               "Inspect the reset finding on the client-side capture."),
        ],
    },
    "pool-member": {
        "title": "Pool-member connectivity investigation", "difficulty": "advanced", "xp": 200, "files": ["pool-member.pcapng"],
        "config": "bigip-config.json",
        "briefing": "This capture was taken on the BIG-IP with 'tcpdump -i 0.0:nnnp', so every packet carries an F5 Ethernet "
                    "trailer. Some requests to vs_app_http fail.",
        "objectives": [
            _o("Which pool member (ip:port) never answered the BIG-IP's SYNs?", {"type": "finding_subject", "rule": "TCP-001"},
               "Server-side SYNs come from the SNAT address."),
            _o("Which pool member (ip:port) refused the connection?", {"type": "finding_subject", "rule": "TCP-002"},
               "Look for a RST in reply to a SYN."),
            _o("What reset cause did the BIG-IP record for the timed-out connection? (a) No pool member available "
               "(b) Server-side connection timed out (c) Connection idle timeout",
               {"type": "choice_by_subject", "rule": "F5-001", "options": {"a": "No pool member available",
                                                                            "b": "Server-side connection timed out",
                                                                            "c": "Connection idle timeout"}},
               "Run 'tcp resets' — the BIG-IP cause column comes from the F5 trailer."),
            _o("Run 'f5 correlate'. How many client/server flow pairs are linked by F5 trailer flow IDs?",
               {"type": "correlation", "field": "pair_count"}, "F5 trailers carry flow and peer IDs."),
        ],
    },
}


def _fixture(name: str) -> Path:
    path = FIXTURES_DIR / name
    if path.exists():
        return path
    cache = Path(get_settings().cache_dir) / "training-fixtures"
    if not (cache / name).exists():
        from app.training.generator import build_all

        build_all(cache)
    return cache / name


def list_missions(principal: Principal) -> list[dict]:
    prog = TenantDB(principal.tenant_id).user_progress.find_one({"user_id": principal.user_id}) or {}
    done = prog.get("missions", {})
    out = []
    for mid, m in MISSIONS.items():
        out.append({"id": mid, "title": m["title"], "difficulty": m["difficulty"], "xp": m["xp"], "briefing": m["briefing"],
                    "objectives": len(m["objectives"]), "synthetic": True, "status": done.get(mid, {}).get("status", "not started"),
                    "paired_captures": len(m["files"]) > 1, "uses_bigip_metadata": bool(m.get("config"))})
    return out


def _training_capture(principal: Principal, mission_id: str, filename: str, config_id: str | None, point: str | None) -> dict:
    path = _fixture(filename)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    tdb = TenantDB(principal.tenant_id)
    existing = tdb.captures.find_one({"sha256": sha, "training": True, "mission_id": mission_id, "deleted_at": None,
                                      "status": {"$in": ["analyzed", "queued", "analyzing"]}})
    if existing:
        return existing
    cap = ingest_capture(principal, iter_file(path), filename, training=True, mission_id=mission_id, f5_config_id=config_id,
                         description=f"SYNTHETIC training capture for mission {mission_id}", capture_point=point)
    start_analysis(principal, cap["id"])
    return get_capture(principal, cap["id"])


def _training_config(principal: Principal, filename: str) -> str:
    from app.services.f5 import import_config

    data = json.loads(_fixture(filename).read_text())
    doc = import_config(principal, data, name=f"training: {data['name']}", source="training-fixture", training=True, upsert=True)
    return doc["id"]


def start_mission(principal: Principal, mission_id: str) -> dict:
    principal.require("mission:play")
    m = MISSIONS.get(mission_id)
    if not m:
        raise not_found("Mission")
    config_id = _training_config(principal, m["config"]) if m.get("config") else None
    caps = []
    for i, f in enumerate(m["files"]):
        point = None if len(m["files"]) == 1 else ("client-side" if i == 0 else "server-side")
        caps.append(_training_capture(principal, mission_id, f, config_id, point))
    tdb = TenantDB(principal.tenant_id)
    tdb.mission_runs.update_many({"user_id": principal.user_id, "status": "active"}, {"$set": {"status": "abandoned"}})
    run = {
        "_id": new_id("run"), "user_id": principal.user_id, "mission_id": mission_id, "title": m["title"], "status": "active",
        "capture_id": caps[0]["_id"], "secondary_capture_id": caps[1]["_id"] if len(caps) > 1 else None, "config_id": config_id,
        "objectives": [{"index": i + 1, "prompt": o["prompt"], "completed": False, "attempts": 0} for i, o in enumerate(m["objectives"])],
        "started_at": utcnow(), "synthetic": True,
    }
    tdb.mission_runs.insert_one(run)
    gamification._progress(tdb, principal.user_id)
    tdb.user_progress.update_one({"user_id": principal.user_id},
                                 {"$set": {f"missions.{mission_id}.status": "in progress", f"missions.{mission_id}.last_started": utcnow()}},
                                 upsert=False)
    audit(principal, "mission.start", "mission", mission_id, {"run_id": run["_id"]})
    briefing = m["briefing"]
    if run["secondary_capture_id"]:
        briefing += f" Client-side capture: {run['capture_id']} (selected). Server-side capture: {run['secondary_capture_id']}."
    if config_id:
        briefing += f" BIG-IP metadata: {config_id}."
    return {**clean(run), "briefing": briefing, "status_of_captures": [c["status"] for c in caps]}


def active_run(principal: Principal) -> dict | None:
    run = TenantDB(principal.tenant_id).mission_runs.find_one({"user_id": principal.user_id, "status": "active"}, sort=[("started_at", -1)])
    return clean(run) if run else None


# ------------------------------------------------------------------ checking
def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s).strip().lower())


def _norm_endpoint(s: str) -> str:
    s = _norm(s).replace(" ", "")
    m = re.match(r"^\[?([0-9a-f:.]+?)\]?[:.](\d+)$", s)
    if m:
        try:
            return f"{ipaddress.ip_address(m.group(1))}:{int(m.group(2))}"
        except ValueError:
            return s
    return s


def _tls_norm(s: str) -> str:
    s = _norm(s).replace("tlsv", "tls ").replace("tls", "tls ").replace("  ", " ").strip()
    if re.fullmatch(r"\d\.\d", s):
        s = "tls " + s
    return s.replace("ssl v", "ssl ").strip()


def _findings(tdb: TenantDB, capture_ids: list[str], rule: str) -> list[dict]:
    return list(tdb.findings.find({"capture_id": {"$in": capture_ids}, "rule_id": rule}))


def _latest_correlation(tdb: TenantDB, run: dict) -> dict | None:
    ids = [run["capture_id"]] + ([run["secondary_capture_id"]] if run.get("secondary_capture_id") else [])
    return tdb.correlations.find_one({"client_capture_id": {"$in": ids}, "created_by": run["user_id"]}, sort=[("created_at", -1)])


def _check(tdb: TenantDB, run: dict, check: dict, answer: str) -> tuple[bool, str | None]:
    caps = [run["capture_id"]] + ([run["secondary_capture_id"]] if run.get("secondary_capture_id") else [])
    ctype = check["type"]
    if ctype == "concept":
        return _norm(answer) == check["answer"], None
    if ctype == "correlation":
        corr = _latest_correlation(tdb, run)
        if not corr:
            return False, "Run 'f5 correlate' first (use --with <server capture> for paired captures)."
        pairs = corr.get("pairs", [])
        field = check["field"]
        if field == "snat":
            return _norm(answer) in {_norm(p["snat"].rsplit(":", 1)[0]) for p in pairs}, None
        if field == "pair_count":
            return answer.strip().isdigit() and int(answer) == len(pairs), None
        if field == "member_for_client_port":
            want = {_norm_endpoint(p["member"]) for p in pairs if p["client"].endswith(f":{check['client_port']}")}
            return _norm_endpoint(answer) in want, None
        if field == "first_reset_side":
            sides = {p.get("first_reset_side") for p in pairs if p.get("first_reset_side")}
            return _norm(answer) in sides, None
        if field == "reset_member":
            want = {_norm_endpoint(p["member"]) for p in pairs if p.get("first_reset_side") == "server"}
            return _norm_endpoint(answer) in want, None
        return False, None
    findings = _findings(tdb, caps, check["rule"]) if "rule" in check else []
    if ctype == "choice_by_rule":
        present = {f["rule_id"] for f in tdb.findings.find({"capture_id": {"$in": caps}}, {"rule_id": 1})}
        choice = _norm(answer).strip("()")[:1]
        return check["options"].get(choice) in present, None
    if not findings:
        return False, "The analysis has no finding of the kind this objective is about yet; is the capture analysed?"
    if ctype == "choice_by_subject":
        choice = _norm(answer).strip("()")[:1]
        text = check["options"].get(choice, "")
        return bool(text) and any(text.lower() in f["subject_key"].lower() for f in findings), None
    if ctype == "finding_subject":
        return _norm_endpoint(answer) in {_norm_endpoint(f["subject_key"]) for f in findings}, None
    if ctype == "finding_subject_part":
        return _norm(answer).rstrip(".") in {_norm(f["subject_key"].split(":")[check["part"]]) for f in findings}, None
    if ctype == "finding_frame":
        frames = {p["frame"] for f in findings for p in f.get("packets", []) if check["role"].lower() in (p.get("role") or "").lower()}
        a = answer.strip().lstrip("#")
        return a.isdigit() and int(a) in frames, None
    if ctype == "reset_sender":
        want = set()
        for f in findings:
            t = f["tuples"][0]
            want.add(_norm_endpoint(f"{t['dst']}:{t['dport']}" if f["metrics"].get("reset_by") == "server" else f"{t['src']}:{t['sport']}"))
        return _norm_endpoint(answer) in want, None
    if ctype == "finding_metric":
        values = []
        for f in findings:
            metrics = f.get("metrics", {})
            if all(str(metrics.get(k)) == v for k, v in (check.get("where") or {}).items()):
                values.append(metrics.get(check["metric"]))
        tr = check.get("transform")
        for v in values:
            if v is None:
                continue
            if isinstance(v, list):
                candidates = [str(x) for x in v]
            else:
                candidates = [str(v)]
            for c in candidates:
                if tr == "date" and _norm(answer) == c[:10]:
                    return True, None
                if tr == "tls_version" and _tls_norm(answer) == _tls_norm(c):
                    return True, None
                if tr == "path" and _norm(answer).split("?")[0] == _norm(c).split("?")[0]:
                    return True, None
                if tr == "bool" and _norm(answer) in (("yes", "true", "y") if c == "True" else ("no", "false", "n")):
                    return True, None
                if tr is None and _norm(answer) == _norm(c):
                    return True, None
        return False, None
    return False, None


def submit_answer(principal: Principal, objective: int, answer: str) -> dict:
    principal.require("mission:play")
    tdb = TenantDB(principal.tenant_id)
    run = tdb.mission_runs.find_one({"user_id": principal.user_id, "status": "active"}, sort=[("started_at", -1)])
    if not run:
        raise ApiError(409, "no_active_mission", "No active mission; start one with 'mission start <id>'")
    m = MISSIONS[run["mission_id"]]
    if objective < 1 or objective > len(m["objectives"]):
        raise ApiError(400, "invalid_objective", f"Objective must be 1-{len(m['objectives'])}")
    obj_def = m["objectives"][objective - 1]
    state = run["objectives"][objective - 1]
    for cid in [run["capture_id"], run.get("secondary_capture_id")]:
        if cid:
            cap = tdb.captures.find_one({"_id": cid}, {"status": 1})
            if cap and cap["status"] != "analyzed":
                raise ApiError(409, "not_analyzed", f"Mission capture {cid} is still '{cap['status']}'")
    if state.get("completed"):
        return {"correct": True, "already_completed": True, "mission_completed": run["status"] == "completed"}
    correct, reason = _check(tdb, run, obj_def["check"], answer[:200])
    tdb.mission_runs.update_one({"_id": run["_id"]}, {"$inc": {f"objectives.{objective - 1}.attempts": 1},
                                                      **({"$set": {f"objectives.{objective - 1}.completed": True,
                                                                   f"objectives.{objective - 1}.completed_at": utcnow()}} if correct else {})})
    result: dict = {"correct": correct, "objective": objective}
    if correct:
        result["explanation"] = obj_def.get("explanation") or None
        gamification.award(principal.tenant_id, principal.user_id, "objective_completed", f"{run['mission_id']}:{objective}",
                           mode="training")
        run = tdb.mission_runs.find_one({"_id": run["_id"]})
        if all(o.get("completed") for o in run["objectives"]):
            tdb.mission_runs.update_one({"_id": run["_id"]}, {"$set": {"status": "completed", "completed_at": utcnow()}})
            tdb.user_progress.update_one({"user_id": principal.user_id},
                                         {"$set": {f"missions.{run['mission_id']}.status": "completed",
                                                   f"missions.{run['mission_id']}.completed_at": utcnow()}})
            before = {a["id"] for a in (tdb.user_progress.find_one({"user_id": principal.user_id}) or {}).get("achievements", [])}
            entry = gamification.on_mission_completed(principal.tenant_id, principal.user_id, {"id": run["mission_id"], "xp": m["xp"]})
            after = (tdb.user_progress.find_one({"user_id": principal.user_id}) or {}).get("achievements", [])
            result.update(mission_completed=True, xp_awarded=entry["xp"] if entry else 0,
                          achievements=[a["name"] for a in after if a["id"] not in before])
            audit(principal, "mission.complete", "mission", run["mission_id"], {"run_id": run["_id"]})
    else:
        result["hint"] = reason or obj_def["hint"]
    return result
