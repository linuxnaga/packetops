"""Rules for BIG-IP artefacts that are directly observable in packets.

These rules only fire on evidence that is specific to BIG-IP (F5 Ethernet
trailers, BIG-IP persistence cookies). They never infer a BIG-IP from
addressing alone.
"""

from __future__ import annotations

from collections import defaultdict

from . import commands as C
from .base import Confidence, FindingDraft, Observation, Rule, RuleMeta
from .context import RuleContext, frames_text, tcp_timeline, tuple_of


class BigipResetCause(Rule):
    meta = RuleMeta(
        rule_id="F5-001",
        version="1.0.0",
        title="BIG-IP reset cause recorded in the F5 Ethernet trailer",
        category="f5",
        default_severity="high",
        required_evidence=["Capture taken on BIG-IP with 'tcpdump -i 0.0:nnnp' (F5 Ethernet trailer)",
                           "'tm.rstcause.pkt' enabled so TMM embeds the reset cause"],
        detection_logic="Group RST frames whose F5 trailer carries a reset-cause string by cause text.",
        limitations=["Reset causes are only embedded when the tm.rstcause.pkt database variable is enabled."],
        false_positives=["Expected resets (e.g. 'Connection idle timeout' on long-lived idle sessions)"],
        severity_rationale="High: TMM itself states why it reset connections; non-idle causes usually mean failed requests.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[str, list] = defaultdict(list)
        for fl in ctx.tcp_flows:
            for rc in fl.f5.get("rst_causes", []):
                groups[rc["cause"]].append((fl, rc))
        out = []
        for cause, items in groups.items():
            frames = [rc["frame"] for _, rc in items]
            idle = "idle" in cause.lower()
            vips = sorted({fl.f5.get("vip") for fl, _ in items if fl.f5.get("vip")})
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=cause[:120],
                title=f"BIG-IP reset: {cause[:80]}",
                severity="low" if idle else "high",
                confidence=Confidence("high", 0.95, "The reset cause is written into the packet by the BIG-IP that sent the RST."),
                summary=f"The BIG-IP reset {len(items)} connection(s) with cause '{cause}'" + (f" on {', '.join(vips)}." if vips else "."),
                observations=[Observation(f"RST frames carrying this cause: {frames_text(frames)}.", frames)]
                + ([Observation(f"Virtual server name(s) in the trailer: {', '.join(vips)}.")] if vips else []),
                assessment="TMM generated these resets for the stated reason.",
                probable_cause=cause,
                alternatives=[
                    "The cause string names TMM's immediate reason; the underlying fault (an unreachable pool member, a "
                    "monitor marking members down, an iRule decision) still has to be confirmed on the BIG-IP and the servers.",
                    "If several virtual servers share this capture, the reset may belong to a different application than the "
                    "one under investigation; check the virtual server name in the trailer.",
                ],
                verification=[C.cmd("Look up the reset cause in the LTM log", f"grep -F \"{cause[:60]}\" /var/log/ltm", "BIG-IP (bash)"),
                              C.bigip_pool_members(), C.bigip_connections(items[0][0].client[0])],
                remediation=[{"action": "Address the stated cause (e.g. restore pool members for 'No pool member available', raise "
                                        "limits for connection-limit causes, adjust iRules that reject).",
                              "risk": "Raising connection limits can overload pool members."}],
                missing_evidence=["BIG-IP configuration for the virtual server and pool"],
                packets=[{"frame": rc["frame"], "ts_ns": rc["ts_ns"], "role": "BIG-IP RST"} for _, rc in items],
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=[e for fl, _ in items[:3] for e in tcp_timeline(fl)],
                metrics={"resets": len(items), "virtual_servers": vips},
                f5_relevance="Evidence of BIG-IP: F5 Ethernet trailer present.",
            ))
        return out


class BigipPersistence(Rule):
    meta = RuleMeta(
        rule_id="F5-002",
        version="1.0.0",
        title="BIG-IP cookie persistence behaviour",
        category="f5",
        default_severity="info",
        required_evidence=["Cleartext BIGipServer<pool> cookies in Set-Cookie or Cookie headers"],
        detection_logic=("Decode unencrypted BIGipServer cookies (IPv4 'address.port.0000' encoding) into pool member address and port. "
                         "Report each pool cookie with its members; raise severity when one client is assigned to different members "
                         "for the same pool cookie (persistence not holding)."),
        limitations=["Encrypted persistence cookies cannot be decoded.", "Decoded members reveal internal addressing; reports redact on export."],
        false_positives=["Member changes after a legitimate member failure (persistence correctly re-balanced)"],
        severity_rationale="Info normally; Medium when the same client is moved between members, which breaks stateful applications.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        by_cookie: dict[str, dict] = defaultdict(lambda: {"members": defaultdict(list), "clients": defaultdict(set), "encrypted": 0})
        for fl in ctx.tcp_flows:
            for h in fl.http:
                for p in h.bigip_persistence:
                    entry = by_cookie[p["cookie"]]
                    if p.get("encrypted"):
                        entry["encrypted"] += 1
                        continue
                    member = f"{p['member_ip']}:{p['member_port']}"
                    entry["members"][member].append((fl, h))
                    entry["clients"][fl.client[0]].add(member)
        out = []
        for cookie, data in by_cookie.items():
            moved = {c: m for c, m in data["clients"].items() if len(m) > 1}
            members = sorted(data["members"])
            frames = [h.resp_frame or h.req_frame for items in data["members"].values() for _, h in items]
            items = [i for v in data["members"].values() for i in v]
            if not items and not data["encrypted"]:
                continue
            obs = [Observation(f"Cookie {cookie} decodes to pool member(s): {', '.join(members) or 'none (encrypted)'}.", frames)]
            if data["encrypted"]:
                obs.append(Observation(f"{data['encrypted']} encrypted value(s) could not be decoded."))
            if moved:
                obs.append(Observation("Clients assigned to more than one member: " +
                                       "; ".join(f"{c} → {', '.join(sorted(m))}" for c, m in list(moved.items())[:5]) + "."))
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=cookie,
                title=f"Persistence cookie {cookie}" + (" changes member for the same client" if moved else ""),
                severity="medium" if moved else "info",
                confidence=Confidence("high", 0.85, "The cookie value is decoded deterministically from the HTTP header."),
                summary=(f"BIG-IP cookie persistence ({cookie}) points to {len(members)} member(s)"
                         + (f"; {len(moved)} client(s) were moved between members." if moved else ".")),
                observations=obs,
                assessment=("Persistence is not keeping some clients on one member." if moved else
                            "Persistence cookies are present and decode to the listed members."),
                probable_cause=("The persisted member became unavailable, the client did not return the cookie, or the cookie "
                                "persistence profile differs between virtual servers." if moved else "Normal cookie persistence."),
                alternatives=["Multiple virtual servers sharing a pool with different persistence profiles", "OneConnect reusing server-side "
                              "connections without re-evaluating persistence (check OneConnect source mask)"],
                verification=[C.cmd("Show persistence records", "tmsh show ltm persistence persist-records all-properties", "BIG-IP (tmsh)"),
                              C.bigip_pool_members(cookie.replace("BIGipServer", "") or "<pool_name>")],
                remediation=[{"action": "Encrypt persistence cookies (cookie-encryption in the persistence profile) to avoid exposing internal addresses.",
                              "risk": "Changing cookie encryption invalidates existing cookies once, moving clients one time."}],
                missing_evidence=["Pool member availability history"] if moved else [],
                packets=[{"frame": h.resp_frame or h.req_frame, "ts_ns": h.resp_ts or h.req_ts, "role": "persistence cookie"} for _, h in items],
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=[],
                metrics={"cookie": cookie, "members": members, "clients_moved": len(moved), "encrypted_values": data["encrypted"]},
                f5_relevance="BIGipServer cookies are set by BIG-IP cookie persistence, so a BIG-IP is in the path of these sessions.",
            ))
        return out


F5_OBSERVABLE_RULES: list[type[Rule]] = [BigipResetCause, BigipPersistence]
