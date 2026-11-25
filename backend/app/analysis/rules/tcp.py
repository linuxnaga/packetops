"""TCP troubleshooting rules."""

from __future__ import annotations

from collections import defaultdict

from ..state import TcpFlow
from . import commands as C
from .base import Confidence, FindingDraft, Observation, Rule, RuleMeta
from .context import RuleContext, ep, frames_text, ms, tcp_timeline, tuple_of


def is_packet_too_big(icmp: dict) -> bool:
    """ICMPv4 fragmentation-needed or ICMPv6 packet-too-big."""
    return (not icmp["v6"] and icmp["type"] == 3 and icmp["code"] == 4) or (icmp["v6"] and icmp["type"] == 2)


def _group_by_server(flows: list[TcpFlow]) -> dict[tuple[str, int], list[TcpFlow]]:
    groups: dict[tuple[str, int], list[TcpFlow]] = defaultdict(list)
    for fl in flows:
        groups[fl.server].append(fl)
    return groups


class UnansweredSyn(Rule):
    meta = RuleMeta(
        rule_id="TCP-001",
        version="1.2.0",
        title="Connection attempts receive no SYN-ACK",
        category="tcp",
        default_severity="high",
        required_evidence=["Client SYN segments (tcp.flags.syn==1 && tcp.flags.ack==0)",
                           "Absence of any server-to-client packet in the same TCP conversation"],
        detection_logic=(
            "Group TCP conversations by server endpoint. Report endpoints where at least one conversation has a "
            "client SYN but no packet at all in the server-to-client direction. Conversations whose only SYN is "
            "within 3 s of the end of the capture are ignored because the answer may have arrived after capture stopped."
        ),
        limitations=[
            "A capture point that only sees one routing direction (asymmetric routing) will also show unanswered SYNs.",
            "The capture cannot show whether the SYN reached the server; it only shows that no reply passed the capture point.",
        ],
        false_positives=["Port scans and health probes to closed, filtered ports",
                         "Captures filtered to one direction (e.g. 'src host X')"],
        severity_rationale="High: the client cannot establish a connection at all, so the service is unavailable to it.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        candidates = []
        for fl in ctx.tcp_flows:
            if fl.syn_count and not fl.packets["s2c"] and not fl.direction_inferred:
                if fl.syn_count == 1 and ctx.near_end(fl.syns[0]["ts_ns"]):
                    continue
                candidates.append(fl)
        out = []
        for server, flows in _group_by_server(candidates).items():
            syn_frames = [s["frame"] for fl in flows for s in fl.syns]
            retrans = sum(1 for fl in flows for s in fl.syns if s["retrans"])
            clients = sorted({fl.client[0] for fl in flows})
            sip, sport = server
            return_seen = any(c in ctx.bidirectional_hosts for c in clients)
            if retrans and return_seen:
                conf = Confidence("high", 0.85, "The client retransmitted its SYN and the capture shows return traffic for "
                                  "other conversations of the same client, so the capture point can see replies.")
            elif retrans:
                conf = Confidence("medium", 0.6, "SYN retransmissions confirm the client never got an answer, but no "
                                  "bidirectional conversation proves this capture point sees return traffic.")
            else:
                conf = Confidence("low", 0.35, "Only single SYNs without retransmission were seen; the client may have "
                                  "given up quickly or the capture may be one-directional.")
            obs = [
                Observation(f"{sum(fl.syn_count for fl in flows)} SYN segment(s) from {', '.join(clients[:5])} to {ep(server)} "
                            f"across {len(flows)} connection attempt(s): {frames_text(syn_frames)}.", syn_frames),
                Observation(f"{retrans} of these SYNs are retransmissions (same sequence number re-sent by the client).",
                            [s["frame"] for fl in flows for s in fl.syns if s["retrans"]]),
                Observation(f"No SYN-ACK, RST or any other packet from {ep(server)} to the client was captured in these conversations."),
            ]
            if return_seen:
                obs.append(Observation("The same client has other conversations with traffic in both directions in this capture."))
            first = min(fl.syns[0]["ts_ns"] for fl in flows)
            last = max(fl.syns[-1]["ts_ns"] for fl in flows)
            obs.append(Observation(f"Attempts span {ms(last - first)}."))
            packets = [{"frame": s["frame"], "ts_ns": s["ts_ns"], "role": "SYN" + (" retransmission" if s["retrans"] else "")}
                       for fl in flows for s in fl.syns]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{sip}:{sport}",
                title=f"No response to connection attempts to {ep(server)}",
                severity="high",
                confidence=conf,
                summary=(f"Clients tried to open {len(flows)} TCP connection(s) to {ep(server)} and the capture shows no reply "
                         f"of any kind from that endpoint; {retrans} SYN retransmission(s) were sent."),
                observations=obs,
                assessment=("The SYNs left the client side of the capture point and nothing came back through it. Either the SYNs "
                            "were dropped before reaching a listener, the listener silently ignored them, or the replies took a "
                            "different path that bypasses this capture point."),
                probable_cause=(f"Silent drop on the path to {ep(server)} (firewall/ACL, routing, or a service that drops instead "
                                "of rejecting), or the return path does not traverse this capture point."),
                alternatives=[
                    "Asymmetric routing: SYN-ACKs exist but return via another path (check a capture on the other path).",
                    f"If {sip} is a BIG-IP virtual server: the virtual is disabled or has no available pool members and is "
                    "configured to drop, an AFM/packet filter/IP intelligence policy drops the SYN, or the address is not "
                    "owned (ARP) by the active device.",
                    "Host firewall on the server drops connections to this port.",
                    "SYN cookies / connection limits on an intermediate device silently dropping new connections.",
                ],
                verification=[
                    C.port_check(sip, sport),
                    *C.bigip_vs_status(sip, sport),
                    C.cmd("Confirm which device answers ARP for the destination", f"tmsh show net arp | grep -w {sip}", "BIG-IP (tmsh)"),
                    C.bigip_tcpdump(clients[0], sip, sport),
                    C.listener_check(sport),
                ],
                remediation=[
                    {"action": "Restore reachability: correct the route/ACL/firewall rule that drops the SYN.",
                     "risk": "Firewall changes can expose the service more broadly than intended; scope rules to required sources."},
                    {"action": "If the destination is a BIG-IP virtual server, enable it or restore at least one healthy pool member.",
                     "risk": "Re-enabling a virtual sends production traffic to members that may still be unhealthy."},
                ],
                missing_evidence=[
                    "A capture on the server side (or on the BIG-IP with 0.0:nnnp) to see whether the SYN arrives",
                    "Firewall / AFM logs for the 5-tuples listed",
                    "BIG-IP virtual server and pool status at the time of the capture",
                ],
                packets=packets,
                flows=[f"t{fl.stream}" for fl in flows],
                tuples=[tuple_of(fl) for fl in flows],
                timeline=[e for fl in flows[:5] for e in tcp_timeline(fl)],
                metrics={"attempts": len(flows), "syn_segments": sum(fl.syn_count for fl in flows), "syn_retransmissions": retrans,
                         "clients": clients[:20]},
                f5_relevance=ctx.bigip_hint(sip),
            ))
        return out


class SynRejected(Rule):
    meta = RuleMeta(
        rule_id="TCP-002",
        version="1.1.0",
        title="Connection attempts rejected with RST",
        category="tcp",
        default_severity="high",
        required_evidence=["Client SYN", "RST (usually RST+ACK) from the server endpoint before any SYN-ACK"],
        detection_logic="Report server endpoints that answered a client SYN with a RST and never sent a SYN-ACK in that conversation.",
        limitations=["The RST may have been generated by a middlebox impersonating the server address."],
        false_positives=["Scans of closed ports", "Clients probing several ports for an available service"],
        severity_rationale="High: the endpoint actively refuses connections, so the service is unavailable on that port.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        hits = [fl for fl in ctx.tcp_flows if fl.syn_count and not fl.synack_count and any(r["dir"] == "s2c" for r in fl.rsts)]
        out = []
        for server, flows in _group_by_server(hits).items():
            sip, sport = server
            rsts = [r for fl in flows for r in fl.rsts if r["dir"] == "s2c"]
            syns = [s for fl in flows for s in fl.syns]
            delays = [r["ts_ns"] - fl.syns[-1]["ts_ns"] for fl in flows for r in fl.rsts if r["dir"] == "s2c" and fl.syns]
            causes = sorted({r["f5_rst_cause"] for r in rsts if r.get("f5_rst_cause")})
            obs = [
                Observation(f"{len(syns)} SYN(s) to {ep(server)}: {frames_text([s['frame'] for s in syns])}.", [s["frame"] for s in syns]),
                Observation(f"{len(rsts)} RST(s) returned from {ep(server)} without a SYN-ACK: {frames_text([r['frame'] for r in rsts])}.",
                            [r["frame"] for r in rsts]),
            ]
            if delays:
                obs.append(Observation(f"Reset arrived {ms(min(delays))}–{ms(max(delays))} after the SYN."))
            if causes:
                obs.append(Observation("BIG-IP reset cause in the F5 Ethernet trailer: " + "; ".join(causes),
                                       [r["frame"] for r in rsts if r.get("f5_rst_cause")]))
            conf = Confidence("high", 0.9, "A RST in direct reply to a SYN is an explicit refusal visible in the capture.") if not causes else \
                Confidence("high", 0.95, "The RST carries a BIG-IP reset cause, which states why TMM refused the connection.")
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{sip}:{sport}",
                title=f"Connections to {ep(server)} refused with TCP reset",
                severity="high",
                confidence=conf,
                summary=f"{len(flows)} connection attempt(s) to {ep(server)} were answered with a TCP reset instead of a SYN-ACK.",
                observations=obs,
                assessment="Something at or in front of the destination address actively refused the connection.",
                probable_cause=("No service is listening on this port, or a load balancer virtual server has no available pool members "
                                "and rejects new connections." if not causes else f"BIG-IP refused the connection: {causes[0]}"),
                alternatives=[
                    "A firewall configured to reject (send RST) rather than drop.",
                    f"If {sip} is a BIG-IP virtual server: the virtual is disabled/offline, the connection limit is reached, "
                    "or a reject-type virtual server matches this destination.",
                    "The service is bound to a different address or port.",
                ],
                verification=[C.listener_check(sport), *C.bigip_vs_status(sip, sport), C.bigip_pool_members(), C.bigip_rst_cause()],
                remediation=[
                    {"action": "Start or rebind the service on the expected port, or restore pool member health.",
                     "risk": "Bringing an unhealthy member back without fixing its health check can cause errors for users."},
                ],
                missing_evidence=["Server listener state at capture time", "BIG-IP reset cause logging (tm.rstcause.log) if a BIG-IP is in path"]
                if not causes else ["BIG-IP pool member status at capture time"],
                packets=[{"frame": s["frame"], "ts_ns": s["ts_ns"], "role": "SYN"} for s in syns]
                + [{"frame": r["frame"], "ts_ns": r["ts_ns"], "role": "RST"} for r in rsts],
                flows=[f"t{fl.stream}" for fl in flows],
                tuples=[tuple_of(fl) for fl in flows],
                timeline=[e for fl in flows[:5] for e in tcp_timeline(fl)],
                metrics={"attempts": len(flows), "f5_rst_causes": causes},
                f5_relevance=ctx.bigip_hint(sip),
            ))
        return out


class Retransmissions(Rule):
    meta = RuleMeta(
        rule_id="TCP-003",
        version="1.2.0",
        title="TCP retransmissions",
        category="tcp",
        default_severity="medium",
        required_evidence=["tcp.analysis.retransmission markers", "Data segment counts per direction"],
        detection_logic=(
            "For each established conversation count retransmitted segments per direction (as identified by the "
            "Wireshark TCP analysis engine). Report a conversation when it has at least 2 retransmissions and they "
            "make up at least 1% of the data segments in that direction. Conversations are grouped by server endpoint."
        ),
        limitations=[
            "A retransmission proves the sender did not receive a timely acknowledgement; it does not prove the "
            "original segment was lost (the ACK may have been lost or delayed instead).",
            "If the capture point is upstream of the loss, both the original and the retransmission are visible.",
        ],
        false_positives=["Spurious retransmissions caused by aggressive RTO on high-latency paths",
                         "Capture taken on a host with TSO/GSO offload producing misleading segment boundaries"],
        severity_rationale="Medium: retransmissions add latency and reduce throughput but traffic still flows.",
        parameters={"min_retrans": 2, "min_ratio": 0.01},
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        hits = []
        for fl in ctx.tcp_flows:
            if any(is_packet_too_big(i) for i in fl.icmp):
                continue  # explained by TCP-008 (path MTU)
            for d in ("c2s", "s2c"):
                n = fl.retrans[d].count
                data_pkts = max(1, fl.packets[d])
                if n >= 2 and n / data_pkts >= 0.01:
                    hits.append((fl, d))
        out = []
        grouped: dict[tuple, list] = defaultdict(list)
        for fl, d in hits:
            grouped[fl.server].append((fl, d))
        for server, items in grouped.items():
            total = sum(fl.retrans[d].count for fl, d in items)
            fast = sum(fl.fast_retrans.count for fl, _ in items)
            spurious = sum(fl.spurious.count for fl, _ in items)
            dup = sum(fl.dupacks.count for fl, _ in items)
            lost = sum(fl.lost.count for fl, _ in items)
            frames = [f for fl, d in items for f in fl.retrans[d].frames()]
            senders = sorted({ep(fl.client) if d == "c2s" else ep(fl.server) for fl, d in items})
            ratio = max(fl.retrans[d].count / max(1, fl.packets[d]) for fl, d in items)
            rto_like = total - fast - spurious
            sev = "high" if ratio >= 0.1 else "medium"
            obs = [
                Observation(f"{total} retransmitted segment(s) in {len(items)} conversation direction(s) with {ep(server)}; "
                            f"sent by {', '.join(senders[:4])}: {frames_text(frames)}.", frames),
                Observation(f"Highest retransmission ratio in one direction: {ratio:.1%} of that direction's packets."),
                Observation(f"Breakdown: {fast} fast retransmission(s) (after duplicate ACKs), {spurious} spurious, "
                            f"{max(0, rto_like)} other (typically timeout-driven)."),
            ]
            if dup:
                obs.append(Observation(f"{dup} duplicate ACK(s) observed in these conversations.",
                                       [f for fl, _ in items for f in fl.dupacks.frames()]))
            if lost:
                obs.append(Observation(f"{lost} gap(s) where the capture missed a segment before later data ('previous segment not captured').",
                                       [f for fl, _ in items for f in fl.lost.frames()]))
            if spurious and spurious >= total / 2:
                assessment = ("Most retransmissions were spurious: the original data had already been acknowledged. This points "
                              "to delayed ACKs or an RTO that is too aggressive rather than loss.")
                cause = "Excessive delay/jitter on the path or delayed acknowledgements, causing premature retransmission timeouts."
                conf = Confidence("medium", 0.6, "Wireshark marked the retransmissions as spurious based on prior ACKs.")
            elif fast and dup:
                assessment = ("The receiver sent duplicate ACKs and the sender fast-retransmitted, which is the signature of a "
                              "segment that was not delivered to the receiver while later segments were.")
                cause = "Packet loss between the sender and the receiver (consistent with, but not proof of, loss on the path)."
                conf = Confidence("medium", 0.7, "Duplicate ACKs followed by fast retransmission strongly indicate a missing segment "
                                  "at the receiver; the capture cannot show where it was dropped.")
            else:
                assessment = ("The sender re-sent data after not receiving an acknowledgement in time. Either the data or the "
                              "acknowledgement did not arrive, or arrived late.")
                cause = "Loss or excessive delay of data or ACK segments on the path, or a congested/overloaded receiver."
                conf = Confidence("low" if total < 5 else "medium", 0.4 if total < 5 else 0.55,
                                  "Timeout retransmissions alone cannot distinguish data loss from ACK loss or delay.")
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}",
                title=f"Retransmissions on connections with {ep(server)}",
                severity=sev,
                confidence=conf,
                summary=f"{total} TCP retransmission(s) were observed on {len(items)} conversation direction(s) with {ep(server)} "
                        f"(peak {ratio:.1%} of packets in one direction).",
                observations=obs,
                assessment=assessment,
                probable_cause=cause,
                alternatives=[
                    "ACKs lost or delayed on the return path (data was delivered but the sender did not learn of it).",
                    "Capture-point drops (check the capture's own drop counters; 'previous segment not captured' gaps suggest this).",
                    "Interface errors, duplex mismatch or a congested link along the path.",
                    "If a BIG-IP is in path: compare client-side and server-side legs to see on which side retransmissions occur; "
                    "the TCP profile (e.g. congestion control, RTO settings) applies separately to each side.",
                ],
                verification=[
                    C.cmd("Check interface errors and drops", "tmsh show net interface all-properties", "BIG-IP (tmsh)"),
                    C.cmd("Check host interface counters", "ip -s link; ethtool -S <iface> | grep -Ei 'err|drop|discard'", "Linux host"),
                    C.generic_tcpdump(server[0]),
                    C.bigip_tcpdump(server[0]),
                ],
                remediation=[
                    {"action": "Identify the lossy segment of the path by capturing at two points and comparing.",
                     "risk": "Additional captures add CPU load on busy devices; use tight filters."},
                    {"action": "Fix interface errors / congestion (QoS, capacity) on the identified link.",
                     "risk": "QoS changes affect other traffic classes."},
                ],
                missing_evidence=["A capture at the receiver to see whether the original segment arrived",
                                  "Interface error and drop counters along the path",
                                  "Capture tool drop statistics"],
                packets=[{"frame": f, "ts_ns": t, "role": "retransmission"} for fl, d in items for f, t in fl.retrans[d].refs],
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=[e for fl, _ in items[:3] for e in tcp_timeline(fl)],
                metrics={"retransmissions": total, "fast": fast, "spurious": spurious, "dup_acks": dup, "max_ratio": round(ratio, 4)},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


class DuplicateAcks(Rule):
    meta = RuleMeta(
        rule_id="TCP-004",
        version="1.0.0",
        title="Duplicate ACK bursts",
        category="tcp",
        default_severity="low",
        required_evidence=["tcp.analysis.duplicate_ack markers"],
        detection_logic="Report conversations with 3 or more duplicate ACKs (the fast-retransmit threshold).",
        limitations=["Duplicate ACKs also occur with packet reordering, which does not imply loss.",
                     "With SACK, duplicate ACKs may be legitimate signals while recovery proceeds normally."],
        false_positives=["Reordering on multipath links (ECMP / link aggregation)"],
        severity_rationale="Low: duplicate ACKs indicate the receiver is missing data; impact depends on recovery speed.",
        parameters={"min_dup_acks": 3},
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        out = []
        for fl in ctx.tcp_flows:
            if fl.dupacks.count < 3:
                continue
            frames = fl.dupacks.frames()
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"t{fl.stream}",
                title=f"Duplicate ACKs between {ep(fl.client)} and {ep(fl.server)}",
                severity="low",
                confidence=Confidence("high", 0.8, "Duplicate ACKs are directly marked by the TCP analysis engine."),
                summary=f"{fl.dupacks.count} duplicate ACK(s) were sent in conversation t{fl.stream}; "
                        f"{fl.fast_retrans.count} fast retransmission(s) followed and {fl.ooo.count} segment(s) were out of order.",
                observations=[
                    Observation(f"Duplicate ACKs: {frames_text(frames)}.", frames),
                    Observation(f"Fast retransmissions: {frames_text(fl.fast_retrans.frames())}.", fl.fast_retrans.frames()),
                    Observation(f"Out-of-order segments: {fl.ooo.count}.", fl.ooo.frames()),
                ],
                assessment="The receiver repeatedly acknowledged the same sequence number, meaning it received later data while "
                           "an earlier segment was missing.",
                probable_cause="A missing segment (loss) or reordering between the sender and receiver."
                if not fl.ooo.count else "Segment reordering on the path, possibly combined with loss.",
                alternatives=["Reordering due to per-packet load sharing", "Capture-point drops"],
                verification=[C.generic_tcpdump(fl.client[0], fl.server[0], fl.server[1])],
                remediation=[{"action": "Investigate loss/reordering on the path (see TCP-003 if retransmissions are also reported).",
                              "risk": "None from investigation alone."}],
                missing_evidence=["Receiver-side capture"],
                packets=[{"frame": f, "ts_ns": t, "role": "duplicate ACK"} for f, t in fl.dupacks.refs]
                + [{"frame": f, "ts_ns": t, "role": "fast retransmission"} for f, t in fl.fast_retrans.refs],
                flows=[f"t{fl.stream}"],
                tuples=[tuple_of(fl)],
                timeline=tcp_timeline(fl),
                metrics={"dup_acks": fl.dupacks.count, "fast_retransmissions": fl.fast_retrans.count, "out_of_order": fl.ooo.count},
            ))
        return out


class ZeroWindow(Rule):
    meta = RuleMeta(
        rule_id="TCP-005",
        version="1.0.0",
        title="Receiver advertises a zero window",
        category="tcp",
        default_severity="medium",
        required_evidence=["tcp.analysis.zero_window markers"],
        detection_logic="Report each direction of a conversation in which the receiver advertised a zero receive window.",
        limitations=["The capture cannot show why the receiving application stopped reading data."],
        false_positives=["Brief zero windows during normal flow control on slow consumers"],
        severity_rationale="Medium: the sender is blocked until the receiver frees buffer space, stalling the transfer.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        out = []
        for fl in ctx.tcp_flows:
            for d in ("c2s", "s2c"):
                zw = fl.zero_window[d]
                if not zw.count:
                    continue
                receiver = fl.client if d == "c2s" else fl.server
                sender = fl.server if d == "c2s" else fl.client
                out.append(FindingDraft(
                    rule=self.meta,
                    subject_key=f"t{fl.stream}:{d}",
                    title=f"{ep(receiver)} advertised a zero receive window",
                    severity="medium",
                    confidence=Confidence("high", 0.85, "Zero-window advertisements are explicit header values."),
                    summary=f"{ep(receiver)} told {ep(sender)} {zw.count} time(s) that its receive buffer was full, pausing the transfer.",
                    observations=[Observation(f"Zero-window segments from {ep(receiver)}: {frames_text(zw.frames())}.", zw.frames()),
                                  Observation(f"Zero-window probes in conversation: {fl.keepalive.count + 0}.")],
                    assessment=f"The application on {ep(receiver)} was not reading data as fast as it arrived.",
                    probable_cause=f"Slow or blocked application or resource exhaustion (CPU, memory, disk) on {ep(receiver)[:60]}.",
                    alternatives=["Receive buffer size too small for the bandwidth-delay product",
                                  "If the receiver is a BIG-IP: proxy buffer limits in the TCP profile (send-buffer/receive-window) "
                                  "or a slow peer on the other side of the full proxy"],
                    verification=[C.cmd("Check socket queues on the receiver", "ss -tmi dst " + sender[0], "Receiver (Linux)")],
                    remediation=[{"action": "Investigate the receiving application's throughput; tune buffers if appropriate.",
                                  "risk": "Larger buffers increase memory use per connection."}],
                    missing_evidence=["Application and host resource metrics on the receiver at capture time"],
                    packets=[{"frame": f, "ts_ns": t, "role": "zero window"} for f, t in zw.refs],
                    flows=[f"t{fl.stream}"],
                    tuples=[tuple_of(fl)],
                    timeline=tcp_timeline(fl),
                    metrics={"zero_window_segments": zw.count, "direction": "client" if d == "c2s" else "server"},
                ))
        return out


class UnexpectedReset(Rule):
    meta = RuleMeta(
        rule_id="TCP-006",
        version="1.2.0",
        title="Established connection reset",
        category="tcp",
        default_severity="medium",
        required_evidence=["Completed three-way handshake", "RST after application data", "No preceding FIN exchange"],
        detection_logic=(
            "Report RST segments sent after the handshake completed and after payload was exchanged, where the "
            "connection had not already been closed with FIN by both sides. Severity is raised when an HTTP request "
            "was still awaiting its response at the time of the reset."
        ),
        limitations=["Some applications intentionally abort connections with RST instead of FIN.",
                     "A RST may be injected by a middlebox using the endpoint's address."],
        false_positives=["Browsers aborting idle keep-alive connections", "Load balancers configured to reset on idle timeout"],
        severity_rationale="Medium by default; High when a request was in flight, because users see an error.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        out = []
        for fl in ctx.tcp_flows:
            if not fl.handshake_complete and not fl.direction_inferred:
                continue
            fin_dirs = set()
            resets = []
            for r in fl.rsts:
                if r["after_data"] and len(fin_dirs) < 2:
                    resets.append(r)
            for f in fl.fins:
                fin_dirs.add(f["dir"])
            resets = [r for r in resets if not any(f["ts_ns"] < r["ts_ns"] and f["dir"] == r["dir"] for f in fl.fins)]
            if fl.tls and any(a["level"] == "fatal" for a in fl.tls.alerts):
                continue  # termination is explained by the TLS alert (TLS-001)
            if not resets:
                continue
            r = resets[0]
            sender = fl.client if r["dir"] == "c2s" else fl.server
            other = fl.server if r["dir"] == "c2s" else fl.client
            pending = r.get("pending_http", 0)
            sev = "high" if pending else "medium"
            obs = [
                Observation(f"Handshake completed at frame #{fl.handshake_ack['frame']}." if fl.handshake_ack else
                            "Conversation started before the capture (handshake not seen)."),
                Observation(f"{ep(sender)} sent RST at frame #{r['frame']} after {fl.payload['c2s']} bytes client→server and "
                            f"{fl.payload['s2c']} bytes server→client.", [r["frame"]]),
            ]
            req = next((h for h in fl.http if h.resp_frame is None and h.req_ts <= r["ts_ns"]), None) if pending else None
            if pending:
                obs.append(Observation(f"{pending} HTTP request(s) were awaiting a response when the reset was sent"
                                       + (f" (request at frame #{req.req_frame}: {req.method} {req.path})." if req else "."),
                                       [req.req_frame] if req else []))
            if fl.last_data.get("c2s") and fl.last_data["c2s"][1] <= r["ts_ns"]:
                obs.append(Observation(f"Time from the last client data (#{fl.last_data['c2s'][0]}) to the reset: "
                                       f"{ms(r['ts_ns'] - fl.last_data['c2s'][1])}.", [fl.last_data["c2s"][0]]))
            if r.get("f5_rst_cause"):
                obs.append(Observation(f"BIG-IP reset cause in F5 Ethernet trailer: {r['f5_rst_cause']}.", [r["frame"]]))
            cause = (f"BIG-IP aborted the connection: {r['f5_rst_cause']}" if r.get("f5_rst_cause") else
                     f"The application or a device in front of {ep(sender)} aborted the connection"
                     + (" while a request was outstanding." if pending else "."))
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"t{fl.stream}",
                title=f"Connection reset by {ep(sender)}" + (" with request in flight" if pending else ""),
                severity=sev,
                confidence=Confidence("high" if r.get("f5_rst_cause") else "medium", 0.9 if r.get("f5_rst_cause") else 0.65,
                                      "The reset is directly observed; the reason is only known when the RST carries a BIG-IP "
                                      "reset cause or matching server logs exist."),
                summary=f"{ep(sender)} reset an established connection with {ep(other)}"
                        + (" while an HTTP request was still waiting for its response." if pending else "."),
                observations=obs,
                assessment=("The reset came from the server side of the conversation." if r["dir"] == "s2c"
                            else "The client aborted the connection."),
                probable_cause=cause,
                alternatives=[
                    "Application crash or worker restart on the server.",
                    "Idle or session timeout on a firewall or load balancer between the endpoints.",
                    "If a BIG-IP is in path: iRule reject, ASM/AWAF blocking with TCP RST, connection limits, or "
                    "'reset on timeout' in the TCP/FastL4 profile.",
                    "Request rejected by a security device that injects RSTs.",
                ],
                verification=[C.bigip_rst_cause(), C.bigip_connections(fl.client[0], None),
                              C.cmd("Check server application logs around the reset time", "journalctl --since '<capture time>' -u <service>", "Server")],
                remediation=[{"action": "Identify the component that generated the reset (enable reset-cause logging, check server logs) "
                                        "and fix the underlying error.", "risk": "Reset-cause logging adds log volume; disable after the test."}],
                missing_evidence=["Server application logs", "BIG-IP /var/log/ltm with tm.rstcause.log enabled (if BIG-IP is in path)"],
                packets=[{"frame": x["frame"], "ts_ns": x["ts_ns"], "role": "RST"} for x in resets]
                + ([{"frame": fl.handshake_ack["frame"], "ts_ns": fl.handshake_ack["ts_ns"], "role": "handshake ACK"}] if fl.handshake_ack else []),
                flows=[f"t{fl.stream}"],
                tuples=[tuple_of(fl)],
                timeline=tcp_timeline(fl),
                metrics={"pending_http_requests": pending, "reset_by": "server" if r["dir"] == "s2c" else "client",
                         "pending_request_path": req.path if req else None,
                         "bytes_c2s": fl.payload["c2s"], "bytes_s2c": fl.payload["s2c"]},
                f5_relevance=ctx.bigip_hint(fl.server[0]),
            ))
        return out


class SlowHandshake(Rule):
    meta = RuleMeta(
        rule_id="TCP-007",
        version="1.0.0",
        title="Slow connection establishment",
        category="tcp",
        default_severity="low",
        required_evidence=["SYN and SYN-ACK timestamps", "Handshake-completing ACK"],
        detection_logic=("Report conversations whose first-SYN-to-ACK time exceeds 1 s (usually caused by SYN retransmission), "
                         "or whose SYN→SYN-ACK time exceeds both 200 ms and 3× the capture's median handshake RTT."),
        limitations=["Handshake RTT measured at the capture point only covers the path between the capture point and the server."],
        false_positives=["Long-distance (satellite/intercontinental) paths with legitimately high RTT"],
        severity_rationale="Low/Medium: connections succeed but users experience delays before any data is exchanged.",
        parameters={"connect_time_s": 1.0, "rtt_ms": 200, "median_factor": 3},
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        med = ctx.median_handshake_rtt_ns
        out = []
        grouped: dict[tuple, list[TcpFlow]] = defaultdict(list)
        for fl in ctx.tcp_flows:
            ct = fl.connect_time_ns
            rtt = fl.handshake_rtt_ns
            if (ct and ct > 1_000_000_000) or (rtt and rtt > 200_000_000 and med and rtt > 3 * med):
                grouped[fl.server].append(fl)
        for server, flows in grouped.items():
            worst = max(flows, key=lambda f: f.connect_time_ns or 0)
            retried = [fl for fl in flows if fl.syn_count > 1]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}",
                title=f"Slow TCP connection setup to {ep(server)}",
                severity="medium" if retried else "low",
                confidence=Confidence("high", 0.8, "Handshake timings are measured directly from packet timestamps."),
                summary=f"{len(flows)} connection(s) to {ep(server)} took up to {ms(worst.connect_time_ns)} to establish"
                        + (f"; {len(retried)} needed SYN retransmissions." if retried else "."),
                observations=[
                    Observation(f"Slowest: t{worst.stream} — first SYN #{worst.syns[0]['frame']} to handshake ACK "
                                f"#{worst.handshake_ack['frame'] if worst.handshake_ack else '?'} = {ms(worst.connect_time_ns)}; "
                                f"SYN→SYN-ACK {ms(worst.handshake_rtt_ns)}.",
                                [worst.syns[0]["frame"]] + ([worst.handshake_ack["frame"]] if worst.handshake_ack else [])),
                    Observation(f"Median handshake RTT across the capture: {ms(med)}."),
                ],
                assessment="SYN retransmissions mean the first SYN(s) went unanswered; the delay equals the client's SYN retry timer."
                if retried else "The server or the path to it was slow to answer the SYN.",
                probable_cause="Intermittent drops of SYN or SYN-ACK segments, or a server/listener with a full accept queue."
                if retried else "High latency or queuing on the path, or a busy server delaying SYN-ACKs.",
                alternatives=["SYN flood protection (SYN cookies / SYN check) activating on an intermediate device",
                              "If a BIG-IP is in path: virtual server or pool connection limits, or SYN cookie protection thresholds."],
                verification=[C.cmd("Check listen queue overflows", "nstat -az | grep -i -E 'ListenOverflows|ListenDrops'", "Server (Linux)"),
                              C.cmd("Check SYN cookie activity", "tmsh show ltm virtual <virtual_name> | grep -i syncookie", "BIG-IP (tmsh)")],
                remediation=[{"action": "Find where SYNs are being dropped intermittently; increase accept backlog if the server is saturated.",
                              "risk": "Raising backlogs on an overloaded server only hides the saturation."}],
                missing_evidence=["Server-side capture or listen-queue statistics"],
                packets=[{"frame": s["frame"], "ts_ns": s["ts_ns"], "role": "SYN"} for fl in flows[:10] for s in fl.syns]
                + [{"frame": s["frame"], "ts_ns": s["ts_ns"], "role": "SYN-ACK"} for fl in flows[:10] for s in fl.synacks],
                flows=[f"t{fl.stream}" for fl in flows],
                tuples=[tuple_of(fl) for fl in flows],
                timeline=tcp_timeline(worst),
                metrics={"connections": len(flows), "worst_connect_ms": round((worst.connect_time_ns or 0) / 1e6, 2),
                         "median_rtt_ms": round(med / 1e6, 2) if med else None},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


class PmtudProblem(Rule):
    meta = RuleMeta(
        rule_id="TCP-008",
        version="1.1.0",
        title="MTU / MSS inconsistency or path-MTU discovery failure",
        category="tcp",
        default_severity="high",
        required_evidence=["ICMP fragmentation-needed / packet-too-big messages referencing the conversation", "or",
                           "repeated retransmission of full-size segments while smaller segments succeed",
                           "MSS options in SYN/SYN-ACK"],
        detection_logic=(
            "Report a conversation when (a) ICMP 'fragmentation needed' (IPv4 type 3 code 4) or ICMPv6 'packet too big' "
            "messages quote one of its segments, or (b) segments larger than 1200 bytes are retransmitted 2+ times with "
            "no acknowledgement while smaller segments in the same direction were acknowledged, or (c) a segment exceeds "
            "the MSS the peer advertised."
        ),
        limitations=["If ICMP is filtered before the capture point, only the retransmission pattern (b) is visible.",
                     "TSO/GRO on the capture host can show segments larger than the MSS; check where the capture was taken."],
        false_positives=["Captures taken on a host with segmentation offload (large 'super-segments')"],
        severity_rationale="High: large transfers stall completely while small requests succeed, which is hard for users to diagnose.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        out = []
        for fl in ctx.tcp_flows:
            icmp_ptb = [i for i in fl.icmp if is_packet_too_big(i)]
            mss_violation = []
            for d, peer in (("c2s", "s2c"), ("s2c", "c2s")):
                peer_mss = fl.mss.get(peer)
                if peer_mss and fl.max_segment[d] > peer_mss and fl.max_segment[d] < 9000:
                    mss_violation.append((d, fl.max_segment[d], peer_mss))
            big_retrans = []
            for d in ("c2s", "s2c"):
                receiver_ack = fl.max_ack_s2c if d == "c2s" else fl.max_ack_c2s
                if (fl.retrans[d].count >= 2 and fl.retrans_max_len[d] > 1200
                        and receiver_ack < fl.retrans_max_end[d]):
                    big_retrans.append(d)
            if not (icmp_ptb or mss_violation or big_retrans):
                continue
            obs = []
            frames: list[int] = []
            if icmp_ptb:
                mtus = sorted({i["mtu"] for i in icmp_ptb if i.get("mtu")})
                f = [i["frame"] for i in icmp_ptb]
                frames += f
                obs.append(Observation(f"{len(icmp_ptb)} ICMP 'fragmentation needed / packet too big' message(s) from "
                                       f"{', '.join(sorted({i['src'] for i in icmp_ptb}))} quoting this conversation; "
                                       f"next-hop MTU {', '.join(map(str, mtus)) or 'not stated'}: {frames_text(f)}.", f))
            for d, size, peer_mss in mss_violation:
                obs.append(Observation(f"{'Client' if d == 'c2s' else 'Server'} sent a {size}-byte segment although the peer "
                                       f"advertised MSS {peer_mss}."))
            if big_retrans:
                d = big_retrans[0]
                f = fl.retrans[d].frames()
                frames += f
                obs.append(Observation(f"{fl.retrans[d].count} retransmission(s) of segments up to {fl.retrans_max_len[d]} bytes from "
                                       f"{'client' if d == 'c2s' else 'server'} that were never acknowledged: {frames_text(f)}.", f))
            obs.append(Observation(f"MSS advertised: client {fl.mss.get('c2s', 'n/a')}, server {fl.mss.get('s2c', 'n/a')}."))
            conf = Confidence("high", 0.85, "ICMP messages quoting the conversation state the path MTU explicitly.") if icmp_ptb else \
                Confidence("medium", 0.5, "Retransmission of only large segments fits a PMTUD black hole but other causes are possible.")
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"t{fl.stream}",
                title=f"Possible path-MTU problem between {ep(fl.client)} and {ep(fl.server)}",
                severity="high",
                confidence=conf,
                summary=("Large segments in this conversation do not get through: "
                         + ("ICMP reports a smaller path MTU and " if icmp_ptb else "")
                         + "full-size segments are retransmitted without being acknowledged."),
                observations=obs,
                assessment="Packets larger than the path MTU are being dropped. The sender keeps retransmitting the same large "
                           "segment instead of reducing its size.",
                probable_cause=("A link with a smaller MTU (tunnel, VPN, VXLAN/GRE overlay) is in the path and the sender does not "
                                "act on ICMP fragmentation-needed messages (or they are filtered closer to the sender)."),
                alternatives=["MSS clamping missing on a tunnel/VPN device",
                              "If a BIG-IP is in path: the TCP profile MSS or the VLAN/tunnel MTU differs between client and "
                              "server side, or 'pmtu' handling is disabled.",
                              "Firewall dropping ICMP type 3 code 4 on the return path"],
                verification=[
                    C.cmd("Probe the path MTU (DF set)", f"ping -M do -s 1472 -c 3 {fl.server[0]}", "Client-side host (Linux)"),
                    C.cmd("Trace the path MTU", f"tracepath -n {fl.server[0]}", "Client-side host (Linux)"),
                    C.cmd("Check VLAN / tunnel MTU", "tmsh list net vlan all mtu; tmsh list net tunnels tunnel all mtu", "BIG-IP (tmsh)"),
                ],
                remediation=[
                    {"action": "Clamp TCP MSS on the tunnel/VPN edge (e.g. to 1360) or align MTUs along the path.",
                     "risk": "Too-small MSS reduces throughput slightly; mismatched MTU changes can black-hole other traffic."},
                    {"action": "Permit ICMP type 3 code 4 / ICMPv6 type 2 through firewalls.",
                     "risk": "Limit to these ICMP types; do not open all ICMP."},
                ],
                missing_evidence=["Path MTU along the route (tracepath)", "Sender-side capture to confirm ICMP arrives at the sender"],
                packets=[{"frame": i["frame"], "ts_ns": i["ts_ns"], "role": "ICMP fragmentation needed"} for i in icmp_ptb]
                + [{"frame": f, "ts_ns": t, "role": "retransmission"} for d in big_retrans for f, t in fl.retrans[d].refs],
                flows=[f"t{fl.stream}"],
                tuples=[tuple_of(fl)],
                timeline=tcp_timeline(fl),
                metrics={"icmp_frag_needed": len(icmp_ptb), "mss": fl.mss, "max_segment": dict(fl.max_segment)},
                f5_relevance=ctx.bigip_hint(fl.server[0]),
            ))
        return out


class OneDirectional(Rule):
    meta = RuleMeta(
        rule_id="TCP-009",
        version="1.1.0",
        title="Only one direction of the conversation is visible",
        category="tcp",
        default_severity="medium",
        required_evidence=["Packets in only one direction", "ACK numbers acknowledging data that never crossed the capture point"],
        detection_logic=("Report conversations with traffic from one side only in which that side acknowledges data from the "
                         "other side (its ACK number advances), proving the other side's packets exist but were not captured."),
        limitations=["Cannot tell whether the missing direction takes a different network path or was filtered by the capture tool."],
        false_positives=["Capture filters such as 'src host X'", "SPAN sessions configured for one direction only"],
        severity_rationale=("Medium: asymmetric paths break stateful devices (firewalls, load balancers without SNAT) and also "
                            "limit what this capture can prove."),
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        hits = []
        for fl in ctx.tcp_flows:
            if fl.packets["c2s"] and not fl.packets["s2c"] and fl.max_ack_c2s > 1:
                hits.append((fl, "c2s"))
            elif fl.packets["s2c"] and not fl.packets["c2s"] and fl.max_ack_s2c > 1:
                hits.append((fl, "s2c"))
        out = []
        for fl, d in hits:
            seen = fl.client if d == "c2s" else fl.server
            unseen = fl.server if d == "c2s" else fl.client
            acked = (fl.max_ack_c2s if d == "c2s" else fl.max_ack_s2c) - 1
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"t{fl.stream}",
                title=f"Return traffic from {ep(unseen)} is not visible (asymmetric path?)",
                severity="medium",
                confidence=Confidence("high", 0.85, f"{ep(seen)} acknowledged {acked} bytes that never appeared in the capture, "
                                      "so those packets exist but bypassed this capture point."),
                summary=f"Only packets from {ep(seen)} were captured in conversation t{fl.stream}, yet it acknowledges {acked} "
                        f"bytes sent by {ep(unseen)}.",
                observations=[
                    Observation(f"{fl.packets[d]} packet(s) from {ep(seen)}, none from {ep(unseen)}."),
                    Observation(f"Highest acknowledgement number sent by {ep(seen)}: {acked + 1} (relative), i.e. {acked} bytes received."),
                    Observation(f"Segments acknowledging unseen data: {frames_text(fl.ack_lost.frames())}.", fl.ack_lost.frames()),
                ],
                assessment="The packets from the other side reach the host by a path that does not pass this capture point.",
                probable_cause="Asymmetric routing between the capture point and the remote endpoint.",
                alternatives=["One-directional SPAN/mirror configuration", "Capture filter excluding the return direction",
                              "If a BIG-IP is in path: server responses bypass the BIG-IP because SNAT is not used and the server's "
                              "default gateway is not the BIG-IP (classic asymmetric load-balancing issue)."],
                verification=[C.cmd("Check the route back to the client from the server", f"ip route get {fl.client[0]}", "Server (Linux)"),
                              C.cmd("Check whether the virtual server uses SNAT", "tmsh list ltm virtual <virtual_name> source-address-translation", "BIG-IP (tmsh)"),
                              C.generic_tcpdump(fl.client[0], fl.server[0], fl.server[1])],
                remediation=[{"action": "Make the return path symmetric (correct routes) or enable SNAT (Auto Map / SNAT pool) on the virtual server.",
                              "risk": "SNAT hides the client IP from servers; use X-Forwarded-For if the application needs it."}],
                missing_evidence=["Capture on the return path", "Routing tables of the server and intermediate routers"],
                packets=[{"frame": f, "ts_ns": t, "role": "ACK for unseen data"} for f, t in fl.ack_lost.refs]
                + [{"frame": fl.first_frame, "ts_ns": fl.first_ts, "role": "first packet"}],
                flows=[f"t{fl.stream}"],
                tuples=[tuple_of(fl)],
                timeline=tcp_timeline(fl),
                metrics={"visible_direction": "client→server" if d == "c2s" else "server→client", "unseen_bytes_acked": acked},
                f5_relevance=ctx.bigip_hint(fl.server[0]),
            ))
        return out


class IdleTimeout(Rule):
    meta = RuleMeta(
        rule_id="TCP-010",
        version="1.0.0",
        title="Connection closed after a long idle period",
        category="tcp",
        default_severity="low",
        required_evidence=["Inter-packet gap of 30 s or more", "RST or FIN as the first packet after the gap"],
        detection_logic="Report conversations whose largest idle gap is at least 30 s and whose next packet after the gap is a RST or FIN.",
        limitations=["The capture shows the timing pattern only; the device enforcing the timeout must be confirmed from its configuration."],
        false_positives=["Applications that deliberately close idle connections"],
        severity_rationale="Low: timeouts are often intended, but mismatched timeouts cause intermittent errors on reused connections.",
        parameters={"min_idle_s": 30},
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        out = []
        for fl in ctx.tcp_flows:
            if fl.max_gap_ns < 30_000_000_000 or not fl.max_gap_frames:
                continue
            after = fl.max_gap_frames[1]
            close = next((r for r in fl.rsts if r["frame"] == after), None) or next((f for f in fl.fins if f["frame"] == after), None)
            if not close:
                continue
            kind = "RST" if close in fl.rsts else "FIN"
            sender = fl.client if close["dir"] == "c2s" else fl.server
            idle_s = fl.max_gap_ns / 1e9
            common = [t for t in (60, 120, 180, 300, 600, 900, 1800, 3600) if abs(idle_s - t) <= max(2, t * 0.02)]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"t{fl.stream}",
                title=f"{kind} from {ep(sender)} after {idle_s:.0f} s idle",
                severity="low",
                confidence=Confidence("medium", 0.6, "The idle gap and the closing packet are measured directly; which device "
                                      "enforces the timeout is an inference."),
                summary=f"Conversation t{fl.stream} was idle for {idle_s:.1f} s and then {ep(sender)} closed it with {kind}.",
                observations=[Observation(f"No packets between #{fl.max_gap_frames[0]} and #{after} ({ms(fl.max_gap_ns)}).",
                                          list(fl.max_gap_frames)),
                              Observation(f"Frame #{after} is a {kind} from {ep(sender)}.", [after])]
                + ([Observation(f"The idle period is within 2% of a common timeout value ({common[0]} s).")] if common else []),
                assessment="The timing matches an idle-timeout expiring on an endpoint or an intermediate device.",
                probable_cause=f"Idle timeout of ~{common[0] if common else round(idle_s)} s on {ep(sender)} or a stateful device in path.",
                alternatives=["If a BIG-IP is in path: TCP/FastL4 profile idle-timeout (default 300 s) with reset-on-timeout enabled",
                              "Firewall session timeout", "Application keep-alive timeout"],
                verification=[C.cmd("Check profile idle timeouts", "tmsh list ltm profile tcp all idle-timeout reset-on-timeout; "
                                    "tmsh list ltm profile fastl4 all idle-timeout reset-on-timeout", "BIG-IP (tmsh)")],
                remediation=[{"action": "Align idle timeouts so the client/application side times out before intermediate devices, "
                                        "or enable TCP keep-alives.", "risk": "Longer timeouts consume connection-table memory."}],
                missing_evidence=["Timeout configuration of firewalls / load balancers in path"],
                packets=[{"frame": fl.max_gap_frames[0], "ts_ns": 0, "role": "last packet before idle"},
                         {"frame": after, "ts_ns": close["ts_ns"], "role": kind}],
                flows=[f"t{fl.stream}"],
                tuples=[tuple_of(fl)],
                timeline=tcp_timeline(fl),
                metrics={"idle_seconds": round(idle_s, 3), "closed_with": kind},
                f5_relevance=ctx.bigip_hint(fl.server[0]),
            ))
        return out


class SynAckNotAcknowledged(Rule):
    meta = RuleMeta(
        rule_id="TCP-011",
        version="1.0.0",
        title="SYN-ACK sent but handshake never completes",
        category="tcp",
        default_severity="high",
        required_evidence=["SYN-ACK from server (often retransmitted)", "No final ACK from the client"],
        detection_logic="Report conversations with at least one SYN-ACK, no handshake-completing ACK and no client data.",
        limitations=["If the capture is on the server, it cannot show whether the SYN-ACK reached the client."],
        false_positives=["SYN floods with spoofed sources (many sources, one SYN each)"],
        severity_rationale="High: the server accepted the connection but the client never learns of it, so the connection fails.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        hits = [fl for fl in ctx.tcp_flows if fl.synack_count and not fl.handshake_complete and not fl.payload["c2s"]
                and not (fl.synack_count == 1 and ctx.near_end(fl.synacks[0]["ts_ns"]))]
        out = []
        for server, flows in _group_by_server(hits).items():
            sa = [s for fl in flows for s in fl.synacks]
            retr = [s for s in sa if s["retrans"]]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}",
                title=f"Handshakes with {ep(server)} never complete",
                severity="high",
                confidence=Confidence("medium" if not retr else "high", 0.6 if not retr else 0.8,
                                      "SYN-ACK retransmissions show the server never received the final ACK."
                                      if retr else "No final ACK was captured; it may have been sent on another path."),
                summary=f"{ep(server)} answered {len(flows)} SYN(s) with SYN-ACK ({len(retr)} retransmitted) but no client ever completed the handshake.",
                observations=[Observation(f"SYN-ACKs: {frames_text([s['frame'] for s in sa])}.", [s["frame"] for s in sa]),
                              Observation(f"SYN-ACK retransmissions: {len(retr)}.", [s["frame"] for s in retr]),
                              Observation("No ACK or data from the client followed in these conversations.")],
                assessment="The server's SYN-ACK is not reaching the client, or the client's ACK is not reaching the server.",
                probable_cause="Return-path problem: the SYN-ACK is routed away from the client's path (e.g. server default gateway "
                               "bypasses the load balancer/firewall that saw the SYN) or is dropped by a stateful device.",
                alternatives=["If a BIG-IP is in path without SNAT: the pool member replies directly to the client, bypassing "
                              "BIG-IP, so the client rejects/ignores the unexpected SYN-ACK.",
                              "Client-side firewall dropping the SYN-ACK", "Spoofed SYN traffic (SYN flood)"],
                verification=[C.cmd("Check the server's route back to the client", f"ip route get {flows[0].client[0]}", "Server (Linux)"),
                              C.cmd("Check SNAT on the virtual server", "tmsh list ltm virtual <virtual_name> source-address-translation", "BIG-IP (tmsh)")],
                remediation=[{"action": "Ensure replies return through the same stateful devices (SNAT or symmetric routing).",
                              "risk": "Routing changes on servers can affect other services."}],
                missing_evidence=["Client-side capture to see whether SYN-ACKs arrive"],
                packets=[{"frame": s["frame"], "ts_ns": s["ts_ns"], "role": "SYN-ACK"} for s in sa]
                + [{"frame": s["frame"], "ts_ns": s["ts_ns"], "role": "SYN"} for fl in flows for s in fl.syns],
                flows=[f"t{fl.stream}" for fl in flows],
                tuples=[tuple_of(fl) for fl in flows],
                timeline=[e for fl in flows[:5] for e in tcp_timeline(fl)],
                metrics={"connections": len(flows), "synack_retransmissions": len(retr)},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


TCP_RULES: list[type[Rule]] = [UnansweredSyn, SynRejected, Retransmissions, DuplicateAcks, ZeroWindow, UnexpectedReset,
                               SlowHandshake, PmtudProblem, OneDirectional, IdleTimeout, SynAckNotAcknowledged]
