"""DNS / BIG-IP DNS (GTM) troubleshooting rules."""

from __future__ import annotations

from collections import defaultdict

from ..state import DNS_RCODES, DnsTxn
from . import commands as C
from .base import Confidence, FindingDraft, Observation, Rule, RuleMeta
from .context import RuleContext, ep, frames_text, ms

GTM_NOTE = ("DNS packets alone cannot show BIG-IP DNS wide-IP or pool decisions; correlate with 'tmsh show gtm wideip' "
            "statistics and /var/log/gtm when a BIG-IP DNS listener is involved.")


def _dns_timeline(txns: list[DnsTxn], limit: int = 40) -> list[dict]:
    ev = []
    for t in txns[:limit]:
        ev.append({"ts_ns": t.query_ts, "frame": t.query_frame, "dir": "c2s",
                   "event": f"query 0x{t.txid:04x} {t.qtype or ''} {t.qname} → {ep(t.server)}"})
        if t.response_frame:
            ev.append({"ts_ns": t.response_ts, "frame": t.response_frame, "dir": "s2c",
                       "event": f"response 0x{t.txid:04x} {DNS_RCODES.get(t.rcode, t.rcode)} after {ms(t.latency_ns)}"
                       + (" (truncated)" if t.truncated else "")})
    return sorted(ev, key=lambda e: e["ts_ns"])


def _dns_tuple(t: DnsTxn) -> dict:
    return {"src": t.client[0], "sport": t.client[1], "dst": t.server[0], "dport": t.server[1], "proto": t.transport}


class DnsUnanswered(Rule):
    meta = RuleMeta(
        rule_id="DNS-001",
        version="1.1.0",
        title="DNS queries without a response",
        category="dns",
        default_severity="high",
        required_evidence=["DNS queries", "No response with the same transaction ID, client port and server"],
        detection_logic=("Match responses to queries on (client IP, client port, server IP, server port, transaction ID, name). "
                         "Report (server, name) pairs with unanswered queries, ignoring queries sent within 2 s of capture end."),
        limitations=["If responses return on a path that bypasses the capture point, every query looks unanswered.",
                     "Resolvers may answer from a different source address (misconfiguration) which this rule treats as no answer."],
        false_positives=["Captures stopped right after queries", "Queries to unreachable secondary resolvers that clients then abandon"],
        severity_rationale="High: unanswered lookups delay or break every application that depends on the name.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list[DnsTxn]] = defaultdict(list)
        answered_servers: dict[str, int] = defaultdict(int)
        for t in ctx.agg.dns_txns:
            if t.response_frame:
                answered_servers[t.server[0]] += 1
            elif not ctx.agg.dns_is_near_end(t, ctx.capture_end_ns):
                groups[(t.server, t.qname)].append(t)
        out = []
        for (server, qname), txns in groups.items():
            frames = [t.query_frame for t in txns]
            others = answered_servers.get(server[0], 0)
            other_resolvers = sorted({t.server[0] for t in ctx.agg.dns_txns if t.qname == qname and t.response_frame and t.server != server})
            if others:
                cause = (f"{server[0]} answers other queries in this capture, so it is reachable; resolution of {qname} specifically "
                         "fails (e.g. upstream forwarder or authoritative server for that zone not responding).")
                conf = Confidence("high", 0.8, "Other queries to the same resolver were answered, so the capture point sees responses.")
            else:
                cause = f"The resolver {server[0]} is unreachable or not running, or its responses take another path."
                conf = Confidence("medium" if len(txns) > 1 else "low", 0.6 if len(txns) > 1 else 0.35,
                                  "No response from this resolver was seen at all, which may also be explained by one-directional capture.")
            retries = len(txns) - 1
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{qname}",
                title=f"No DNS response for {qname} from {server[0]}",
                severity="high",
                confidence=conf,
                summary=f"{len(txns)} quer{'y' if len(txns) == 1 else 'ies'} for {qname} to {ep(server)} got no response"
                        + (f" ({retries} retr{'y' if retries == 1 else 'ies'})." if retries else "."),
                observations=[
                    Observation(f"Unanswered queries for {qname} ({txns[0].qtype or '?'}): {frames_text(frames)}; transaction IDs "
                                f"{', '.join(f'0x{t.txid:04x}' for t in txns[:6])}.", frames),
                    Observation(f"Queries span {ms(txns[-1].query_ts - txns[0].query_ts)}."),
                    Observation(f"{others} other quer{'y' if others == 1 else 'ies'} to {server[0]} were answered in this capture."),
                ] + ([Observation(f"{qname} was resolved successfully via {', '.join(other_resolvers)}.")] if other_resolvers else []),
                assessment="The client retried the lookup and never received an answer through the capture point.",
                probable_cause=cause,
                alternatives=["Firewall blocking UDP/53 responses", "Resolver rate-limiting this client",
                              "If the resolver is a BIG-IP DNS listener: the wide IP has no available pool members and no "
                              "fallback, or a DNS cache/forwarder upstream does not answer. " + GTM_NOTE],
                verification=[C.dig(server[0], qname, txns[0].qtype or "A"), C.dig(server[0], qname, txns[0].qtype or "A", tcp=True),
                              C.cmd("Check wide IP status (BIG-IP DNS)", f"tmsh show gtm wideip a {qname}", "BIG-IP DNS (tmsh)"),
                              C.cmd("Check the DNS listener statistics", "tmsh show ltm virtual <dns_listener>", "BIG-IP (tmsh)")],
                remediation=[{"action": "Restore resolver/forwarder reachability or the authoritative path for this zone; "
                                        "ensure clients have a working secondary resolver.",
                              "risk": "Changing client resolvers can alter split-horizon results."}],
                missing_evidence=["Resolver logs / query log", "Capture on the resolver to see whether queries arrive"],
                packets=[{"frame": t.query_frame, "ts_ns": t.query_ts, "role": "unanswered query"} for t in txns],
                tuples=[_dns_tuple(t) for t in txns[:20]],
                timeline=_dns_timeline(txns),
                metrics={"queries": len(txns), "retries": retries, "resolver_answers_other_queries": others,
                         "resolved_elsewhere": other_resolvers},
            ))
        return out


class DnsErrorRcode(Rule):
    meta = RuleMeta(
        rule_id="DNS-002",
        version="1.0.0",
        title="DNS server failures and refusals",
        category="dns",
        default_severity="high",
        required_evidence=["DNS responses with RCODE SERVFAIL(2), REFUSED(5), FORMERR(1) or NOTIMP(4)"],
        detection_logic="Group error responses by (server, RCODE) and report each group.",
        limitations=["The capture does not show which upstream step failed inside the resolver."],
        false_positives=["DNSSEC validation failures for deliberately broken test zones"],
        severity_rationale="High for SERVFAIL/REFUSED: the client receives no usable answer.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list[DnsTxn]] = defaultdict(list)
        for t in ctx.agg.dns_txns:
            if t.rcode in (1, 2, 4, 5):
                groups[(t.server, t.rcode)].append(t)
        out = []
        for (server, rcode), txns in groups.items():
            name = DNS_RCODES[rcode]
            names = sorted({t.qname for t in txns})
            cause = {
                "SERVFAIL": "The resolver could not complete resolution (upstream/authoritative unreachable, DNSSEC validation failure, "
                            "or lame delegation).",
                "REFUSED": "The server's policy refuses this client or this zone (recursion disabled, ACL, or not authoritative).",
                "FORMERR": "The server could not parse the query (often EDNS incompatibility on middleboxes).",
                "NOTIMP": "The server does not implement the requested query type/opcode.",
            }[name]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{name}",
                title=f"{name} responses from {server[0]}",
                severity="high" if name in ("SERVFAIL", "REFUSED") else "medium",
                confidence=Confidence("high", 0.9, "The response code is read directly from the DNS header."),
                summary=f"{server[0]} returned {name} for {len(txns)} quer{'y' if len(txns) == 1 else 'ies'} ({', '.join(names[:5])}).",
                observations=[Observation(f"{name} responses: {frames_text([t.response_frame for t in txns])}.", [t.response_frame for t in txns]),
                              Observation(f"Names affected: {', '.join(names[:10])}.")],
                assessment=f"The server answered, but with {name}: {cause}",
                probable_cause=cause,
                alternatives=["If the server is a BIG-IP DNS listener: the wide IP is disabled or the DNS profile disallows recursion. " + GTM_NOTE],
                verification=[C.dig(server[0], names[0]), C.cmd("Trace delegation", f"dig +trace {names[0]}", "Client-side host")],
                remediation=[{"action": "Fix the resolver's upstream path, ACLs or zone configuration according to the RCODE.",
                              "risk": "Opening recursion to more clients can create an open resolver; restrict by ACL."}],
                missing_evidence=["Resolver logs explaining the failure"],
                packets=[{"frame": t.response_frame, "ts_ns": t.response_ts, "role": name} for t in txns]
                + [{"frame": t.query_frame, "ts_ns": t.query_ts, "role": "query"} for t in txns],
                tuples=[_dns_tuple(t) for t in txns[:20]],
                timeline=_dns_timeline(txns),
                metrics={"rcode": name, "responses": len(txns), "names": names[:20]},
            ))
        return out


class DnsNxdomain(Rule):
    meta = RuleMeta(
        rule_id="DNS-003",
        version="1.0.0",
        title="Names that do not exist (NXDOMAIN)",
        category="dns",
        default_severity="low",
        required_evidence=["DNS responses with RCODE NXDOMAIN(3)"],
        detection_logic="Group NXDOMAIN responses by queried name.",
        limitations=["NXDOMAIN is often expected (search-domain expansion, typos, malware probes)."],
        false_positives=["Search-list expansion queries (name.corp.example) followed by a successful absolute query"],
        severity_rationale="Low: usually expected; important only when an application depends on the name.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[str, list[DnsTxn]] = defaultdict(list)
        for t in ctx.agg.dns_txns:
            if t.rcode == 3:
                groups[t.qname].append(t)
        out = []
        for qname, txns in groups.items():
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=qname,
                title=f"NXDOMAIN for {qname}",
                severity="low",
                confidence=Confidence("high", 0.9, "The response code is read directly from the DNS header."),
                summary=f"{len(txns)} lookup(s) for {qname} returned NXDOMAIN (name does not exist).",
                observations=[Observation(f"NXDOMAIN responses from {', '.join(sorted({t.server[0] for t in txns}))}: "
                                          f"{frames_text([t.response_frame for t in txns])}.", [t.response_frame for t in txns])],
                assessment="The resolver states that the name does not exist.",
                probable_cause="Misspelled or retired name, missing record in the zone, or search-domain expansion.",
                alternatives=["Split-horizon DNS: the name exists only in another view"],
                verification=[C.dig(txns[0].server[0], qname)],
                remediation=[{"action": "Correct the application's configured hostname or add the missing record.", "risk": "None."}],
                missing_evidence=[],
                packets=[{"frame": t.response_frame, "ts_ns": t.response_ts, "role": "NXDOMAIN"} for t in txns],
                tuples=[_dns_tuple(t) for t in txns[:20]],
                timeline=_dns_timeline(txns),
                metrics={"responses": len(txns)},
            ))
        return out


class DnsSlow(Rule):
    meta = RuleMeta(
        rule_id="DNS-004",
        version="1.0.0",
        title="Slow DNS responses",
        category="dns",
        default_severity="medium",
        required_evidence=["Matched DNS query/response timestamps"],
        detection_logic="Report resolvers with responses slower than 500 ms.",
        limitations=["Latency is measured at the capture point, not at the client application."],
        false_positives=["First (uncached) lookups of distant authoritative zones"],
        severity_rationale="Medium: every connection to the name waits for the lookup.",
        parameters={"threshold_ms": 500},
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list[DnsTxn]] = defaultdict(list)
        for t in ctx.agg.dns_txns:
            if t.latency_ns is not None and t.latency_ns > 500_000_000:
                groups[t.server].append(t)
        out = []
        for server, txns in groups.items():
            worst = max(txns, key=lambda t: t.latency_ns or 0)
            fast = [t.latency_ns for t in ctx.agg.dns_txns if t.server == server and t.latency_ns is not None and t.latency_ns <= 500_000_000]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=server[0],
                title=f"Slow DNS responses from {server[0]}",
                severity="medium",
                confidence=Confidence("high", 0.85, "Latency is computed from matched query and response timestamps."),
                summary=f"{len(txns)} response(s) from {server[0]} took over 500 ms (worst {ms(worst.latency_ns)} for {worst.qname}).",
                observations=[Observation(f"Slowest: {worst.qname} query #{worst.query_frame} → response #{worst.response_frame} in "
                                          f"{ms(worst.latency_ns)}.", [worst.query_frame, worst.response_frame or 0]),
                              Observation(f"{len(fast)} other response(s) from this server were under 500 ms.")],
                assessment="The resolver is slow for some or all names.",
                probable_cause="Cache misses resolving through slow or lossy upstream servers, or an overloaded resolver.",
                alternatives=["Upstream forwarder timeouts followed by retry to another forwarder"],
                verification=[C.dig(server[0], worst.qname)],
                remediation=[{"action": "Check resolver load and upstream forwarder health; consider closer forwarders.",
                              "risk": "Forwarder changes alter resolution paths for all clients."}],
                missing_evidence=["Resolver performance metrics"],
                packets=[{"frame": t.query_frame, "ts_ns": t.query_ts, "role": "query"} for t in txns]
                + [{"frame": t.response_frame, "ts_ns": t.response_ts, "role": "slow response"} for t in txns],
                tuples=[_dns_tuple(t) for t in txns[:20]],
                timeline=_dns_timeline(txns),
                metrics={"slow_responses": len(txns), "worst_ms": round((worst.latency_ns or 0) / 1e6, 2)},
            ))
        return out


class DnsTruncated(Rule):
    meta = RuleMeta(
        rule_id="DNS-005",
        version="1.0.0",
        title="Truncated DNS responses and TCP fallback",
        category="dns",
        default_severity="medium",
        required_evidence=["UDP responses with the TC bit", "Presence or absence of a TCP/53 query for the same name"],
        detection_logic="For each truncated UDP response, look for a later TCP DNS query for the same name from the same client.",
        limitations=["A TCP retry may go to a different resolver than the one captured."],
        false_positives=["Large DNSSEC/TXT answers where truncation is expected"],
        severity_rationale="Medium: if TCP fallback is blocked, large answers never reach the client.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        truncated = [t for t in ctx.agg.dns_txns if t.truncated and t.transport == "udp"]
        if not truncated:
            return []
        tcp_names = {(t.client[0], t.qname): t for t in ctx.agg.dns_txns if t.transport == "tcp"}
        out = []
        groups: dict[tuple, list[DnsTxn]] = defaultdict(list)
        for t in truncated:
            groups[t.server].append(t)
        for server, txns in groups.items():
            fallback = [tcp_names[(t.client[0], t.qname)] for t in txns if (t.client[0], t.qname) in tcp_names]
            missing = len(txns) - len(fallback)
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=server[0],
                title=f"Truncated DNS answers from {server[0]}" + (" without TCP retry" if missing else ""),
                severity="medium" if missing else "low",
                confidence=Confidence("high", 0.8, "The TC flag and TCP/53 queries are observed directly."),
                summary=f"{len(txns)} UDP response(s) were truncated; {len(fallback)} were retried over TCP.",
                observations=[Observation(f"Truncated responses: {frames_text([t.response_frame for t in txns])}.", [t.response_frame for t in txns]),
                              Observation(f"EDNS buffer sizes advertised: {sorted({t.edns_size for t in txns if t.edns_size}) or 'none'}."),
                              Observation(f"TCP fallback queries: {frames_text([f.query_frame for f in fallback])}.", [f.query_frame for f in fallback])],
                assessment="Answers are larger than the UDP size the client advertised." + (" Some clients did not retry over TCP." if missing else ""),
                probable_cause="Large responses (DNSSEC, many records) and" + (" TCP/53 blocked or not attempted." if missing else " normal TCP fallback."),
                alternatives=["Middlebox stripping EDNS options, forcing 512-byte UDP limit"],
                verification=[C.dig(server[0], txns[0].qname, tcp=True)],
                remediation=[{"action": "Permit TCP/53 between clients and resolvers; avoid EDNS buffer sizes above 1232 bytes.",
                              "risk": "None significant."}],
                missing_evidence=[],
                packets=[{"frame": t.response_frame, "ts_ns": t.response_ts, "role": "truncated response"} for t in txns],
                tuples=[_dns_tuple(t) for t in txns[:20]],
                timeline=_dns_timeline(txns),
                metrics={"truncated": len(txns), "tcp_fallback": len(fallback)},
            ))
        return out


DNS_RULES: list[type[Rule]] = [DnsUnanswered, DnsErrorRcode, DnsNxdomain, DnsSlow, DnsTruncated]
