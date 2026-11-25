"""HTTP and application-delivery rules, including observable ASM/AWAF and APM patterns."""

from __future__ import annotations

from collections import defaultdict

from ..state import APM_COOKIE_NAMES, APM_PATH_HINTS, ASM_COOKIE_PREFIX, HttpTxn, TcpFlow
from . import commands as C
from .base import Confidence, FindingDraft, Observation, Rule, RuleMeta
from .context import RuleContext, ep, frames_text, ms, tcp_timeline, tuple_of

POLICY_LIMITATION = ("A packet capture cannot establish the exact ASM/AWAF violation, policy decision or APM session failure; "
                     "confirm with BIG-IP ASM request logs / APM session logs and the relevant policy configuration.")


def _txns(ctx: RuleContext) -> list[tuple[TcpFlow, HttpTxn]]:
    return [(fl, h) for fl in ctx.tcp_flows for h in fl.http]


def _http_timeline(items: list[tuple[TcpFlow, HttpTxn]], limit: int = 40) -> list[dict]:
    ev = []
    for fl, h in items[:limit]:
        if h.req_frame:
            ev.append({"ts_ns": h.req_ts, "frame": h.req_frame, "dir": "c2s", "event": f"{h.method} {h.host or ''}{h.path} (t{fl.stream})"})
        if h.first_byte_frame and h.first_byte_frame != h.resp_frame:
            ev.append({"ts_ns": h.first_byte_ts, "frame": h.first_byte_frame, "dir": "s2c", "event": f"first response byte after {ms(h.ttfb_ns)}"})
        if h.resp_frame:
            ev.append({"ts_ns": h.resp_ts, "frame": h.resp_frame, "dir": "s2c", "event": f"{h.status} {h.phrase or ''} after {ms(h.latency_ns)}"})
    return sorted(ev, key=lambda e: e["ts_ns"])


def _uses_tls(fl: TcpFlow) -> bool:
    return fl.tls is not None


class HttpServerErrors(Rule):
    meta = RuleMeta(
        rule_id="HTTP-001",
        version="1.1.0",
        title="HTTP 5xx server errors",
        category="http",
        default_severity="high",
        required_evidence=["Cleartext (or decrypted) HTTP responses with status 500-599"],
        detection_logic="Group 5xx responses by server endpoint and Host header.",
        limitations=["Encrypted HTTPS traffic is only covered when decryption material was supplied."],
        false_positives=["Planned maintenance pages returned with 503"],
        severity_rationale="High: users receive an error page instead of content.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list] = defaultdict(list)
        for fl, h in _txns(ctx):
            if h.status and 500 <= h.status <= 599:
                groups[(fl.server, h.host)].append((fl, h))
        out = []
        for (server, host), items in groups.items():
            codes = sorted({h.status for _, h in items})
            servers = sorted({h.server for _, h in items if h.server})
            bigip_generated = any(s and "big" in s.lower() and "ip" in s.lower() for s in servers)
            frames = [h.resp_frame for _, h in items]
            fl0, h0 = items[0]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}:{host}",
                title=f"HTTP {', '.join(map(str, codes))} from {host or ep(server)}",
                severity="high",
                confidence=Confidence("high", 0.9, "Status codes are read directly from HTTP responses."),
                summary=f"{len(items)} request(s) to {host or ep(server)} returned server errors ({', '.join(map(str, codes))}).",
                observations=[Observation(f"Error responses: {frames_text(frames)}.", frames),
                              Observation("Requests: " + "; ".join(f"#{h.req_frame} {h.method} {h.path} → {h.status}" for _, h in items[:5]) + ".",
                                          [h.req_frame for _, h in items[:5]])]
                + ([Observation(f"Server header(s): {', '.join(servers)}.")] if servers else []),
                assessment="The server (or a proxy in front of it) reported that it could not fulfil the requests.",
                probable_cause=("Upstream application unavailable or failing" + (" — 503 suggests no healthy backend." if 503 in codes else ".")),
                alternatives=["A reverse proxy/load balancer generating the error because its backend failed",
                              "If a BIG-IP is in path: an iRule HTTP::respond or the fallback host behaviour when the pool has no "
                              "available members" + (" (the Server header suggests the BIG-IP generated this response)." if bigip_generated else ".")],
                verification=[C.curl_timing(host, server[0], server[1], h0.path, _uses_tls(fl0)), C.bigip_pool_members(),
                              C.cmd("Check application/server error logs at the response time", "grep ' 50[0-9] ' /var/log/<web>/access.log", "Server")],
                remediation=[{"action": "Fix the failing backend or restore pool member health; add retries only for idempotent requests.",
                              "risk": "Automatic retries of non-idempotent requests can duplicate transactions."}],
                missing_evidence=["Backend application logs", "BIG-IP pool member status at the time"],
                packets=[{"frame": h.resp_frame, "ts_ns": h.resp_ts, "role": f"HTTP {h.status}"} for _, h in items]
                + [{"frame": h.req_frame, "ts_ns": h.req_ts, "role": "request"} for _, h in items if h.req_frame],
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=_http_timeline(items),
                metrics={"errors": len(items), "codes": codes, "host": host},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


class HttpSlowResponse(Rule):
    meta = RuleMeta(
        rule_id="HTTP-002",
        version="1.1.0",
        title="Slow HTTP responses",
        category="http",
        default_severity="medium",
        required_evidence=["Request timestamp", "First response byte timestamp", "Response completion timestamp"],
        detection_logic=("Report requests whose response took more than 2 s. The time to first byte (TTFB) separates "
                         "server think-time from transfer time."),
        limitations=["Response time is measured to the frame where the HTTP dissector completed the response, "
                     "which for large bodies is the last segment."],
        false_positives=["Long-polling or streaming endpoints", "Large downloads"],
        severity_rationale="Medium: users wait; the service still responds.",
        parameters={"threshold_ms": 2000},
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list] = defaultdict(list)
        for fl, h in _txns(ctx):
            if h.latency_ns and h.latency_ns > 2_000_000_000:
                groups[fl.server].append((fl, h))
        out = []
        for server, items in groups.items():
            fl0, worst = max(items, key=lambda i: i[1].latency_ns or 0)
            server_stall = worst.ttfb_ns is not None and worst.ttfb_ns > 0.8 * (worst.latency_ns or 1)
            obs = [Observation(f"Slowest: #{worst.req_frame} {worst.method} {worst.host or ''}{worst.path} → {worst.status} at "
                               f"#{worst.resp_frame} after {ms(worst.latency_ns)}; first byte after {ms(worst.ttfb_ns)}.",
                               [worst.req_frame, worst.resp_frame or 0]),
                   Observation(f"{len(items)} request(s) to {ep(server)} exceeded 2 s.")]
            fast = [h for f, h in _txns(ctx) if f.server == server and h.latency_ns is not None and h.latency_ns <= 2_000_000_000]
            if fast:
                obs.append(Observation(f"{len(fast)} other request(s) on the same server completed within 2 s "
                                       f"(e.g. #{fast[0].req_frame} {fast[0].path} in {ms(fast[0].latency_ns)})."))
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}",
                title=f"Slow responses from {ep(server)} (up to {ms(worst.latency_ns)})",
                severity="medium",
                confidence=Confidence("high", 0.8, "Timings come from packet timestamps on the same capture point."),
                summary=f"{len(items)} HTTP request(s) to {ep(server)} took longer than 2 s; worst {worst.path} took {ms(worst.latency_ns)}.",
                observations=obs,
                assessment=("Almost all of the delay happened before the first response byte, i.e. the server was processing "
                            "(TCP stayed healthy)." if server_stall else
                            "The server started answering quickly but the transfer itself was slow."),
                probable_cause=("Server-side stall: slow application, database or upstream dependency for this request."
                                if server_stall else "Slow data transfer: throughput limited by loss, window size or bandwidth."),
                alternatives=["Server overloaded (all requests slow) vs. specific endpoint slow (only some URIs) — compare URIs",
                              "If a BIG-IP is in path: compare client-side and server-side captures to see whether the delay is "
                              "before or after the BIG-IP; check OneConnect/connection reuse and pool member load."],
                verification=[C.curl_timing(worst.host, server[0], server[1], worst.path, _uses_tls(fl0)),
                              C.cmd("Compare server-side timing on BIG-IP", "tmsh show ltm pool <pool_name> members field-fmt | grep -E 'cur-conns|serverside'", "BIG-IP (tmsh)")],
                remediation=[{"action": "Profile the slow endpoint on the server (APM/tracing); check its dependencies.",
                              "risk": "None from investigation."}],
                missing_evidence=["Server application timing logs for the request", "Server-side capture (behind any proxy)"],
                packets=[{"frame": h.req_frame, "ts_ns": h.req_ts, "role": "request"} for _, h in items if h.req_frame]
                + [{"frame": h.resp_frame, "ts_ns": h.resp_ts, "role": "slow response"} for _, h in items]
                + ([{"frame": worst.first_byte_frame, "ts_ns": worst.first_byte_ts, "role": "first byte"}] if worst.first_byte_frame else []),
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=_http_timeline(items),
                metrics={"slow_requests": len(items), "worst_ms": round((worst.latency_ns or 0) / 1e6, 1),
                         "worst_ttfb_ms": round((worst.ttfb_ns or 0) / 1e6, 1), "server_stall": server_stall, "worst_path": worst.path},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


class HttpIncomplete(Rule):
    meta = RuleMeta(
        rule_id="HTTP-003",
        version="1.0.0",
        title="HTTP requests without a response",
        category="http",
        default_severity="high",
        required_evidence=["HTTP request", "Connection closed (FIN/RST) or idle until capture end without a response"],
        detection_logic="Report requests with no matching response where the connection was later closed, or the request is older than 3 s at capture end.",
        limitations=["HTTP pipelining with out-of-order failures may misattribute responses."],
        false_positives=["Capture stopped while a long request was still being processed"],
        severity_rationale="High: the client never receives an answer.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list] = defaultdict(list)
        for fl, h in _txns(ctx):
            if h.resp_frame is None and h.req_frame and not ctx.near_end(h.req_ts):
                groups[fl.server].append((fl, h))
        out = []
        for server, items in groups.items():
            closes = [(fl, x) for fl, _ in items for x in fl.rsts + fl.fins]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}",
                title=f"{len(items)} HTTP request(s) to {ep(server)} never answered",
                severity="high",
                confidence=Confidence("medium", 0.7, "The request is visible and no response was captured on the same connection."),
                summary=f"{len(items)} HTTP request(s) to {ep(server)} received no response"
                        + (" before the connection was closed." if closes else "."),
                observations=[Observation("Requests: " + "; ".join(f"#{h.req_frame} {h.method} {h.path}" for _, h in items[:6]) + ".",
                                          [h.req_frame for _, h in items]),
                              Observation(f"Connection closes: {frames_text([x['frame'] for _, x in closes])}.", [x["frame"] for _, x in closes])],
                assessment="The server or an intermediary accepted the request but never answered it.",
                probable_cause="Application hang/crash, or a proxy/security device aborting the request.",
                alternatives=["If a BIG-IP is in path: ASM blocking with connection reset, iRule drop/reject, or server-side "
                              "connection failure to the pool member. " + POLICY_LIMITATION],
                verification=[C.bigip_rst_cause(), C.curl_timing(items[0][1].host, server[0], server[1], items[0][1].path, _uses_tls(items[0][0]))],
                remediation=[{"action": "Find the component that dropped the request using server/proxy logs.", "risk": "None."}],
                missing_evidence=["Server/proxy logs", "BIG-IP ASM request log (if ASM is enabled)"],
                packets=[{"frame": h.req_frame, "ts_ns": h.req_ts, "role": "unanswered request"} for _, h in items]
                + [{"frame": x["frame"], "ts_ns": x["ts_ns"], "role": "close"} for _, x in closes],
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=[e for fl, _ in items[:3] for e in tcp_timeline(fl)],
                metrics={"unanswered": len(items)},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


class HttpPolicyBlock(Rule):
    meta = RuleMeta(
        rule_id="HTTP-004",
        version="1.0.0",
        title="Response consistent with security-policy blocking (ASM/AWAF)",
        category="f5",
        default_severity="medium",
        required_evidence=["Cleartext HTTP response containing the BIG-IP ASM default blocking page text, or",
                           "403 response carrying ASM-style TS cookies"],
        detection_logic=("Detect the ASM/AWAF default blocking page ('The requested URL was rejected...') and extract its support ID; "
                         "separately report 403 responses that set TS* cookies."),
        limitations=[POLICY_LIMITATION, "Custom blocking pages are not recognised unless they keep the default text."],
        false_positives=["Applications that copy the default ASM blocking text", "403 from the application with unrelated TS* cookies"],
        severity_rationale="Medium: legitimate users may be blocked (false positive policy), or the block may be correct.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        blocks = [(fl, h) for fl, h in _txns(ctx) if h.asm_block_page]
        ts403 = [(fl, h) for fl, h in _txns(ctx) if not h.asm_block_page and h.status == 403
                 and any(n.startswith(ASM_COOKIE_PREFIX) for n in h.set_cookie_names + h.request_cookie_names)]
        out = []
        for items, strong in ((blocks, True), (ts403, False)):
            if not items:
                continue
            ids = sorted({h.asm_support_id for _, h in items if h.asm_support_id})
            fl0, _ = items[0]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key="asm-block-page" if strong else "asm-403",
                title="Requests blocked with the ASM/AWAF blocking page" if strong else "403 responses with ASM-style cookies",
                severity="medium",
                confidence=Confidence("high" if strong else "low", 0.85 if strong else 0.35,
                                      "The response body matches the default BIG-IP ASM blocking page." if strong else
                                      "Only the status code and cookie naming suggest ASM; the body was not a known blocking page."),
                summary=(f"{len(items)} response(s) are the BIG-IP ASM/AWAF default blocking page"
                         + (f" (support IDs {', '.join(ids[:5])})." if ids else ".")) if strong else
                f"{len(items)} 403 response(s) carry TS* cookies typically set by BIG-IP ASM/AWAF.",
                observations=[Observation("Blocked requests: " + "; ".join(f"#{h.req_frame} {h.method} {h.host or ''}{h.path}" for _, h in items[:6]) + ".",
                                          [h.req_frame for _, h in items]),
                              Observation(f"Blocking responses: {frames_text([h.resp_frame for _, h in items])}.", [h.resp_frame for _, h in items])]
                + ([Observation(f"Support IDs: {', '.join(ids)}.")] if ids else []),
                assessment="These responses are consistent with a web application firewall policy rejecting the requests.",
                probable_cause="A security policy violation was detected for these requests. Which violation cannot be determined from packets.",
                alternatives=["Application-generated 403 (authorization failure)", "Bot defense / DoS profile challenges"],
                verification=[C.cmd("Look up the support ID in the ASM request log", "Security ›› Event Logs ›› Application ›› Requests → filter Support ID",
                                    "BIG-IP Configuration utility"),
                              C.cmd("Find the request in the local ASM log", f"grep -E '{ids[0] if ids else '<support_id>'}' /var/log/asm", "BIG-IP (bash)")],
                remediation=[{"action": "Review the violation for each support ID; if it is a false positive, adjust the policy (e.g. learning suggestion, "
                                        "parameter/URL exception) instead of disabling enforcement.",
                              "risk": "Relaxing the policy can allow real attacks; scope exceptions narrowly."}],
                missing_evidence=["ASM request log entries for the support IDs", "Security policy configuration and enforcement mode"],
                packets=[{"frame": h.resp_frame, "ts_ns": h.resp_ts, "role": "blocking response"} for _, h in items]
                + [{"frame": h.req_frame, "ts_ns": h.req_ts, "role": "blocked request"} for _, h in items if h.req_frame],
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=_http_timeline(items),
                metrics={"responses": len(items), "support_ids": ids},
                f5_relevance=POLICY_LIMITATION,
            ))
        return out


class HttpAuthLoop(Rule):
    meta = RuleMeta(
        rule_id="HTTP-005",
        version="1.0.0",
        title="Repeated authentication redirects or challenges (APM / SSO)",
        category="f5",
        default_severity="medium",
        required_evidence=["Three or more redirects (301/302/303/307) from the same server to the same Location for one client, or",
                           "Three or more 401 responses with WWW-Authenticate", "APM cookie names or paths when visible"],
        detection_logic=("Per client and server, count redirects grouped by Location and 401 challenges. Mark APM involvement only "
                         "when APM cookie names (MRHSession, LastMRH_Session, F5_ST...) or APM paths (/my.policy, /vdesk/) are visible."),
        limitations=[POLICY_LIMITATION, "Redirect loops inside encrypted HTTPS are invisible without decryption."],
        false_positives=["Normal multi-step SSO flows that redirect a few times before succeeding"],
        severity_rationale="Medium: users cannot log in or are repeatedly prompted.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        redirects: dict[tuple, list] = defaultdict(list)
        challenges: dict[tuple, list] = defaultdict(list)
        for fl, h in _txns(ctx):
            if h.status in (301, 302, 303, 307, 308) and h.location:
                redirects[(fl.client[0], fl.server, h.location.split("?")[0])].append((fl, h))
            if h.status == 401 and h.www_authenticate:
                challenges[(fl.client[0], fl.server)].append((fl, h))
        out = []
        for key, items in list(redirects.items()) + list(challenges.items()):
            if len(items) < 3:
                continue
            is_redirect = len(key) == 3
            client, server = key[0], key[1]
            names = {n for _, h in items for n in h.set_cookie_names + h.request_cookie_names}
            apm_cookies = sorted(names & APM_COOKIE_NAMES)
            apm_paths = sorted({h.path for _, h in items if any(p in (h.path or "") for p in APM_PATH_HINTS)}
                               | ({key[2]} if is_redirect and any(p in key[2] for p in APM_PATH_HINTS) else set()))
            apm = bool(apm_cookies or apm_paths)
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{client}:{server[0]}:{server[1]}:{key[2] if is_redirect else '401'}",
                title=(f"Redirect loop to {key[2]} for {client}" if is_redirect else f"Repeated 401 challenges for {client}"),
                severity="medium",
                confidence=Confidence("medium", 0.6, "The repetition is observed; whether it is a loop or a slow multi-step login needs logs."),
                summary=(f"{client} was redirected to {key[2]} {len(items)} times by {ep(server)}" if is_redirect else
                         f"{client} received {len(items)} authentication challenges from {ep(server)}")
                + (" with APM session artefacts visible." if apm else "."),
                observations=[Observation(f"Responses: {frames_text([h.resp_frame for _, h in items])}.", [h.resp_frame for _, h in items])]
                + ([Observation(f"APM cookie names seen: {', '.join(apm_cookies)}.")] if apm_cookies else [])
                + ([Observation(f"APM paths seen: {', '.join(apm_paths)}.")] if apm_paths else []),
                assessment="The client keeps being sent back to authentication instead of reaching the application.",
                probable_cause="The session is not being established or recognised (cookie not stored/returned, session invalidated, "
                               "or the access policy keeps denying).",
                alternatives=["Client blocks third-party/session cookies", "Clock skew breaking SSO token validation",
                              "Kerberos/NTLM negotiation failure (for 401 loops)"]
                + (["APM access policy ending in Deny or session limits reached. " + POLICY_LIMITATION] if apm else []),
                verification=[C.cmd("Review APM session logs for this client", f"sessiondump --allkeys | grep -A3 {client}; grep {client} /var/log/apm",
                                    "BIG-IP (bash)")] if apm else
                [C.cmd("Check the identity provider / web server authentication logs for this client", f"grep {client} <auth log>", "Server")],
                remediation=[{"action": "Fix the session/cookie or policy problem identified in the logs.", "risk": "None from investigation."}],
                missing_evidence=["APM session log (if APM)" if apm else "Authentication server logs", "Browser developer-tools trace"],
                packets=[{"frame": h.resp_frame, "ts_ns": h.resp_ts, "role": f"HTTP {h.status}"} for _, h in items],
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=_http_timeline(items),
                metrics={"count": len(items), "apm_cookies": apm_cookies, "apm_paths": apm_paths},
                f5_relevance=POLICY_LIMITATION if apm else None,
            ))
        return out


HTTP_RULES: list[type[Rule]] = [HttpServerErrors, HttpSlowResponse, HttpIncomplete, HttpPolicyBlock, HttpAuthLoop]
