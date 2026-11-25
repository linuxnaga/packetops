"""TLS / SSL troubleshooting rules."""

from __future__ import annotations

from collections import defaultdict

from ..state import TcpFlow
from . import commands as C
from .base import Confidence, FindingDraft, Observation, Rule, RuleMeta
from .context import RuleContext, ep, frames_text, tcp_timeline, tuple_of

LEGACY = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}

ALERT_GUIDANCE = {
    "handshake_failure": ("No mutually acceptable cipher suite, protocol version, or required client certificate.",
                          ["Compare the ClientHello cipher list with the server's enabled ciphers",
                           "Client certificate required but not supplied"]),
    "protocol_version": ("The peer does not support the offered/selected protocol version.", ["Minimum TLS version policy on one side"]),
    "insufficient_security": ("The server requires stronger ciphers than the client offered.", ["Cipher policy mismatch"]),
    "certificate_expired": ("The certificate presented by the peer is outside its validity period.", ["Clock skew on the validating side"]),
    "unknown_ca": ("The validating side does not trust the certificate's issuer (missing chain or private CA).",
                   ["Intermediate certificate not sent by the server", "Client trust store lacks the CA"]),
    "bad_certificate": ("The certificate was rejected as corrupt or invalid.", ["Hostname or key-usage mismatch on some clients"]),
    "certificate_unknown": ("The certificate was rejected for an unspecified reason.", ["Hostname mismatch", "Untrusted chain"]),
    "unsupported_certificate": ("The certificate type is not supported by the peer.", ["ECDSA vs RSA certificate mismatch"]),
    "unrecognized_name": ("The server does not recognise the SNI name.", ["SNI-based profile/vhost selection lacks this name"]),
    "certificate_required": ("TLS 1.3 server requires a client certificate that was not provided.", []),
    "no_application_protocol": ("No common ALPN protocol.", ["HTTP/2-only server with HTTP/1.1-only client or vice versa"]),
    "decrypt_error": ("Handshake signature or Finished verification failed.", ["Key mismatch", "Middlebox tampering"]),
    "illegal_parameter": ("A handshake field was invalid or inconsistent.", ["Implementation bug", "Middlebox interference"]),
    "internal_error": ("The peer hit an internal error unrelated to the protocol.", ["Resource exhaustion", "HSM/key access failure"]),
    "access_denied": ("Valid certificate but access was denied by policy.", []),
    "close_notify": ("Orderly TLS shutdown.", []),
    "user_canceled": ("The handshake was cancelled by the user/application.", []),
}


def _sni(fl: TcpFlow) -> str | None:
    return fl.tls.client_hello.get("sni") if fl.tls and fl.tls.client_hello else None


class TlsHandshakeAlert(Rule):
    meta = RuleMeta(
        rule_id="TLS-001",
        version="1.2.0",
        title="TLS alert terminates the handshake",
        category="tls",
        default_severity="high",
        required_evidence=["Cleartext TLS alert record (content type 21) sent before any application data"],
        detection_logic=("Report fatal alerts and non-close_notify warning alerts seen before the first application-data record "
                         "of the conversation. Group by server endpoint, alert description and sending side."),
        limitations=["TLS 1.3 encrypts alerts sent after the ServerHello; those are not visible without decryption keys.",
                     "The alert name states the sender's reason category, not the exact configuration problem."],
        false_positives=["Clients probing protocol support (e.g. scanners) intentionally triggering alerts"],
        severity_rationale="High: a fatal alert during the handshake means no application data can be exchanged.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list[tuple[TcpFlow, dict]]] = defaultdict(list)
        for fl in ctx.tcp_flows:
            if not fl.tls:
                continue
            for a in fl.tls.alerts:
                if a["before_app_data"] and (a["level"] == "fatal" or a["description"] != "close_notify"):
                    groups[(fl.server, a["description"], a["dir"])].append((fl, a))
                    break
        out = []
        for (server, desc, d), items in groups.items():
            fl0, a0 = items[0]
            sender = "client" if d == "c2s" else "server"
            meaning, alts = ALERT_GUIDANCE.get(desc, ("The sender aborted the handshake.", []))
            snis = sorted({_sni(fl) for fl, _ in items if _sni(fl)})
            ch = fl0.tls.client_hello or {}
            sh = fl0.tls.server_hello or {}
            obs = [Observation(f"{len(items)} handshake(s) with {ep(server)} ended with a {a0['level']} '{desc}' alert sent by the "
                               f"{sender}: {frames_text([a['frame'] for _, a in items])}.", [a["frame"] for _, a in items])]
            if ch:
                offered = ch.get("supported_versions") or [ch.get("legacy_version")]
                obs.append(Observation(f"ClientHello at #{ch['frame']}: SNI {ch.get('sni') or '(none)'}, versions offered "
                                       f"{', '.join(v for v in offered if v)}, {ch.get('cipher_suites_offered', 0)} cipher suites"
                                       + (f", ALPN {', '.join(ch['alpn_offered'])}" if ch.get("alpn_offered") else "") + ".", [ch["frame"]]))
            if sh:
                obs.append(Observation(f"ServerHello at #{sh['frame']}: {sh.get('version')} cipher {sh.get('cipher_suite')}.", [sh["frame"]]))
            else:
                obs.append(Observation("No ServerHello was sent before the alert."))
            if fl0.tls.certificates:
                c0 = fl0.tls.certificates[0]
                obs.append(Observation(f"Server certificate (frame #{fl0.tls.certificate_frame}): CN={c0.get('subject_cn')}, issuer "
                                       f"{c0.get('issuer_cn')}, valid {c0.get('not_before')[:10]} to {c0.get('not_after')[:10]}"
                                       + (", self-signed" if c0.get("self_signed") else "") + ".",
                                       [fl0.tls.certificate_frame] if fl0.tls.certificate_frame else []))
            verification = [C.openssl_probe(server[0], server[1], snis[0] if snis else None)]
            if desc in ("handshake_failure", "protocol_version", "insufficient_security"):
                verification += [
                    C.openssl_probe(server[0], server[1], snis[0] if snis else None, "-tls1_2"),
                    C.cmd("Show ciphers enabled by a client-ssl profile cipher string",
                          "tmm --clientciphers \"$(tmsh list ltm profile client-ssl <profile> ciphers | awk '/ciphers/{print $2}')\"",
                          "BIG-IP (bash)"),
                    C.cmd("Show protocol options on the client-ssl profile", "tmsh list ltm profile client-ssl <profile> options ciphers cipher-group",
                          "BIG-IP (tmsh)"),
                ]
            if desc.startswith("certificate") or desc in ("unknown_ca", "bad_certificate"):
                verification.append(C.cmd("Check certificate, key and chain on the client-ssl profile",
                                          "tmsh list ltm profile client-ssl <profile> cert-key-chain", "BIG-IP (tmsh)"))
            verification.append(C.cmd("Look for handshake failures logged by TMM", "grep -i 'handshake' /var/log/ltm | tail -50",
                                      "BIG-IP (bash)"))
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}:{desc}:{sender}",
                title=f"TLS {desc} alert from {sender} ({ep(server)})",
                severity="high" if a0["level"] == "fatal" else "medium",
                confidence=Confidence("high", 0.9, "The alert record is visible in cleartext and identifies its sender and category."),
                summary=f"The {sender} aborted {len(items)} TLS handshake(s) with {ep(server)} using a '{desc}' alert"
                        + (f" (SNI {', '.join(snis)})." if snis else "."),
                observations=obs,
                assessment=f"The {sender} rejected the handshake. '{desc}' means: {meaning}",
                probable_cause=meaning,
                alternatives=alts + ([f"If {server[0]} is a BIG-IP virtual server: the client-ssl profile (cipher string, "
                                      "protocol options, certificate/chain, SNI default profile) does not match this client."]
                                     if sender == "server" else
                                     ["The client's trust store or validation policy rejects what the server sent."]),
                verification=verification,
                remediation=[{"action": "Align TLS versions/ciphers or fix the certificate chain according to the alert category.",
                              "risk": "Enabling legacy protocols or weak ciphers to restore compatibility reduces security; prefer upgrading clients."}],
                missing_evidence=["Server/BIG-IP TLS logs for the exact reason", "The validating client's own error message"],
                packets=[{"frame": a["frame"], "ts_ns": a["ts_ns"], "role": f"TLS alert {desc}"} for _, a in items]
                + ([{"frame": ch["frame"], "ts_ns": ch["ts_ns"], "role": "ClientHello"}] if ch else [])
                + ([{"frame": sh["frame"], "ts_ns": sh["ts_ns"], "role": "ServerHello"}] if sh else []),
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=[e for fl, _ in items[:3] for e in tcp_timeline(fl)],
                metrics={"alert": desc, "sender": sender, "handshakes": len(items), "sni": snis},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


class TlsNoServerHello(Rule):
    meta = RuleMeta(
        rule_id="TLS-002",
        version="1.0.0",
        title="ClientHello not answered",
        category="tls",
        default_severity="high",
        required_evidence=["ClientHello", "No ServerHello and no alert in the same conversation"],
        detection_logic=("Report conversations where a ClientHello was sent, no ServerHello or alert followed, and the "
                         "conversation was closed (FIN/RST) or went silent for at least 3 s before capture end."),
        limitations=["If the server answered with something other than TLS (e.g. plain HTTP), it is reported here as no ServerHello."],
        false_positives=["Captures that end shortly after the ClientHello"],
        severity_rationale="High: the TLS session cannot be established.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list[TcpFlow]] = defaultdict(list)
        for fl in ctx.tcp_flows:
            t = fl.tls
            if t and t.client_hello and not t.server_hello and not t.alerts and not ctx.near_end(t.client_hello["ts_ns"]):
                if fl.packets["s2c"] or fl.syn_count:
                    groups[fl.server].append(fl)
        out = []
        for server, flows in groups.items():
            fl0 = flows[0]
            ch = fl0.tls.client_hello
            ended = [r for fl in flows for r in fl.rsts] + [f for fl in flows for f in fl.fins]
            s2c_payload = sum(fl.payload["s2c"] for fl in flows)
            obs = [Observation(f"{len(flows)} ClientHello(s) to {ep(server)} (SNI {ch.get('sni') or 'none'}) with no ServerHello or alert: "
                               f"{frames_text([fl.tls.client_hello['frame'] for fl in flows])}.", [fl.tls.client_hello["frame"] for fl in flows])]
            if s2c_payload:
                obs.append(Observation(f"The server sent {s2c_payload} bytes of non-TLS payload."))
            if ended:
                obs.append(Observation(f"Connections were then closed: {frames_text([e['frame'] for e in ended])}.", [e["frame"] for e in ended]))
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}",
                title=f"TLS ClientHello to {ep(server)} gets no ServerHello",
                severity="high",
                confidence=Confidence("medium", 0.65, "The absence of a ServerHello is directly observed; why the server did not "
                                      "answer is not visible in the capture."),
                summary=f"{len(flows)} TLS handshake(s) to {ep(server)} stalled after the ClientHello.",
                observations=obs,
                assessment="The TCP connection works but the server side never started TLS.",
                probable_cause="The service on this port is not TLS-enabled, or the TLS terminator rejected/ignored the ClientHello.",
                alternatives=["Server application speaks plain HTTP on this port", "SNI-based routing has no match for this name",
                              f"If {server[0]} is a BIG-IP virtual server: no client-ssl profile is attached (traffic passes through "
                              "to a non-TLS pool member) or an iRule drops based on SNI."],
                verification=[C.openssl_probe(server[0], server[1], ch.get("sni")),
                              C.cmd("List profiles on the virtual server", "tmsh list ltm virtual <virtual_name> profiles", "BIG-IP (tmsh)")],
                remediation=[{"action": "Attach the correct TLS profile/certificate or point clients at the TLS port.",
                              "risk": "Changing profiles on a live virtual server affects all its clients."}],
                missing_evidence=["Server/TLS terminator logs"],
                packets=[{"frame": fl.tls.client_hello["frame"], "ts_ns": fl.tls.client_hello["ts_ns"], "role": "ClientHello"} for fl in flows]
                + [{"frame": e["frame"], "ts_ns": e["ts_ns"], "role": "close"} for e in ended],
                flows=[f"t{fl.stream}" for fl in flows],
                tuples=[tuple_of(fl) for fl in flows],
                timeline=[e for fl in flows[:3] for e in tcp_timeline(fl)],
                metrics={"handshakes": len(flows), "sni": ch.get("sni")},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


class TlsEndedBeforeAppData(Rule):
    meta = RuleMeta(
        rule_id="TLS-003",
        version="1.0.0",
        title="Connection closed after ServerHello without application data",
        category="tls",
        default_severity="medium",
        required_evidence=["ServerHello", "FIN or RST", "No application-data record from the client and no visible alert"],
        detection_logic=("Report conversations with a ServerHello, no visible alert and no client application data, closed by FIN/RST."),
        limitations=["In TLS 1.3 the failure reason is usually in an encrypted alert that cannot be read without keys."],
        false_positives=["Clients that open speculative connections and close them unused (browser pre-connect)"],
        severity_rationale="Medium: handshakes fail silently; may be benign pre-connections, so verify with client logs.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list[TcpFlow]] = defaultdict(list)
        for fl in ctx.tcp_flows:
            t = fl.tls
            if (t and t.server_hello and not t.alerts and "c2s" not in t.first_app_data and (fl.rsts or fl.fins)):
                v = t.negotiated_version
                if v == "TLS 1.3" and "c2s" in t.first_app_data:
                    continue
                groups[fl.server].append(fl)
        out = []
        for server, flows in groups.items():
            fl0 = flows[0]
            v = fl0.tls.negotiated_version
            closes = [r for fl in flows for r in fl.rsts] + [f for fl in flows for f in fl.fins]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}",
                title=f"TLS sessions with {ep(server)} closed before application data",
                severity="medium",
                confidence=Confidence("low" if v == "TLS 1.3" else "medium", 0.4 if v == "TLS 1.3" else 0.55,
                                      "The close is observed, but encrypted handshake messages hide the reason."),
                summary=f"{len(flows)} connection(s) negotiated {v or 'TLS'} with {ep(server)} and closed before the client sent any request.",
                observations=[Observation(f"ServerHello frames: {frames_text([fl.tls.server_hello['frame'] for fl in flows])}.",
                                          [fl.tls.server_hello["frame"] for fl in flows]),
                              Observation(f"Close frames (FIN/RST): {frames_text([c['frame'] for c in closes])}.", [c["frame"] for c in closes]),
                              Observation("No cleartext alert and no client application data were seen.")],
                assessment="The handshake did not lead to an application exchange; a failure after encryption started is likely.",
                probable_cause="Certificate validation failure on the client (alert hidden by encryption) or client cancelled the connection.",
                alternatives=["Browser speculative pre-connect closed unused", "Client certificate request the client cannot satisfy",
                              "ALPN/HTTP2 negotiation problem after the handshake"],
                verification=[C.openssl_probe(server[0], server[1], _sni(fl0)),
                              C.cmd("Decrypt with a key log to read hidden alerts", "export SSLKEYLOGFILE=~/tls-keys.log  # then reproduce and upload with the capture",
                                    "Client-side host")],
                remediation=[{"action": "Reproduce with a TLS key log so the platform can decrypt and show the hidden alert.",
                              "risk": "Key log files decrypt the session: handle them as secrets and delete after use."}],
                missing_evidence=["TLS session keys (SSLKEYLOGFILE) or a pcapng with embedded decryption secrets", "Client error logs"],
                packets=[{"frame": fl.tls.server_hello["frame"], "ts_ns": fl.tls.server_hello["ts_ns"], "role": "ServerHello"} for fl in flows]
                + [{"frame": c["frame"], "ts_ns": c["ts_ns"], "role": "close"} for c in closes],
                flows=[f"t{fl.stream}" for fl in flows],
                tuples=[tuple_of(fl) for fl in flows],
                timeline=[e for fl in flows[:3] for e in tcp_timeline(fl)],
                metrics={"connections": len(flows), "negotiated_version": v},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


class TlsLegacyProtocol(Rule):
    meta = RuleMeta(
        rule_id="TLS-004",
        version="1.0.0",
        title="Legacy TLS/SSL protocol version",
        category="tls",
        default_severity="medium",
        required_evidence=["ServerHello negotiated version", "or ClientHello maximum offered version"],
        detection_logic="Report servers that negotiated SSL 3.0 / TLS 1.0 / TLS 1.1, and clients whose highest offered version is one of these.",
        limitations=["The ClientHello legacy_version field is used when no supported_versions extension is present."],
        false_positives=["Deliberately supported legacy clients in an isolated environment"],
        severity_rationale="Medium: deprecated protocols are insecure (RFC 8996) and are increasingly refused, causing failures.",
    )

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list[tuple[TcpFlow, str, str]]] = defaultdict(list)
        order = ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
        for fl in ctx.tcp_flows:
            t = fl.tls
            if not t:
                continue
            if t.negotiated_version in LEGACY:
                groups[(fl.server, "negotiated")].append((fl, t.negotiated_version, "negotiated"))
            elif t.client_hello:
                offered = t.client_hello.get("supported_versions") or [t.client_hello.get("legacy_version")]
                offered = [v for v in offered if v in order]
                if offered and max(offered, key=order.index) in LEGACY:
                    groups[(fl.server, "offered")].append((fl, max(offered, key=order.index), "offered"))
        out = []
        for (server, kind), items in groups.items():
            versions = sorted({v for _, v, _ in items})
            clients = sorted({fl.client[0] for fl, _, _ in items})
            frames = [(fl.tls.server_hello if kind == "negotiated" else fl.tls.client_hello)["frame"] for fl, _, _ in items]
            refused = [fl for fl, _, _ in items if fl.tls.alerts]
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}:{kind}",
                title=(f"{ep(server)} negotiated {', '.join(versions)}" if kind == "negotiated"
                       else f"Clients offer only {', '.join(versions)} to {ep(server)}"),
                severity="medium",
                confidence=Confidence("high", 0.9, "Protocol versions are read directly from the handshake messages."),
                summary=(f"{len(items)} TLS session(s) with {ep(server)} used deprecated {', '.join(versions)}." if kind == "negotiated"
                         else f"{len(clients)} client(s) offered at most {', '.join(versions)} to {ep(server)}"
                         + (f"; {len(refused)} of these handshakes were refused." if refused else ".")),
                observations=[Observation(f"{'ServerHello' if kind == 'negotiated' else 'ClientHello'} frames: {frames_text(frames)}.", frames),
                              Observation(f"Clients: {', '.join(clients[:10])}.")]
                + ([Observation(f"Refused with alerts in: {frames_text([fl.tls.alerts[0]['frame'] for fl in refused])}.",
                                [fl.tls.alerts[0]["frame"] for fl in refused])] if refused else []),
                assessment=("The server still accepts deprecated protocol versions." if kind == "negotiated"
                            else "These clients cannot use TLS 1.2 or newer, so modern servers will refuse them."),
                probable_cause=("Server TLS policy permits legacy versions." if kind == "negotiated"
                                else "Outdated client TLS stack or a client configuration limiting the maximum version."),
                alternatives=["A TLS-intercepting middlebox downgrading the connection"],
                verification=[C.openssl_probe(server[0], server[1], None, "-tls1"),
                              C.cmd("Check the client-ssl profile options", "tmsh list ltm profile client-ssl <profile> options", "BIG-IP (tmsh)")],
                remediation=[{"action": "Upgrade clients to TLS 1.2+ and disable TLS 1.0/1.1 on servers (e.g. 'no-tlsv1 no-tlsv1.1' options).",
                              "risk": "Disabling legacy versions breaks any client that cannot be upgraded; inventory clients first."}],
                missing_evidence=["Inventory of client software versions"],
                packets=[{"frame": f, "ts_ns": 0, "role": "ServerHello" if kind == "negotiated" else "ClientHello"} for f in frames],
                flows=[f"t{fl.stream}" for fl, _, _ in items],
                tuples=[tuple_of(fl) for fl, _, _ in items],
                timeline=[e for fl, _, _ in items[:3] for e in tcp_timeline(fl)],
                metrics={"versions": versions, "kind": kind, "clients": clients[:20]},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


class TlsCertificateValidity(Rule):
    meta = RuleMeta(
        rule_id="TLS-005",
        version="1.1.0",
        title="Server certificate does not match the capture time or SNI",
        category="tls",
        default_severity="high",
        required_evidence=["Cleartext Certificate handshake message (TLS 1.2 or earlier)", "ClientHello SNI (for name checks)"],
        detection_logic=("Parse the first certificate presented. Report when the capture timestamp is outside its validity window, or "
                         "when the SNI name matches neither the subject CN nor any DNS SAN (wildcards honoured)."),
        limitations=["TLS 1.3 certificates are encrypted and cannot be checked without keys.",
                     "This proves what the server presented; it proves the client rejected it only when a matching alert is also visible.",
                     "Chain trust (whether the issuer is trusted) cannot be evaluated from the capture."],
        false_positives=["Capture host clock wrong (validity is compared with packet timestamps)"],
        severity_rationale="High: clients that validate certificates will refuse the connection.",
    )

    @staticmethod
    def _name_matches(sni: str, cert: dict) -> bool:
        names = [n.lower() for n in cert.get("san_dns") or []] or ([cert["subject_cn"].lower()] if cert.get("subject_cn") else [])
        sni = sni.lower().rstrip(".")
        for n in names:
            if n == sni:
                return True
            if n.startswith("*.") and sni.count(".") >= 1 and sni.split(".", 1)[1] == n[2:]:
                return True
        return False

    def evaluate(self, ctx: RuleContext) -> list[FindingDraft]:
        groups: dict[tuple, list[tuple[TcpFlow, str]]] = defaultdict(list)
        for fl in ctx.tcp_flows:
            t = fl.tls
            if not t or not t.certificates:
                continue
            cert = t.certificates[0]
            ts = t.server_hello["ts_ns"] if t.server_hello else fl.first_ts
            if ts > cert["not_after_ns"]:
                groups[(fl.server, cert["sha256_fingerprint"], "expired")].append((fl, "expired"))
            elif ts < cert["not_before_ns"]:
                groups[(fl.server, cert["sha256_fingerprint"], "not_yet_valid")].append((fl, "not_yet_valid"))
            sni = _sni(fl)
            if sni and not self._name_matches(sni, cert):
                groups[(fl.server, cert["sha256_fingerprint"], "name_mismatch")].append((fl, "name_mismatch"))
        out = []
        for (server, _fp, problem), items in groups.items():
            fl0 = items[0][0]
            cert = fl0.tls.certificates[0]
            alerts = [a for fl, _ in items for a in fl.tls.alerts if a["dir"] == "c2s"]
            sni = _sni(fl0)
            obs = [Observation(f"Certificate presented in frame #{fl0.tls.certificate_frame}: CN={cert.get('subject_cn')}, SAN="
                               f"{', '.join(cert.get('san_dns') or []) or 'none'}, issuer {cert.get('issuer_cn')}, valid "
                               f"{cert['not_before']} → {cert['not_after']}.", [fl0.tls.certificate_frame] if fl0.tls.certificate_frame else [])]
            if problem == "expired":
                obs.append(Observation(f"The capture time is after the certificate's notAfter date ({cert['not_after']})."))
                title = f"Expired certificate presented by {ep(server)}"
            elif problem == "not_yet_valid":
                obs.append(Observation(f"The capture time is before the certificate's notBefore date ({cert['not_before']})."))
                title = f"Not-yet-valid certificate presented by {ep(server)}"
            else:
                obs.append(Observation(f"Requested SNI '{sni}' matches neither the CN nor any SAN of the certificate."))
                title = f"Certificate from {ep(server)} does not cover '{sni}'"
            if alerts:
                obs.append(Observation(f"The client then sent alert(s): {', '.join(sorted({a['description'] for a in alerts}))} "
                                       f"({frames_text([a['frame'] for a in alerts])}).", [a["frame"] for a in alerts]))
            conf = Confidence("high", 0.9, "The certificate fields are parsed from the handshake and the client's rejection alert is visible.") \
                if alerts else Confidence("medium", 0.7, "The certificate problem is proven from its fields; no client alert proves "
                                          "a client rejected it (clients may not validate).")
            out.append(FindingDraft(
                rule=self.meta,
                subject_key=f"{server[0]}:{server[1]}:{problem}",
                title=title,
                severity="high",
                confidence=conf,
                summary=title + f" for {len(items)} session(s)" + (", and the client rejected it." if alerts else "."),
                observations=obs,
                assessment="Clients that validate certificates will refuse this server." + (
                    " The visible client alert shows at least one client did." if alerts else ""),
                probable_cause={"expired": "The certificate was not renewed before its expiry date.",
                                "not_yet_valid": "A newly issued certificate was deployed before its start date, or clocks are wrong.",
                                "name_mismatch": "The wrong certificate is served for this name (SNI mapping or default certificate)."}[problem],
                alternatives=["Wrong clock on the capture host (timestamps)"] if problem != "name_mismatch" else
                ["If a BIG-IP is in path: the SNI default client-ssl profile is used because no profile has a matching server name."],
                verification=[C.openssl_probe(server[0], server[1], sni),
                              C.cmd("List certificates and expiry on BIG-IP", "tmsh list sys file ssl-cert all expiration-string subject",
                                    "BIG-IP (tmsh)")],
                remediation=[{"action": "Install a valid certificate (correct names, current validity) with its full chain and update the profile.",
                              "risk": "Certificate swaps on a live profile apply to new handshakes immediately; test with openssl first."}],
                missing_evidence=["Client-side validation error message"] if not alerts else [],
                packets=[{"frame": fl.tls.certificate_frame, "ts_ns": 0, "role": "Certificate"} for fl, _ in items if fl.tls.certificate_frame]
                + [{"frame": a["frame"], "ts_ns": a["ts_ns"], "role": "client alert"} for a in alerts],
                flows=[f"t{fl.stream}" for fl, _ in items],
                tuples=[tuple_of(fl) for fl, _ in items],
                timeline=[e for fl, _ in items[:3] for e in tcp_timeline(fl)],
                metrics={"problem": problem, "subject_cn": cert.get("subject_cn"), "not_after": cert["not_after"], "sni": sni},
                f5_relevance=ctx.bigip_hint(server[0]),
            ))
        return out


TLS_RULES: list[type[Rule]] = [TlsHandshakeAlert, TlsNoServerHello, TlsEndedBeforeAppData, TlsLegacyProtocol, TlsCertificateValidity]

