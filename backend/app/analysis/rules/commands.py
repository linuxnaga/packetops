"""Verification command templates.

Commands are parameterised only with values taken from the capture (addresses,
ports, names). They are suggestions for an engineer to run; the platform never
executes them and never presents their output as if it had been run.
"""

from __future__ import annotations


def cmd(purpose: str, command: str, where: str) -> dict:
    return {"purpose": purpose, "command": command, "where": where}


def bigip_tcpdump(host_a: str, host_b: str | None = None, port: int | None = None) -> dict:
    flt = f"host {host_a}"
    if host_b:
        flt += f" and host {host_b}"
    if port:
        flt += f" and port {port}"
    return cmd(
        "Capture both client-side and server-side legs with F5 flow metadata (Ethernet trailer)",
        f"tcpdump -nni 0.0:nnnp -s0 -w /var/tmp/packetops_$(date +%s).pcap '{flt}'",
        "BIG-IP (bash)",
    )


def bigip_vs_status(ip: str, port: int) -> list[dict]:
    return [
        cmd("Find the virtual server that owns this destination",
            f"tmsh list ltm virtual one-line | grep -E 'destination [^ ]*{ip}[:.]{port}( |$)'", "BIG-IP (bash)"),
        cmd("Check virtual server availability and status reason", "tmsh show ltm virtual <virtual_name> field-fmt | grep -E 'status|availability'", "BIG-IP (tmsh)"),
    ]


def bigip_connections(client_ip: str | None = None, server_ip: str | None = None) -> dict:
    args = []
    if client_ip:
        args.append(f"cs-client-addr {client_ip}")
    if server_ip:
        args.append(f"ss-server-addr {server_ip}")
    return cmd("List BIG-IP connection table entries for this flow", f"tmsh show sys connection {' '.join(args)} all-properties", "BIG-IP (tmsh)")


def bigip_pool_members(pool: str = "<pool_name>") -> dict:
    return cmd("Check pool member availability and monitor state", f"tmsh show ltm pool {pool} members field-fmt", "BIG-IP (tmsh)")


def bigip_rst_cause() -> dict:
    return cmd(
        "Log BIG-IP reset causes (temporarily) to learn why TMM sent RSTs",
        "tmsh modify sys db tm.rstcause.log value enable && tail -f /var/log/ltm | grep RST",
        "BIG-IP (bash) — revert with: tmsh modify sys db tm.rstcause.log value disable",
    )


def generic_tcpdump(host_a: str, host_b: str | None = None, port: int | None = None) -> dict:
    flt = f"host {host_a}"
    if host_b:
        flt += f" and host {host_b}"
    if port:
        flt += f" and port {port}"
    return cmd("Capture at a second point to confirm where packets stop", f"tcpdump -nni any -s0 -w second_point.pcap '{flt}'", "Linux host / network device")


def port_check(ip: str, port: int) -> dict:
    return cmd("Test TCP reachability from the client network", f"nc -vz -w 3 {ip} {port}", "Client-side host")


def listener_check(port: int) -> dict:
    return cmd("Confirm the service is listening on the server", f"ss -ltnp 'sport = :{port}'", "Server (Linux)")


def openssl_probe(ip: str, port: int, sni: str | None, version_flag: str | None = None) -> dict:
    sn = f" -servername {sni}" if sni else ""
    vf = f" {version_flag}" if version_flag else ""
    return cmd("Reproduce the TLS handshake and print the certificate chain",
               f"openssl s_client -connect {ip}:{port}{sn}{vf} -showcerts </dev/null", "Client-side host")


def dig(server: str, name: str, qtype: str = "A", tcp: bool = False) -> dict:
    return cmd("Query the resolver directly" + (" over TCP" if tcp else ""),
               f"dig @{server} {name} {qtype}{' +tcp' if tcp else ''} +tries=1 +time=2", "Client-side host")


def curl_timing(host: str | None, ip: str, port: int, path: str, tls: bool) -> dict:
    scheme = "https" if tls else "http"
    h = host or ip
    resolve = f" --resolve {h}:{port}:{ip}" if host else ""
    fmt = "connect=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total} code=%{http_code}\\n"
    p = path.split("?")[0] if path else "/"
    return cmd("Measure connect / TLS / first-byte / total timing for the same request",
               f"curl -sS -o /dev/null{resolve} -w '{fmt}' {scheme}://{h}:{port}{p}", "Client-side host")
