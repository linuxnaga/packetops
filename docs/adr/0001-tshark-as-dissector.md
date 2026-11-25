# 0001: tshark as the dissector

**Status:** accepted

## Context
The product must dissect real PCAP/PCAPNG files, including TLS, DNS, HTTP and F5 Ethernet trailers, with results analysts already trust. Writing dissectors would take years and would disagree with Wireshark.

## Decision
Use tshark (Wireshark 4.x) as the only dissector. Bulk extraction uses `-T fields` with a fixed field list. Single-frame detail uses `-T json -x` bounded to one frame. tshark is started without a shell, with name resolution off (`-n`), and with rlimits on CPU time, address space, file writes and core dumps. It runs only in the worker, which has no network egress. The API also calls it for single-frame detail.

## Consequences
- The results match what analysts see in Wireshark, including expert info and the `f5ethtrailer` dissector.
- Dissector vulnerabilities are a real risk for untrusted captures. The risk is contained by rlimits, the no-egress network, a read-only container and a non-root user, and by tracking Wireshark security releases (see [security.md](../security.md)).
- Field names are pinned in code. A tshark upgrade must pass the golden-file tests.
