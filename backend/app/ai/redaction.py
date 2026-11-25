"""Reversible redaction of network identifiers before text is sent to an external model.

Addresses, hostnames, DNS names, URL paths and MAC addresses are replaced with
stable placeholders (``IP_1``, ``HOST_2``, ``PATH_1`` …). The model reasons over the
placeholders; the response is mapped back locally. Placeholders the model invents
cannot be mapped back and make validation fail.
"""

from __future__ import annotations

import ipaddress
import re

IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)")
IPV6_CANDIDATE = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3}(?![\w])")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
HOST = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|local|internal|corp|lan|example|test|[a-z]{2})\b")
PATH = re.compile(r"(?<=\s)(/[A-Za-z0-9._~%!$&'*+,;=:@/-]{1,200}[A-Za-z0-9_~%$&'*+=@/-])")
PLACEHOLDER = re.compile(r"\b(?:IP|HOST|MAC|PATH)_\d+\b")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def find_ips(text: str) -> set[str]:
    found = {m.group(0) for m in IPV4.finditer(text) if is_ip(m.group(0))}
    found |= {str(ipaddress.ip_address(m.group(0))) for m in IPV6_CANDIDATE.finditer(text) if is_ip(m.group(0))}
    return found


class Redactor:
    def __init__(self) -> None:
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        self.counts: dict[str, int] = {}

    def _token(self, kind: str, value: str) -> str:
        if value not in self.forward:
            self.counts[kind] = self.counts.get(kind, 0) + 1
            tok = f"{kind}_{self.counts[kind]}"
            self.forward[value] = tok
            self.reverse[tok] = value
        return self.forward[value]

    def redact(self, text: str) -> str:
        text = MAC.sub(lambda m: self._token("MAC", m.group(0).lower()), text)
        text = IPV4.sub(lambda m: self._token("IP", m.group(0)) if is_ip(m.group(0)) else m.group(0), text)
        text = IPV6_CANDIDATE.sub(lambda m: self._token("IP", m.group(0)) if is_ip(m.group(0)) else m.group(0), text)
        text = HOST.sub(lambda m: m.group(0) if m.group(0).startswith(("IP_", "HOST_")) else self._token("HOST", m.group(0).lower()), text)
        text = PATH.sub(lambda m: m.group(0) if m.group(0).startswith("/Common/") else self._token("PATH", m.group(0)), text)
        return text

    def restore(self, text: str) -> tuple[str, list[str]]:
        unknown: list[str] = []

        def sub(m: re.Match) -> str:
            tok = m.group(0)
            if tok in self.reverse:
                return self.reverse[tok]
            unknown.append(tok)
            return tok

        return PLACEHOLDER.sub(sub, text), unknown
