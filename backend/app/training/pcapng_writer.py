"""Minimal deterministic PCAPNG writer used to build synthetic training captures.

Every file written here carries a section-header comment that labels it as
synthetic training data, so it can never be mistaken for real evidence.
"""

from __future__ import annotations

import struct
from pathlib import Path

SYNTHETIC_LABEL = "F5 PacketOps SYNTHETIC TRAINING DATA - not real network evidence"


def _opt(code: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad


def _block(btype: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


class PcapNgWriter:
    def __init__(self, path: str | Path, comments: list[str] | None = None):
        self.path = Path(path)
        self.fh = self.path.open("wb")
        opts = b"".join(_opt(1, c.encode()) for c in [SYNTHETIC_LABEL, *(comments or [])])
        opts += _opt(4, b"F5 PacketOps training generator") + struct.pack("<HH", 0, 0)
        body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + opts
        self.fh.write(_block(0x0A0D0D0A, body))
        self.interfaces: list[str] = []

    def add_interface(self, name: str, link_type: int = 1, snaplen: int = 262144, description: str = "") -> int:
        opts = _opt(2, name.encode())
        if description:
            opts += _opt(3, description.encode())
        opts += _opt(9, bytes([9]))  # nanosecond timestamps
        opts += struct.pack("<HH", 0, 0)
        self.fh.write(_block(1, struct.pack("<HHI", link_type, 0, snaplen) + opts))
        self.interfaces.append(name)
        return len(self.interfaces) - 1

    def write(self, ts_ns: int, data: bytes, interface: int = 0, comment: str | None = None) -> None:
        pad = (-len(data)) % 4
        body = struct.pack("<IIIII", interface, ts_ns >> 32, ts_ns & 0xFFFFFFFF, len(data), len(data))
        body += data + b"\x00" * pad
        if comment:
            body += _opt(1, comment.encode()) + struct.pack("<HH", 0, 0)
        self.fh.write(_block(6, body))

    def close(self) -> None:
        self.fh.close()

    def __enter__(self) -> PcapNgWriter:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
