"""Streaming, defensive PCAP / PCAPNG structural parser.

This module never trusts the input file. It walks the capture block by block
(or record by record for classic pcap), validates every length field against
hard limits before reading, and never holds more than one packet in memory.

It produces two things:

* ``CaptureMetadata`` describing the evidence file (format, interfaces,
  link types, timestamp precision, packet count, first/last timestamps).
* An iterator of ``PacketIndexEntry`` giving, for each frame, its number,
  timestamp (integer nanoseconds, so precision is preserved), the interface
  it was captured on, the captured/original lengths and the byte offset of
  the packet data in the original file. The offset index lets the API fetch
  a single packet's bytes for the detail/hex view without rescanning.

Frame numbering matches Wireshark/tshark: every packet-bearing block
(EPB, SPB, OPB) increments the frame number by one, starting at 1.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

# Hard limits that protect the parser against hostile inputs.
MAX_PACKET_BYTES = 262_144  # Wireshark's default maximum snapshot length.
MAX_BLOCK_BYTES = 16 * 1024 * 1024  # Any pcapng block larger than this is rejected.
MAX_INTERFACES = 4096
MAX_OPTION_BYTES = 64 * 1024

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BOM = 0x1A2B3C4D

BT_IDB = 0x00000001
BT_OPB = 0x00000002
BT_SPB = 0x00000003
BT_NRB = 0x00000004
BT_ISB = 0x00000005
BT_EPB = 0x00000006
BT_DSB = 0x0000000A

# A subset of LINKTYPE_* values, for display only.
LINKTYPE_NAMES = {
    0: "NULL",
    1: "ETHERNET",
    101: "RAW",
    105: "IEEE802_11",
    113: "LINUX_SLL",
    127: "IEEE802_11_RADIOTAP",
    228: "IPV4",
    229: "IPV6",
    276: "LINUX_SLL2",
}


class MalformedCaptureError(ValueError):
    """Raised when the evidence file is structurally invalid."""

    def __init__(self, reason: str, offset: int | None = None):
        self.reason = reason
        self.offset = offset
        super().__init__(f"{reason}" + (f" (at byte offset {offset})" if offset is not None else ""))


@dataclass
class InterfaceInfo:
    interface_id: int
    section: int
    link_type: int
    snaplen: int
    name: str | None = None
    description: str | None = None
    os: str | None = None
    hardware: str | None = None
    # Number of timestamp units per second (10**6 for microseconds, 10**9 for ns).
    ts_units_per_sec: int = 1_000_000
    ts_offset_sec: int = 0

    @property
    def link_type_name(self) -> str:
        return LINKTYPE_NAMES.get(self.link_type, f"LINKTYPE_{self.link_type}")

    @property
    def timestamp_precision(self) -> str:
        return _precision_name(self.ts_units_per_sec)


@dataclass
class PacketIndexEntry:
    number: int
    ts_ns: int
    interface_id: int  # Global interface index (across sections).
    caplen: int
    origlen: int
    data_offset: int


@dataclass
class CaptureMetadata:
    file_format: str  # "pcap" or "pcapng"
    format_version: str
    byte_order: str  # "little" or "big"
    file_size: int = 0
    packet_count: int = 0
    first_ts_ns: int | None = None
    last_ts_ns: int | None = None
    total_captured_bytes: int = 0
    total_original_bytes: int = 0
    truncated_packets: int = 0  # caplen < origlen (snaplen truncation)
    truncated_tail: bool = False  # File ends in the middle of a record/block.
    sections: int = 0
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    has_decryption_secrets: bool = False
    comments: list[str] = field(default_factory=list)
    out_of_order_timestamps: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def duration_ns(self) -> int:
        if self.first_ts_ns is None or self.last_ts_ns is None:
            return 0
        return max(0, self.last_ts_ns - self.first_ts_ns)

    @property
    def link_types(self) -> list[str]:
        return sorted({i.link_type_name for i in self.interfaces})

    @property
    def timestamp_precisions(self) -> list[str]:
        return sorted({i.timestamp_precision for i in self.interfaces})

    def to_dict(self) -> dict:
        return {
            "file_format": self.file_format,
            "format_version": self.format_version,
            "byte_order": self.byte_order,
            "file_size": self.file_size,
            "packet_count": self.packet_count,
            "first_ts_ns": self.first_ts_ns,
            "last_ts_ns": self.last_ts_ns,
            "duration_ns": self.duration_ns,
            "total_captured_bytes": self.total_captured_bytes,
            "total_original_bytes": self.total_original_bytes,
            "truncated_packets": self.truncated_packets,
            "truncated_tail": self.truncated_tail,
            "sections": self.sections,
            "link_types": self.link_types,
            "timestamp_precisions": self.timestamp_precisions,
            "interfaces": [
                {
                    "interface_id": i.interface_id,
                    "section": i.section,
                    "link_type": i.link_type,
                    "link_type_name": i.link_type_name,
                    "snaplen": i.snaplen,
                    "name": i.name,
                    "description": i.description,
                    "os": i.os,
                    "hardware": i.hardware,
                    "timestamp_precision": i.timestamp_precision,
                }
                for i in self.interfaces
            ],
            "has_decryption_secrets": self.has_decryption_secrets,
            "comments": self.comments[:20],
            "out_of_order_timestamps": self.out_of_order_timestamps,
            "warnings": self.warnings,
        }


def _precision_name(units: int) -> str:
    return {1: "s", 1_000: "ms", 1_000_000: "us", 1_000_000_000: "ns"}.get(units, f"1/{units}s")


def _to_ns(ticks: int, units_per_sec: int, offset_sec: int = 0) -> int:
    if units_per_sec == 1_000_000_000:
        ns = ticks
    elif units_per_sec == 1_000_000:
        ns = ticks * 1_000
    else:
        ns = (ticks * 1_000_000_000) // units_per_sec
    return ns + offset_sec * 1_000_000_000


def _read_exact(fh: BinaryIO, n: int) -> bytes | None:
    """Read exactly n bytes, or return None on a short read (truncation)."""
    data = fh.read(n)
    if len(data) != n:
        return None
    return data


def sniff_format(header: bytes) -> str | None:
    if len(header) < 4:
        return None
    if struct.unpack("<I", header[:4])[0] == PCAPNG_SHB:
        return "pcapng"
    le = struct.unpack("<I", header[:4])[0]
    be = struct.unpack(">I", header[:4])[0]
    if le in (PCAP_MAGIC_US, PCAP_MAGIC_NS) or be in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
        return "pcap"
    return None


class CaptureReader:
    """Iterate a capture file once, validating structure as it goes.

    Usage::

        reader = CaptureReader(path)
        for entry in reader.packets():
            ...
        meta = reader.metadata  # complete once iteration has finished
    """

    def __init__(self, path: str | Path, max_packets: int | None = None):
        self.path = Path(path)
        self.max_packets = max_packets
        self.metadata: CaptureMetadata | None = None
        self._finished = False

    # ------------------------------------------------------------------ API
    def packets(self) -> Iterator[PacketIndexEntry]:
        size = self.path.stat().st_size
        with self.path.open("rb") as fh:
            head = fh.read(4)
            fmt = sniff_format(head)
            if fmt is None:
                raise MalformedCaptureError("Not a PCAP or PCAPNG file (unrecognised magic number)", 0)
            fh.seek(0)
            if fmt == "pcap":
                yield from self._pcap(fh, size)
            else:
                yield from self._pcapng(fh, size)
        self._finished = True

    def scan(self) -> CaptureMetadata:
        """Consume the whole file and return its metadata."""
        for _ in self.packets():
            pass
        assert self.metadata is not None
        return self.metadata

    # ----------------------------------------------------------- classic pcap
    def _pcap(self, fh: BinaryIO, size: int) -> Iterator[PacketIndexEntry]:
        hdr = _read_exact(fh, 24)
        if hdr is None:
            raise MalformedCaptureError("PCAP global header is truncated", 0)
        magic_le = struct.unpack("<I", hdr[:4])[0]
        if magic_le in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian, order = "<", "little"
            magic = magic_le
        else:
            endian, order = ">", "big"
            magic = struct.unpack(">I", hdr[:4])[0]
        vmaj, vmin, _thiszone, _sigfigs, snaplen, linktype_raw = struct.unpack(endian + "HHiIII", hdr[4:24])
        if vmaj != 2:
            raise MalformedCaptureError(f"Unsupported PCAP major version {vmaj}", 4)
        units = 1_000_000_000 if magic == PCAP_MAGIC_NS else 1_000_000
        linktype = linktype_raw & 0x0FFFFFFF
        meta = CaptureMetadata(
            file_format="pcap", format_version=f"{vmaj}.{vmin}", byte_order=order, file_size=size, sections=1
        )
        meta.interfaces.append(
            InterfaceInfo(interface_id=0, section=0, link_type=linktype, snaplen=snaplen, ts_units_per_sec=units)
        )
        self.metadata = meta
        number = 0
        last_ts = None
        rec = struct.Struct(endian + "IIII")
        while True:
            offset = fh.tell()
            rh = fh.read(16)
            if not rh:
                break
            if len(rh) != 16:
                meta.truncated_tail = True
                meta.warnings.append(f"Capture ends with a truncated record header at offset {offset}")
                break
            ts_sec, ts_frac, incl, orig = rec.unpack(rh)
            if incl > MAX_PACKET_BYTES:
                raise MalformedCaptureError(
                    f"Record {number + 1} claims {incl} captured bytes, above the {MAX_PACKET_BYTES} limit", offset
                )
            if units == 1_000_000 and ts_frac >= 1_000_000 or units == 1_000_000_000 and ts_frac >= 1_000_000_000:
                raise MalformedCaptureError(f"Record {number + 1} has an invalid fractional timestamp", offset)
            data_offset = offset + 16
            if data_offset + incl > size:
                meta.truncated_tail = True
                meta.warnings.append(f"Capture ends in the middle of packet {number + 1}")
                break
            fh.seek(incl, 1)
            number += 1
            ts_ns = ts_sec * 1_000_000_000 + (ts_frac * (1_000 if units == 1_000_000 else 1))
            last_ts = self._account(meta, ts_ns, incl, orig, last_ts)
            yield PacketIndexEntry(number, ts_ns, 0, incl, orig, data_offset)
            if self.max_packets and number >= self.max_packets:
                meta.warnings.append(f"Packet limit of {self.max_packets} reached; remaining packets not indexed")
                break
        meta.packet_count = number

    # ------------------------------------------------------------------ pcapng
    def _pcapng(self, fh: BinaryIO, size: int) -> Iterator[PacketIndexEntry]:
        meta = CaptureMetadata(file_format="pcapng", format_version="", byte_order="little", file_size=size)
        self.metadata = meta
        endian = "<"
        section = -1
        section_ifaces: list[int] = []  # local interface id -> global index
        number = 0
        last_ts = None
        while True:
            offset = fh.tell()
            head = fh.read(8)
            if not head:
                break
            if len(head) != 8:
                meta.truncated_tail = True
                meta.warnings.append(f"Capture ends with a truncated block header at offset {offset}")
                break
            btype_le = struct.unpack("<I", head[:4])[0]
            if btype_le == PCAPNG_SHB:
                bom_raw = _read_exact(fh, 4)
                if bom_raw is None:
                    meta.truncated_tail = True
                    break
                if struct.unpack("<I", bom_raw)[0] == PCAPNG_BOM:
                    endian = "<"
                elif struct.unpack(">I", bom_raw)[0] == PCAPNG_BOM:
                    endian = ">"
                else:
                    raise MalformedCaptureError("Section header has an invalid byte-order magic", offset + 8)
                meta.byte_order = "little" if endian == "<" else "big"
                total_len = struct.unpack(endian + "I", head[4:8])[0]
                self._check_block_len(total_len, offset, minimum=28)
                body = _read_exact(fh, total_len - 12)
                if body is None:
                    meta.truncated_tail = True
                    meta.warnings.append("Capture ends inside a section header block")
                    break
                vmaj, vmin = struct.unpack(endian + "HH", body[:4])
                if vmaj != 1:
                    raise MalformedCaptureError(f"Unsupported PCAPNG major version {vmaj}", offset)
                meta.format_version = f"{vmaj}.{vmin}"
                self._check_trailer(body, total_len, endian, offset)
                section += 1
                section_ifaces = []
                meta.sections += 1
                for code, val in self._options(body[12:-4], endian, offset):
                    if code == 1:
                        meta.comments.append(val.decode("utf-8", "replace"))
                continue

            btype, total_len = struct.unpack(endian + "II", head)
            if section < 0:
                raise MalformedCaptureError("PCAPNG file does not start with a section header block", offset)
            self._check_block_len(total_len, offset, minimum=12)
            if offset + total_len > size:
                meta.truncated_tail = True
                meta.warnings.append(f"Capture ends in the middle of a block at offset {offset}")
                break
            body_len = total_len - 12

            if btype in (BT_EPB, BT_SPB, BT_OPB):
                if btype == BT_EPB:
                    if body_len < 20:
                        raise MalformedCaptureError("Enhanced packet block is too short", offset)
                    fixed = fh.read(20)
                    iface, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "IIIII", fixed)
                    data_offset = offset + 8 + 20
                    avail = body_len - 20
                elif btype == BT_OPB:
                    if body_len < 20:
                        raise MalformedCaptureError("Packet block is too short", offset)
                    fixed = fh.read(20)
                    iface, _drops, ts_hi, ts_lo, caplen, origlen = struct.unpack(endian + "HHIIII", fixed)
                    data_offset = offset + 8 + 20
                    avail = body_len - 20
                else:  # SPB: always interface 0, no timestamp
                    if body_len < 4:
                        raise MalformedCaptureError("Simple packet block is too short", offset)
                    fixed = fh.read(4)
                    (origlen,) = struct.unpack(endian + "I", fixed)
                    iface, ts_hi, ts_lo = 0, 0, 0
                    data_offset = offset + 8 + 4
                    avail = body_len - 4
                    snap = meta.interfaces[section_ifaces[0]].snaplen if section_ifaces else 0
                    caplen = min(origlen, snap) if snap else origlen
                if iface >= len(section_ifaces):
                    raise MalformedCaptureError(f"Packet references undefined interface {iface}", offset)
                if caplen > MAX_PACKET_BYTES:
                    raise MalformedCaptureError(
                        f"Packet {number + 1} claims {caplen} captured bytes, above the {MAX_PACKET_BYTES} limit",
                        offset,
                    )
                if caplen > avail:
                    raise MalformedCaptureError(f"Packet {number + 1} length exceeds its block", offset)
                gidx = section_ifaces[iface]
                info = meta.interfaces[gidx]
                ticks = (ts_hi << 32) | ts_lo
                ts_ns = _to_ns(ticks, info.ts_units_per_sec, info.ts_offset_sec) if btype != BT_SPB else (
                    last_ts or 0
                )
                fh.seek(offset + total_len - 4)
                trailer = fh.read(4)
                if struct.unpack(endian + "I", trailer)[0] != total_len:
                    raise MalformedCaptureError("Block trailing length does not match leading length", offset)
                number += 1
                last_ts = self._account(meta, ts_ns, caplen, origlen, last_ts)
                yield PacketIndexEntry(number, ts_ns, gidx, caplen, origlen, data_offset)
                if self.max_packets and number >= self.max_packets:
                    meta.warnings.append(f"Packet limit of {self.max_packets} reached; remaining packets not indexed")
                    break
                continue

            body = _read_exact(fh, body_len + 4)
            if body is None:
                meta.truncated_tail = True
                break
            if struct.unpack(endian + "I", body[-4:])[0] != total_len:
                raise MalformedCaptureError("Block trailing length does not match leading length", offset)
            body = body[:-4]
            if btype == BT_IDB:
                if len(body) < 8:
                    raise MalformedCaptureError("Interface description block is too short", offset)
                if len(meta.interfaces) >= MAX_INTERFACES:
                    raise MalformedCaptureError("Too many interfaces defined", offset)
                link_type, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
                info = InterfaceInfo(
                    interface_id=len(meta.interfaces), section=section, link_type=link_type, snaplen=snaplen
                )
                for code, val in self._options(body[8:], endian, offset):
                    if code == 2:
                        info.name = val.decode("utf-8", "replace")[:256]
                    elif code == 3:
                        info.description = val.decode("utf-8", "replace")[:256]
                    elif code == 9 and len(val) >= 1:
                        b = val[0]
                        exp = b & 0x7F
                        if exp > 30 and not (b & 0x80):
                            raise MalformedCaptureError("Interface timestamp resolution is out of range", offset)
                        info.ts_units_per_sec = (2**exp) if (b & 0x80) else (10**exp)
                    elif code == 12:
                        info.os = val.decode("utf-8", "replace")[:256]
                    elif code == 15:
                        info.hardware = val.decode("utf-8", "replace")[:256]
                    elif code == 14 and len(val) == 8:
                        info.ts_offset_sec = struct.unpack(endian + "q", val)[0]
                section_ifaces.append(info.interface_id)
                meta.interfaces.append(info)
            elif btype == BT_DSB:
                meta.has_decryption_secrets = True
            # NRB, ISB, custom and unknown blocks are skipped (structure already validated).
        meta.packet_count = number
        if meta.sections == 0:
            raise MalformedCaptureError("PCAPNG file contains no section header", 0)

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _check_block_len(total_len: int, offset: int, minimum: int) -> None:
        if total_len < minimum or total_len % 4 != 0:
            raise MalformedCaptureError(f"Invalid block length {total_len}", offset)
        if total_len > MAX_BLOCK_BYTES:
            raise MalformedCaptureError(f"Block length {total_len} exceeds the {MAX_BLOCK_BYTES} byte limit", offset)

    @staticmethod
    def _check_trailer(body: bytes, total_len: int, endian: str, offset: int) -> None:
        if struct.unpack(endian + "I", body[-4:])[0] != total_len:
            raise MalformedCaptureError("Block trailing length does not match leading length", offset)

    @staticmethod
    def _options(raw: bytes, endian: str, offset: int) -> Iterator[tuple[int, bytes]]:
        pos = 0
        n = len(raw)
        while pos + 4 <= n:
            code, length = struct.unpack(endian + "HH", raw[pos : pos + 4])
            pos += 4
            if code == 0:
                return
            if length > MAX_OPTION_BYTES or pos + length > n:
                raise MalformedCaptureError("Block option overruns its block", offset)
            yield code, raw[pos : pos + length]
            pos += (length + 3) & ~3

    @staticmethod
    def _account(meta: CaptureMetadata, ts_ns: int, caplen: int, origlen: int, last_ts: int | None) -> int:
        if meta.first_ts_ns is None or ts_ns < meta.first_ts_ns:
            meta.first_ts_ns = ts_ns
        if meta.last_ts_ns is None or ts_ns > meta.last_ts_ns:
            meta.last_ts_ns = ts_ns
        if last_ts is not None and ts_ns < last_ts:
            meta.out_of_order_timestamps += 1
        meta.total_captured_bytes += caplen
        meta.total_original_bytes += origlen
        if caplen < origlen:
            meta.truncated_packets += 1
        return ts_ns


def read_packet_bytes(path: str | Path, data_offset: int, caplen: int) -> bytes:
    """Read one packet's captured bytes using the offset index."""
    if caplen < 0 or caplen > MAX_PACKET_BYTES:
        raise ValueError("Invalid packet length")
    with Path(path).open("rb") as fh:
        fh.seek(data_offset)
        data = fh.read(caplen)
    if len(data) != caplen:
        raise MalformedCaptureError("Packet data is truncated", data_offset)
    return data


def write_single_packet_pcap(dest: str | Path, link_type: int, ts_ns: int, data: bytes, origlen: int) -> None:
    """Write a one-packet nanosecond pcap, used to dissect a single frame on demand."""
    with Path(dest).open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", PCAP_MAGIC_NS, 2, 4, 0, 0, MAX_PACKET_BYTES, link_type))
        fh.write(struct.pack("<IIII", ts_ns // 1_000_000_000, ts_ns % 1_000_000_000, len(data), origlen))
        fh.write(data)
