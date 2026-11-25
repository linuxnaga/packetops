import struct

import pytest

from app.analysis.pcapfile import CaptureReader, MalformedCaptureError, sniff_format, write_single_packet_pcap

from .conftest import FIXTURES


def _pcap(tmp_path, magic=0xA1B2C3D4, endian="<", packets=((b"\x00" * 60),), linktype=1, snap=65535):
    hdr = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snap, linktype)
    body = b""
    for i, data in enumerate(packets):
        body += struct.pack(endian + "IIII", 1700000000 + i, 5, len(data), len(data)) + data
    p = tmp_path / "x.pcap"
    p.write_bytes(hdr + body)
    return p


def test_reads_all_training_fixtures():
    for path in FIXTURES.glob("*.pcapng"):
        meta = CaptureReader(path).scan()
        assert meta.packet_count > 0
        assert meta.file_format == "pcapng"
        assert meta.first_ts_ns <= meta.last_ts_ns


def test_classic_pcap_both_endians_and_ns(tmp_path):
    for magic, endian in ((0xA1B2C3D4, "<"), (0xA1B2C3D4, ">"), (0xA1B23C4D, "<")):
        p = _pcap(tmp_path, magic=magic, endian=endian, packets=[b"\x01" * 60, b"\x02" * 70])
        meta = CaptureReader(p).scan()
        assert meta.packet_count == 2
        assert meta.file_format == "pcap"
    pkts = list(CaptureReader(_pcap(tmp_path, magic=0xA1B23C4D, packets=[b"\x00" * 60])).packets())
    assert pkts[0].ts_ns == 1700000000 * 10**9 + 5  # nanosecond resolution preserved


def test_rejects_unknown_magic(tmp_path):
    p = tmp_path / "bad.pcap"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    with pytest.raises(MalformedCaptureError):
        CaptureReader(p).scan()
    assert sniff_format(b"\x7fELF" + b"\x00" * 20) is None


def test_truncated_record_is_reported_not_crashing(tmp_path):
    p = _pcap(tmp_path, packets=[b"\x00" * 60, b"\x00" * 60])
    data = p.read_bytes()
    p.write_bytes(data[:-20])
    meta = CaptureReader(p).scan()
    assert meta.packet_count == 1
    assert meta.truncated_tail


def test_oversized_record_rejected(tmp_path):
    p = _pcap(tmp_path, packets=[b"\x00" * 60])
    data = bytearray(p.read_bytes())
    struct.pack_into("<I", data, 24 + 8, 10_000_000)  # caplen far beyond the limit
    p.write_bytes(bytes(data))
    with pytest.raises(MalformedCaptureError):
        CaptureReader(p).scan()


def test_pcapng_bad_block_length(tmp_path):
    src = (FIXTURES / "baseline.pcapng").read_bytes()
    corrupt = bytearray(src)
    shb_len = struct.unpack_from("<I", corrupt, 4)[0]
    struct.pack_into("<I", corrupt, shb_len + 4, 0xFFFFFFF0)  # IDB claims a 4 GiB block
    p = tmp_path / "c.pcapng"
    p.write_bytes(bytes(corrupt))
    with pytest.raises(MalformedCaptureError):
        CaptureReader(p).scan()


def test_packet_limit_stops_indexing(tmp_path):
    p = _pcap(tmp_path, packets=[b"\x00" * 60] * 5)
    meta = CaptureReader(p, max_packets=3).scan()
    assert meta.packet_count == 3
    assert any("Packet limit" in w for w in meta.warnings)


def test_single_packet_writer_roundtrip(tmp_path):
    dest = tmp_path / "one.pcap"
    write_single_packet_pcap(dest, 1, 1_700_000_000_123_456_789, b"\xaa" * 64, 64)
    pkts = list(CaptureReader(dest).packets())
    assert len(pkts) == 1 and pkts[0].caplen == 64
