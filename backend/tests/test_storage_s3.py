"""S3 evidence backend against moto's in-process S3."""

import pytest

moto = pytest.importorskip("moto")


@pytest.fixture
def s3(monkeypatch, tmp_path):
    from app.core.config import get_settings

    for k, v in {"PKO_STORAGE_BACKEND": "s3", "PKO_S3_BUCKET": "evidence-test", "PKO_S3_REGION": "us-east-1",
                 "PKO_S3_ACCESS_KEY": "test", "PKO_S3_SECRET_KEY": "test", "PKO_S3_ENDPOINT_URL": ""}.items():
        monkeypatch.setenv(k, v)
    from app.storage import get_storage

    get_settings.cache_clear()
    get_storage.cache_clear()
    with moto.mock_aws():
        yield get_storage()
    get_settings.cache_clear()
    get_storage.cache_clear()


def test_roundtrip_with_server_side_encryption(s3, tmp_path):
    src = tmp_path / "a.pcapng"
    src.write_bytes(b"\x0a\x0d\x0d\x0a" + b"x" * 100)
    key = "tenants/ten_a/captures/cap_1/original.pcapng"
    s3.put_file(key, src, "application/vnd.tcpdump.pcap")
    assert s3.exists(key) and s3.size(key) == 104
    head = s3.client.head_object(Bucket=s3.bucket, Key=key)
    assert head["ServerSideEncryption"] == "AES256"
    dest = tmp_path / "b.pcapng"
    s3.get_to_file(key, dest)
    assert dest.read_bytes() == src.read_bytes()
    assert s3.open_read(key).read(4) == b"\x0a\x0d\x0d\x0a"


def test_delete_prefix_is_scoped(s3, tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"1")
    for k in ("tenants/ten_a/captures/cap_1/original.pcap", "tenants/ten_a/captures/cap_1/derived/packets.parquet",
              "tenants/ten_a/captures/cap_2/original.pcap", "tenants/ten_b/captures/cap_1/original.pcap"):
        s3.put_file(k, f)
    assert s3.delete_prefix("tenants/ten_a/captures/cap_1/") == 2
    assert s3.exists("tenants/ten_a/captures/cap_2/original.pcap")
    assert s3.exists("tenants/ten_b/captures/cap_1/original.pcap")
