"""X.509 certificate parsing for certificates visible in cleartext TLS handshakes."""

from __future__ import annotations

import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger(__name__)

MAX_CERT_BYTES = 64 * 1024


def _name_attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value)[:256] if attrs else None


def parse_certificate_hex(hexder: str) -> dict | None:
    """Return a summary of a DER certificate given as hex (as printed by tshark)."""
    try:
        cleaned = hexder.replace(":", "").strip()
        if len(cleaned) > MAX_CERT_BYTES * 2:
            return None
        der = bytes.fromhex(cleaned)
        cert = x509.load_der_x509_certificate(der)
    except (ValueError, TypeError) as exc:
        log.debug("certificate parse failed: %s", exc)
        return None
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc = f"RSA {key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc = f"EC {key.curve.name}"
    elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_desc = type(key).__name__.replace("PublicKey", "")
    elif isinstance(key, dsa.DSAPublicKey):
        key_desc = f"DSA {key.key_size}"
    else:
        key_desc = "unknown"
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(v) for v in ext.value.get_values_for_type(x509.DNSName)][:50]
    except x509.ExtensionNotFound:
        pass
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001 - unsupported algorithms raise various errors
        sig = None
    return {
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "subject": cert.subject.rfc4514_string()[:512],
        "issuer_cn": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer": cert.issuer.rfc4514_string()[:512],
        "serial": format(cert.serial_number, "x")[:64],
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "not_before_ns": int(cert.not_valid_before_utc.timestamp()) * 1_000_000_000,
        "not_after_ns": int(cert.not_valid_after_utc.timestamp()) * 1_000_000_000,
        "san_dns": sans,
        "self_signed": cert.issuer == cert.subject,
        "public_key": key_desc,
        "signature_hash": sig,
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
    }
