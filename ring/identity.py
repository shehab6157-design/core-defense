"""Component identities (R1, R3).

A private certificate authority (CA) issues each component its own
short-lived certificate. Nothing is trusted because of where it comes
from - only because it carries a valid certificate from our CA.
"""
from __future__ import annotations

import datetime as dt
import os
import re
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROLES = frozenset({"brain", "arm", "barrier", "sensor", "audit", "operator"})
CA_NAME = "core-defense-ca"
CA_DAYS = 365
DEFAULT_CERT_HOURS = 24
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


class IdentityError(Exception):
    """Raised when an identity is invalid or untrusted."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def check_name(name: str) -> None:
    # Names become file names, so block path tricks like "../ca"
    if not _NAME_RE.match(name) or name == "ca":
        raise IdentityError(f"invalid component name: {name!r}")


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)


def _key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def create_ca(directory: Path):
    directory = Path(directory)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write_private(directory / "ca.key", _key_pem(key))
    (directory / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def load_ca(directory: Path, password: str | None = None):
    directory = Path(directory)
    data = (directory / "ca.key").read_bytes()
    encrypted = b"ENCRYPTED" in data
    if encrypted and not password:
        raise IdentityError("CA key is encrypted - passphrase required")
    try:
        key = serialization.load_pem_private_key(data, password=password.encode() if encrypted else None)
    except (ValueError, TypeError):
        raise IdentityError("could not unlock CA key (wrong passphrase?)") from None
    cert = x509.load_pem_x509_certificate((directory / "ca.crt").read_bytes())
    return key, cert


def issue(ca_key, ca_cert, name: str, role: str, hours: int = DEFAULT_CERT_HOURS):
    check_name(name)
    if role not in ROLES:
        raise IdentityError(f"unknown role: {role!r}")
    if not 0 < hours <= 24 * 7:
        raise IdentityError("certificate lifetime must be 1 hour to 7 days")
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(hours=hours))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def save_identity(directory: Path, name: str, key, cert) -> None:
    check_name(name)
    directory = Path(directory)
    _write_private(directory / f"{name}.key", _key_pem(key))
    (directory / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def verify(cert, ca_cert, expected_role: str | None = None, now: dt.datetime | None = None):
    """Return (name, role) if the certificate is trusted, else raise IdentityError."""
    now = now or _now()
    if cert.issuer != ca_cert.subject:
        raise IdentityError("certificate not issued by our CA")
    try:
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    except InvalidSignature:
        raise IdentityError("bad signature: forged or foreign certificate") from None
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise IdentityError("certificate expired or not yet valid")
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise IdentityError("certificate missing basic constraints") from None
    if bc.ca:
        raise IdentityError("component certificate must not be a CA")
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    ous = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if len(cns) != 1 or len(ous) != 1:
        raise IdentityError("certificate missing name or role")
    name, role = cns[0].value, ous[0].value
    if role not in ROLES:
        raise IdentityError(f"unknown role: {role!r}")
    if expected_role is not None and role != expected_role:
        raise IdentityError(f"role mismatch: expected {expected_role}, got {role}")
    return name, role


# ---------- Phase 5a: protect the root of trust (T12) ----------

MIN_PASSPHRASE = 12


def protect_ca(directory: Path, passphrase: str) -> None:
    """Encrypt an unencrypted CA key in place. A stolen copy is useless without the passphrase."""
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise IdentityError(f"passphrase must be at least {MIN_PASSPHRASE} characters")
    key, _ = load_ca(directory)  # fails if it is already encrypted
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(passphrase.encode()))
    _write_private(Path(directory) / "ca.key", pem)
