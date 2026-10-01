"""Signed messages for the ring (R1, R2, R4, T5).

Every message carries the sender's certificate and a signature over its
content, a timestamp, and a one-time nonce. Receivers reject anything
forged, altered, replayed, stale, oversized, or sent by the wrong role.
Every rejection has a reason, so it can be raised as attack evidence.
"""
from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ring import identity as idn

VERSION = 1
MAX_BYTES = 64 * 1024
MAX_AGE_SECONDS = 30
# Which roles may send which message types (least privilege)
ALLOWED = {
    "heartbeat": {"arm", "brain", "sensor", "barrier", "audit"},
    "challenge": {"arm", "brain", "sensor"},
    "response": {"arm", "brain", "sensor", "barrier", "audit"},
    "report": {"arm", "sensor"},
    "facts": {"barrier"},
    "proposal": {"brain"},
    "alert": {"arm", "brain", "sensor", "audit"},
}
_FIELDS = ("v", "type", "sender", "role", "ts", "nonce", "body", "cert")


class MessageError(Exception):
    """A rejected message. str(e) is the reason (attack evidence)."""


@dataclass(frozen=True)
class Message:
    type: str
    sender: str
    role: str
    ts: float
    nonce: str
    body: dict


def _canonical(fields: dict) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


class ReplayCache:
    """Remembers nonces until they are too old to be accepted anyway."""

    def __init__(self, ttl: float = 2 * MAX_AGE_SECONDS):
        self.ttl = ttl
        self._seen: dict[str, float] = {}

    def check_and_add(self, nonce: str, now: float) -> bool:
        for n in [n for n, t in self._seen.items() if now - t > self.ttl]:
            del self._seen[n]
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True


def sign(msg_type: str, body: dict, name: str, role: str, key, cert, now: float | None = None) -> bytes:
    if msg_type not in ALLOWED:
        raise MessageError(f"unknown message type: {msg_type!r}")
    fields = {
        "v": VERSION,
        "type": msg_type,
        "sender": name,
        "role": role,
        "ts": time.time() if now is None else now,
        "nonce": os.urandom(16).hex(),
        "body": body,
        "cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
    }
    sig = key.sign(_canonical(fields), ec.ECDSA(hashes.SHA256()))
    fields["sig"] = base64.b64encode(sig).decode()
    return json.dumps(fields).encode()


def verify(raw: bytes, ca_cert, cache: ReplayCache, now: float | None = None) -> Message:
    """Return the Message if fully trusted, else raise MessageError with the reason."""
    now = time.time() if now is None else now
    if len(raw) > MAX_BYTES:
        raise MessageError("oversized message")
    try:
        data = json.loads(raw)
    except ValueError:
        raise MessageError("malformed message") from None
    if not isinstance(data, dict) or set(data) != set(_FIELDS) | {"sig"}:
        raise MessageError("unexpected message fields")
    if data["v"] != VERSION:
        raise MessageError("unsupported version")
    if not isinstance(data["body"], dict) or isinstance(data["ts"], bool) \
            or not isinstance(data["ts"], (int, float)):
        raise MessageError("bad field types")
    for f in ("type", "sender", "role", "nonce", "cert", "sig"):
        if not isinstance(data[f], str):
            raise MessageError("bad field types")
    try:
        cert = x509.load_pem_x509_certificate(data["cert"].encode())
        name, role = idn.verify(cert, ca_cert)
    except idn.IdentityError as e:
        raise MessageError(f"untrusted sender: {e}") from None
    except ValueError:
        raise MessageError("malformed certificate") from None
    if name != data["sender"] or role != data["role"]:
        raise MessageError("sender does not match certificate")
    fields = {f: data[f] for f in _FIELDS}
    try:
        sig = base64.b64decode(data["sig"], validate=True)
        cert.public_key().verify(sig, _canonical(fields), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise MessageError("bad signature: message altered or forged") from None
    if data["type"] not in ALLOWED:
        raise MessageError(f"unknown message type: {data['type']!r}")
    if role not in ALLOWED[data["type"]]:
        raise MessageError(f"role {role!r} may not send {data['type']!r}")
    if abs(now - data["ts"]) > MAX_AGE_SECONDS:
        raise MessageError("stale or future-dated message")
    # Nonce is recorded only after every other check passes, so attackers
    # cannot fill the cache with junk messages
    if not cache.check_and_add(data["nonce"], now):
        raise MessageError("replayed message")
    return Message(data["type"], name, role, float(data["ts"]), data["nonce"], data["body"])


# Operator decisions (approve / deny / reset) - only the operator role may send them
ALLOWED["approval"] = {"operator"}


# Operator tolerance for known-harmless low-level alert patterns
ALLOWED["tolerance"] = {"operator"}
