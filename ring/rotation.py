"""Short life: identities renew before expiring, and old keys become tripwires (Phase 5a, T12).

- Component certificates are short-lived. A component renews when less
  than RENEW_FRACTION of its certificate's life remains.
- The replaced certificate is RETIRED. It may still be time-valid, but any
  message signed with it is refused and raised as an alarm: a retired key
  in use means someone copied it.
- Messages refused because their certificate EXPIRED also raise an alarm.
"""
from __future__ import annotations

import datetime as dt
import json

from cryptography import x509

from ring import identity as idn

RENEW_FRACTION = 0.25


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def cert_of(raw: bytes):
    """The sender certificate inside a signed message (call after verify succeeded)."""
    return x509.load_pem_x509_certificate(json.loads(raw)["cert"].encode())


class Rotation:
    def __init__(self, ca_key, ca_cert, hours: int = idn.DEFAULT_CERT_HOURS):
        self.ca_key = ca_key
        self.ca_cert = ca_cert
        self.hours = hours
        self.current: dict[str, int] = {}   # name -> serial of its current certificate
        self.retired: dict[int, str] = {}   # serial -> name
        self.alarms: list[tuple] = []        # (kind, who)

    def issue(self, name: str, role: str):
        key, cert = idn.issue(self.ca_key, self.ca_cert, name, role, self.hours)
        self.current[name] = cert.serial_number
        return key, cert

    @staticmethod
    def needs_renewal(cert, now: dt.datetime | None = None) -> bool:
        now = now or _now()
        life = cert.not_valid_after_utc - cert.not_valid_before_utc
        return cert.not_valid_after_utc - now <= life * RENEW_FRACTION

    def renew(self, name: str, role: str, old_cert):
        key, cert = self.issue(name, role)
        self.retired[old_cert.serial_number] = name
        return key, cert

    def check(self, raw: bytes, m) -> str | None:
        """After msg.verify succeeded: refuse messages signed with a retired key."""
        if cert_of(raw).serial_number in self.retired:
            self.alarms.append(("retired-key-in-use", m.sender))
            return "retired-key-in-use"
        return None

    def classify_rejection(self, reason: str, claimed_sender: str = "unknown") -> str | None:
        """After msg.verify FAILED: was it an expired key being used?"""
        if "expired" in reason:
            self.alarms.append(("expired-key-in-use", claimed_sender))
            return "expired-key-in-use"
        return None
