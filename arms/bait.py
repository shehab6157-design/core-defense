"""Captured arm as bait (Phase 4c, T4).

If an arm is caught lying - it reports its host 'clean' while two
independent sensors see trouble there - it is treated as CAPTURED:
  - its identity is revoked: its messages are never trusted again, even
    though its certificate still verifies cryptographically
  - it is NOT shut down: whatever the attacker sends through it is kept
    as a record of their playbook (type, size, digest - never content)
  - a clean replacement arm with a new identity takes over
The playbook stores no attacker text, so the bait cannot be used to
inject anything into the brain.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass

from ring import identity as idn
from ring import message as msg

CONTRADICTIONS_TO_CAPTURE = 2   # one mismatch could be timing; two is a lie
INDEPENDENT_NEEDED = 2          # sensors other than the arm's own host logs
STATUSES = ("clean", "suspicious")


class QuarantineError(Exception):
    pass


@dataclass(frozen=True)
class PlaybookEntry:
    arm: str
    at: float
    msg_type: str
    size: int
    digest: str


def issue_replacement(ca_key, ca_cert, new_name: str):
    """Fresh identity for the clean replacement arm."""
    return idn.issue(ca_key, ca_cert, new_name, "arm")


class Quarantine:
    def __init__(self, ca_cert=None, operators=()):
        self.ca_cert = ca_cert
        self.operators = frozenset(operators)
        self.revoked: dict[str, tuple] = {}       # arm -> (since, why)
        self.replacements: dict[str, str] = {}    # captured arm -> replacement name
        self.playbook: list[PlaybookEntry] = []
        self._contradictions = defaultdict(int)
        self._generation = defaultdict(int)
        self._cache = msg.ReplayCache()

    @staticmethod
    def _base(name: str) -> str:
        return re.sub(r"-r\d+$", "", name)

    def capture(self, arm: str, now: float, why: str) -> str:
        """Revoke an arm and return the name of its clean replacement."""
        try:
            idn.check_name(arm)
        except idn.IdentityError:
            raise QuarantineError("bad arm name") from None
        if arm in self.revoked:
            return self.replacements[arm]
        base = self._base(arm)
        self._generation[base] += 1
        new = f"{base}-r{self._generation[base]}"
        idn.check_name(new)
        self.revoked[arm] = (now, why)
        self.replacements[arm] = new
        return new

    def is_trusted(self, sender: str) -> bool:
        return sender not in self.revoked

    def route(self, m, raw: bytes, now: float) -> str:
        """Call AFTER msg.verify succeeded. Returns 'trusted' or 'bait'."""
        if m.sender in self.revoked:
            self.playbook.append(PlaybookEntry(
                m.sender, now, m.type, len(raw), hashlib.sha256(raw).hexdigest()[:16]))
            return "bait"
        return "trusted"

    def check_report(self, arm: str, host: str, status: str, other_sensors, now: float):
        """An arm reports its host's status. Returns replacement name if it is now captured."""
        if status not in STATUSES:
            raise QuarantineError("bad status")
        if arm in self.revoked:
            return None
        independent = set(other_sensors) - {"host-log"}
        if status == "clean" and len(independent) >= INDEPENDENT_NEEDED:
            self._contradictions[arm] += 1
            if self._contradictions[arm] >= CONTRADICTIONS_TO_CAPTURE:
                return self.capture(arm, now, "contradiction")
        return None

    def handle_operator(self, raw: bytes, now: float) -> str:
        try:
            m = msg.verify(raw, self.ca_cert, self._cache)
        except msg.MessageError:
            raise QuarantineError("rejected message") from None
        if m.type != "quarantine" or m.sender not in self.operators:
            raise QuarantineError("untrusted operator")
        if set(m.body) != {"arm"} or not isinstance(m.body["arm"], str):
            raise QuarantineError("bad quarantine request")
        return self.capture(m.body["arm"], now, "operator")
