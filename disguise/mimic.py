"""Mimic: decoys tailored to what each attacker is hunting (Phase 4b).

Like the mimic octopus choosing its disguise for the predator in front of
it, Mimic watches each attacker's activity and plants the decoy they would
want most. Every decoy carries a unique secret token. No legitimate user
ever touches a decoy, so a touch becomes near-certain 'decoy_touched'
evidence for the brain.
Safety:
  - decoys are PASSIVE: they record and mislead, never attack back
  - no real secrets are ever placed in a decoy
  - caps per attacker and in total, so attackers cannot exhaust resources
  - allowlisted internal scanners are ignored (no false alarms from them)
"""
from __future__ import annotations

import ipaddress
import secrets
from collections import defaultdict
from dataclasses import dataclass

from barrier import barrier as br

INTEREST_OF = {
    "login_failed": "credentials", "login_success": "credentials",
    "lateral_movement": "remote-access",
    "group_added": "admin-rights", "privilege_use": "admin-rights",
    "file_burst": "files",
    "agent_anomaly": "ai-tools", "injection_attempt": "ai-tools",
}
DECOY_FOR = {
    "credentials": "honey-credential", "remote-access": "decoy-host",
    "admin-rights": "honey-admin", "files": "honey-files", "ai-tools": "honey-tool",
}
MAX_PER_ATTACKER = 3
MAX_TOTAL = 50


class MimicError(Exception):
    pass


@dataclass(frozen=True)
class Decoy:
    id: str
    kind: str
    token: str
    attacker: str
    created_at: float
    personality: dict | None = None


def _ip(v: str) -> str:
    return str(ipaddress.ip_address(v))


class Mimic:
    def __init__(self, camouflage, host_map: dict, inventory=(), scanners=()):
        """host_map: {internal ip: host name}. inventory: hosts facts may name."""
        self.cam = camouflage
        self.host_map = {_ip(ip): name for ip, name in host_map.items()}
        self.inventory = frozenset(inventory) | frozenset(self.host_map.values())
        self.scanners = frozenset(_ip(s) for s in scanners)
        self.decoys: dict[str, Decoy] = {}
        self._by_token: dict[str, Decoy] = {}
        self._planted = defaultdict(set)   # attacker -> decoy kinds already planted
        self.refused = 0                   # decoys not planted because of caps
        self.ignored_touches = 0           # touches from allowlisted scanners

    def observe(self, fact, now: float) -> list[Decoy]:
        """Feed a validated fact. Returns any newly planted decoys."""
        br.validate_fact(fact, self.inventory)
        interest = INTEREST_OF.get(fact["kind"])
        if interest is None:
            return []
        attacker = fact.get("src_ip") or f"host:{fact['host']}"
        kind = DECOY_FOR[interest]
        if kind in self._planted[attacker]:
            return []  # this attacker already has bait for this interest
        if len(self._planted[attacker]) >= MAX_PER_ATTACKER or len(self.decoys) >= MAX_TOTAL:
            self.refused += 1
            return []
        n = len(self.decoys) + 1
        decoy_id = f"decoy-{n:03d}"
        personality = self.cam.profile(decoy_id, bait=True) if kind == "decoy-host" else None
        d = Decoy(decoy_id, kind, secrets.token_hex(16), attacker, now, personality)
        self.decoys[d.id] = d
        self._by_token[d.token] = d
        self._planted[attacker].add(kind)
        return [d]

    def touch(self, token: str, src_ip: str, now: float):
        """A decoy token was used. Returns a validated 'decoy_touched' fact, or None."""
        d = self._by_token.get(token) if isinstance(token, str) else None
        if d is None:
            return None
        try:
            src = _ip(src_ip)
        except (ValueError, TypeError):
            raise MimicError("bad source address") from None
        if src in self.scanners:
            self.ignored_touches += 1
            return None
        fact = {"kind": "decoy_touched", "host": self.host_map.get(src, "unknown"),
                "decoy_kind": d.kind, "src_ip": src}
        br.validate_fact(fact, self.inventory)
        return fact
