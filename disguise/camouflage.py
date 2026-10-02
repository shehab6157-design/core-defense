"""Camouflage: control what a host reveals to fingerprinting (Phase 4a, P3).

Attackers fingerprint before they attack: banners, version strings, open
ports, error pages tell them which exploit to use. Camouflage:
  - normalizes real banners to generic values (no exact patch level)
  - gives each host a CONSISTENT fake profile, so answers never contradict
    each other (inconsistency is how fake services get spotted)
  - optionally presents a decoy profile for a host that is bait
Everything here is PASSIVE: it only decides what to say, never attacks.
This is the policy engine; wiring it to a live socket happens in the demo.
"""
from __future__ import annotations

import hashlib
import hmac

from barrier import barrier as br

# Generic banners - believable, but revealing no version or OS detail
GENERIC = {
    "http": "Server: web",
    "ssh": "SSH-2.0-OpenSSH",
    "ftp": "220 FTP ready",
    "smtp": "220 mail ready",
}
# A small set of plausible decoy personalities for bait hosts
DECOY_PROFILES = (
    {"http": "Server: Apache", "os": "linux", "open": ("http", "ssh")},
    {"http": "Server: nginx", "os": "linux", "open": ("http",)},
    {"http": "Server: Microsoft-IIS", "os": "windows", "open": ("http", "smtp")},
)
KNOWN_SERVICES = frozenset({"http", "https", "ssh", "ftp", "smtp", "dns", "rdp"})


class CamouflageError(Exception):
    pass


def normalize_banner(service: str, raw_banner: str) -> str:
    """Strip version/OS detail from a real banner down to a generic one."""
    if service not in GENERIC:
        raise CamouflageError(f"unknown service: {service!r}")
    return GENERIC[service]


class Camouflage:
    def __init__(self, salt: bytes, real_services=()):
        if len(salt) < 16:
            raise CamouflageError("salt must be at least 16 bytes")
        self._salt = salt
        self.real = frozenset(real_services)
        bad = self.real - KNOWN_SERVICES
        if bad:
            raise CamouflageError(f"unknown services: {sorted(bad)}")

    def _choice(self, host: str) -> dict:
        d = hmac.new(self._salt, f"decoy:{host}".encode("utf-8", "replace"), hashlib.sha256).digest()
        return DECOY_PROFILES[d[0] % len(DECOY_PROFILES)]

    def profile(self, host: str, bait: bool = False) -> dict:
        """What this host should present. Deterministic per host."""
        if not br.SAFE_VALUE.fullmatch(host):
            raise CamouflageError("bad host name")
        if bait:
            p = self._choice(host)
            return {"host": host, "bait": True, "os": p["os"],
                    "open_services": list(p["open"]),
                    "banners": {s: p.get(s, GENERIC[s]) for s in p["open"] if s in GENERIC}}
        # Real host: show only generic banners for the services it actually runs
        return {"host": host, "bait": False, "os": "generic",
                "open_services": sorted(self.real),
                "banners": {s: GENERIC[s] for s in sorted(self.real) if s in GENERIC}}

    def answer(self, host: str, service: str, bait: bool = False) -> str | None:
        """What to reply to a probe of one service. None = port appears closed."""
        prof = self.profile(host, bait)
        if service not in prof["open_services"]:
            return None
        return prof["banners"].get(service, "")
