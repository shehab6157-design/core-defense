"""APIS arm adapter: APIS network alerts -> strict 'lateral_movement' facts.

APIS watches network traffic - a DIFFERENT sensor from host logs - so
its alerts give the brain real second-sensor evidence. Each alert is
converted field by field into typed values. Anything that does not fit
is rejected and counted, never passed through. Free-text fields
(reasoning, paths, evidence notes) are never read at all.
APIS code is not modified: the adapter only reads its /alerts output.
"""
from __future__ import annotations

import ipaddress
import re

from barrier import barrier as br

TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
MAX_TECH = 5


class AdapterError(Exception):
    pass


def _ip(v) -> str:
    if not isinstance(v, str):
        raise AdapterError("ip must be text")
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise AdapterError("invalid ip") from None


def _techniques(v) -> list[str]:
    out = []
    for t in v if isinstance(v, list) else []:
        tid = t if isinstance(t, str) else (t.get("technique_id") or t.get("id")) if isinstance(t, dict) else None
        if isinstance(tid, str) and TECH_RE.fullmatch(tid) and tid.lower() not in out:
            out.append(tid.lower())
    return out[:MAX_TECH]


class ApisArm:
    def __init__(self, host_map: dict, scale: float = 100.0):
        """host_map: asset inventory {ip: hostname}. scale: APIS confidence maximum."""
        self.host_map = {}
        for ip, name in host_map.items():
            if not br.SAFE_VALUE.fullmatch(name):
                raise AdapterError(f"bad host name: {name!r}")
            self.host_map[_ip(ip)] = name
        self.scale = float(scale)
        self.rejected = 0

    def _confidence(self, v) -> int:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise AdapterError("confidence must be a number")
        if not 0 <= v <= self.scale:
            raise AdapterError("confidence out of range")
        return int(round(v * 100 / self.scale))

    def to_fact(self, record):
        """One APIS alert -> one validated fact, or None (suppressed or rejected)."""
        try:
            if not isinstance(record, dict):
                raise AdapterError("record must be an object")
            if record.get("suppressed") is True:
                return None  # APIS itself judged this benign
            pair = record.get("pair")
            if not isinstance(pair, dict):
                raise AdapterError("missing pair")
            src, dst = _ip(pair.get("src")), _ip(pair.get("dst"))
            fact = {
                "kind": "lateral_movement",
                "host": self.host_map.get(src, "unknown"),
                "src_ip": src,
                "dst_ip": dst,
                "confidence": self._confidence(record.get("confidence_score")),
                "techniques": _techniques(record.get("mitre_techniques")),
            }
            br.validate_fact(fact, frozenset(self.host_map.values()))
            return fact
        except (AdapterError, br.BarrierError):
            self.rejected += 1
            return None

    def from_alerts_response(self, payload) -> list[dict]:
        """The JSON body of APIS GET /alerts -> list of validated facts."""
        alerts = payload.get("alerts") if isinstance(payload, dict) else None
        if not isinstance(alerts, list):
            self.rejected += 1
            return []
        return [f for f in (self.to_fact(r) for r in alerts) if f is not None]
