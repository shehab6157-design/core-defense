"""Heartbeat monitor: silence is the alarm (R7, T3, T6).

Peers send signed heartbeats. If a peer goes quiet longer than the
timeout, ONE alert is raised and the detection time is recorded.
Only verified messages count as signs of life, so forged heartbeats
cannot keep a killed arm "alive" - they are logged as evidence instead.
Uses a monotonic clock, so changing the system time cannot hide silence.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

INTERVAL = 2.0
MISSES_ALLOWED = 2  # timeout = INTERVAL * (MISSES_ALLOWED + 1) = 6s


@dataclass(frozen=True)
class Alert:
    kind: str  # silent | recovered | unexpected-peer | rejected-message
    peer: str
    at: float
    detail: str = ""


class HeartbeatMonitor:
    def __init__(self, expected_peers, interval=INTERVAL, misses_allowed=MISSES_ALLOWED, now=None):
        start = self._t(now)
        self.interval = interval
        self.timeout = interval * (misses_allowed + 1)
        # Every expected peer gets one timeout of grace from startup
        self.last_seen = {p: start for p in expected_peers}
        self.silent: dict[str, float] = {}
        self.alerts: list[Alert] = []
        self._unexpected: set[str] = set()

    @staticmethod
    def _t(now):
        return time.monotonic() if now is None else now

    def observe(self, m, now=None) -> list[Alert]:
        """Record a VERIFIED message (from ring.message.verify) as a sign of life."""
        now = self._t(now)
        new = []
        if m.sender not in self.last_seen:
            if m.sender not in self._unexpected:
                self._unexpected.add(m.sender)
                new.append(Alert("unexpected-peer", m.sender, now, f"{m.role} not in expected peers"))
        else:
            self.last_seen[m.sender] = now
            if m.sender in self.silent:
                down = now - self.silent.pop(m.sender)
                new.append(Alert("recovered", m.sender, now, f"back {down:.1f}s after alert"))
        self.alerts.extend(new)
        return new

    def rejected(self, reason: str, now=None, source: str = "unknown") -> list[Alert]:
        """Record a message that failed verification - it is attack evidence."""
        a = Alert("rejected-message", source, self._t(now), reason)
        self.alerts.append(a)
        return [a]

    def check(self, now=None) -> list[Alert]:
        """Call regularly. Raises one 'silent' alert per peer that went quiet."""
        now = self._t(now)
        new = []
        for peer, seen in self.last_seen.items():
            gap = now - seen
            if peer not in self.silent and gap > self.timeout:
                self.silent[peer] = now
                new.append(Alert("silent", peer, now, f"no heartbeat for {gap:.1f}s"))
        self.alerts.extend(new)
        return new
