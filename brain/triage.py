"""Alert triage: pheromone-style decay + operator tolerance (Phase 3b, P5).

Analysts drown in one-off alerts. Like ant trails, each alert here has a
STRENGTH that fades over time unless reinforced by more evidence:
  - one weak, isolated alert fades away without paging anyone
  - repeated or multi-sensor evidence builds strength and rises to the top
  - strong actions (limit_access, isolate) are always shown
Operators can TOLERATE a known-harmless LOW-LEVEL pattern for a limited
time (signed message). Tolerance can never hide damage signals or an
escalation to a strong action.
Triage only changes what the HUMAN sees - it never blocks a defensive action.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from barrier import barrier as br
from brain.brain import ACTIONS
from ring import message as msg

WEIGHT = {"watch": 1.0, "collect_evidence": 1.5, "deploy_decoy": 2.0, "limit_access": 4.0, "isolate": 8.0}
HALF_LIFE = 600.0          # seconds for an alert's strength to halve
SHOW_THRESHOLD = 1.5   # 2 weak alerts within ~10 min, or 1 medium alert
ALWAYS_SHOW = frozenset({"limit_access", "isolate"})
TOLERABLE = frozenset({"brute-force", "arm-silent", "lateral-movement", "agent-anomaly"})
MAX_TOLERANCE_HOURS = 168


class TriageError(Exception):
    pass


@dataclass
class Trail:
    host: str
    reason: str
    strength: float
    updated: float
    top_action: str
    sensors: set = field(default_factory=set)
    count: int = 0


def _decay(strength: float, dt: float) -> float:
    return strength * 0.5 ** (max(dt, 0.0) / HALF_LIFE)


class Triage:
    def __init__(self, ca_cert=None, operators=()):
        self.trails: dict[tuple, Trail] = {}
        self.tolerated: dict[tuple, float] = {}
        self.ca_cert = ca_cert
        self.operators = frozenset(operators)
        self.rejected: list[str] = []
        self._cache = msg.ReplayCache()

    def add(self, p, now: float) -> Trail:
        key = (p.host, p.reason)
        t = self.trails.get(key)
        if t is None:
            t = self.trails[key] = Trail(p.host, p.reason, 0.0, now, p.action)
        t.strength = _decay(t.strength, now - t.updated) + WEIGHT[p.action] * len(set(p.sources))
        t.updated = now
        t.count += 1
        t.sensors |= set(p.sources)
        if ACTIONS.index(p.action) > ACTIONS.index(t.top_action):
            t.top_action = p.action
        return t

    def strength(self, t: Trail, now: float) -> float:
        return _decay(t.strength, now - t.updated)

    def _hidden_by_tolerance(self, t: Trail, now: float) -> bool:
        until = self.tolerated.get((t.host, t.reason))
        return until is not None and now < until and t.top_action not in ALWAYS_SHOW

    def is_visible(self, t: Trail, now: float) -> bool:
        if self._hidden_by_tolerance(t, now):
            return False
        return t.top_action in ALWAYS_SHOW or self.strength(t, now) >= SHOW_THRESHOLD

    def visible(self, now: float) -> list[Trail]:
        shown = [t for t in self.trails.values() if self.is_visible(t, now)]
        return sorted(shown, key=lambda t: -self.strength(t, now))

    def handle_operator(self, raw: bytes, now: float) -> tuple:
        try:
            m = msg.verify(raw, self.ca_cert, self._cache)
        except msg.MessageError as e:
            self.rejected.append(str(e))
            raise TriageError("rejected message") from None
        if m.type != "tolerance" or m.sender not in self.operators:
            self.rejected.append("untrusted operator")
            raise TriageError("untrusted operator")
        b = m.body
        if set(b) != {"host", "reason", "hours"}:
            raise TriageError("bad tolerance fields")
        host, reason, hours = b["host"], b["reason"], b["hours"]
        if not isinstance(host, str) or not br.SAFE_VALUE.fullmatch(host):
            raise TriageError("bad host")
        if reason not in TOLERABLE:
            raise TriageError("this kind of alert can never be tolerated")
        if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= MAX_TOLERANCE_HOURS:
            raise TriageError("tolerance must be 1 to 168 hours")
        self.tolerated[(host, reason)] = now + hours * 3600
        return (host, reason)
