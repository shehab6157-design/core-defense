"""Brain: correlates validated facts and PROPOSES actions only (R4, R5, T1, T2, T7).

- Accepts only facts that pass the shared schema. Anything else is
  treated as evidence of tampering, never as input.
- Can only propose actions from a fixed allowlist. It cannot execute
  anything - arms decide (Phase 2: quorum + reversible actions).
- Strong actions (isolate) need SUSPICIOUS evidence from at least two
  INDEPENDENT sensors. Normal activity is never counted as evidence,
  and two facts from the same sensor count once.
- If the brain dies, arms keep defending on their own (ring heartbeats).
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from barrier import barrier as br

ACTIONS = ("watch", "collect_evidence", "deploy_decoy", "limit_access", "isolate")
STRONG = frozenset({"isolate"})
SENSORS = frozenset({"host-log", "ring", "network"})
NETWORK_KINDS = frozenset({"lateral_movement"})
REASONS = frozenset({
    "injection-attempt", "brute-force", "login-after-brute-force",
    "privilege-after-suspicious-login", "account-after-suspicious-login",
    "arm-silent", "arm-silent-on-suspicious-host", "invalid-fact",
    "lateral-movement", "lateral-movement-confirmed",
})
BRUTE_FORCE_THRESHOLD = 5
WINDOW = 300.0          # seconds of memory for correlation
DECOY_CONFIDENCE = 70   # network-only alerts at or above this -> deploy_decoy
CONFIRM_CONFIDENCE = 50 # with a second sensor, at or above this -> isolate


class BrainError(Exception):
    """A proposal that violates the brain's hard rules."""


@dataclass(frozen=True)
class Proposal:
    action: str
    host: str
    reason: str
    sources: tuple
    evidence: int

    def __post_init__(self):
        if self.action not in ACTIONS:
            raise BrainError(f"action not allowed: {self.action!r}")
        if self.reason not in REASONS:
            raise BrainError(f"unknown reason: {self.reason!r}")
        if not br.SAFE_VALUE.fullmatch(self.host):
            raise BrainError("invalid host")
        if not self.sources or not set(self.sources) <= SENSORS:
            raise BrainError("invalid sources")
        if self.action in STRONG and len(set(self.sources)) < 2:
            raise BrainError("strong action needs two independent sensors")

    def body(self) -> dict:
        return {"action": self.action, "host": self.host, "reason": self.reason,
                "sources": sorted(set(self.sources)), "evidence": self.evidence}


class Brain:
    def __init__(self, inventory=()):
        self.inventory = frozenset(inventory)
        self.proposals: list[Proposal] = []
        self._fails = defaultdict(deque)       # (host, src_ip) -> failure times
        self._evidence = defaultdict(deque)    # host -> (time, sensor) of SUSPICIOUS events only
        self._suspicious: dict[str, float] = {}

    # ---- helpers ----
    @staticmethod
    def _prune_times(q, now):
        while q and now - q[0] > WINDOW:
            q.popleft()

    def _note(self, host, sensor, now):
        """Record SUSPICIOUS evidence. Normal activity must never be noted."""
        self._evidence[host].append((now, sensor))

    def _sensors(self, host, now):
        q = self._evidence[host]
        while q and now - q[0][0] > WINDOW:
            q.popleft()
        return tuple(sorted({s for _, s in q}))

    def _suspicious_now(self, host, now):
        t = self._suspicious.get(host)
        return t is not None and now - t <= WINDOW

    def _escalate(self, host, reason, now):
        sensors = self._sensors(host, now)
        action = "isolate" if len(sensors) >= 2 else "limit_access"
        return Proposal(action, host, reason, sensors, len(self._evidence[host]))

    def _emit(self, props):
        self.proposals.extend(props)
        return props

    # ---- inputs ----
    def ingest(self, fact, now: float) -> list[Proposal]:
        """Take one validated fact. Returns any new proposals."""
        try:
            br.validate_fact(fact, self.inventory)
        except br.BarrierError:
            return self._emit([Proposal("collect_evidence", "unknown", "invalid-fact", ("host-log",), 1)])
        kind, host = fact["kind"], fact["host"]
        out = []
        if kind == "injection_attempt":
            self._note(host, "host-log", now)
            out.append(Proposal("collect_evidence", host, "injection-attempt", ("host-log",), 1))
        elif kind == "login_failed":
            q = self._fails[(host, fact["src_ip"])]
            q.append(now)
            self._prune_times(q, now)
            if len(q) == BRUTE_FORCE_THRESHOLD:
                self._note(host, "host-log", now)
                out.append(Proposal("watch", host, "brute-force", ("host-log",), len(q)))
        elif kind == "login_success":
            q = self._fails.get((host, fact["src_ip"]))
            if q is not None:
                self._prune_times(q, now)
                if len(q) >= BRUTE_FORCE_THRESHOLD:
                    self._note(host, "host-log", now)
                    self._suspicious[host] = now
                    out.append(self._escalate(host, "login-after-brute-force", now))
        elif kind in ("privilege_use", "account_created") and self._suspicious_now(host, now):
            self._note(host, "host-log", now)
            reason = ("privilege-after-suspicious-login" if kind == "privilege_use"
                      else "account-after-suspicious-login")
            out.append(self._escalate(host, reason, now))
        elif kind == "lateral_movement":
            out.append(self._network(fact, host, now))
        return self._emit(out)

    def _network(self, fact, host, now):
        if host == "unknown":
            # Source not in our inventory: we cannot act on it, only watch
            return Proposal("watch", "unknown", "lateral-movement", ("network",), 1)
        self._note(host, "network", now)
        self._suspicious[host] = now
        sensors = self._sensors(host, now)
        n = len(self._evidence[host])
        if len(sensors) >= 2 and fact["confidence"] >= CONFIRM_CONFIDENCE:
            return Proposal("isolate", host, "lateral-movement-confirmed", sensors, n)
        if fact["confidence"] >= DECOY_CONFIDENCE:
            return Proposal("deploy_decoy", host, "lateral-movement", sensors, n)
        return Proposal("watch", host, "lateral-movement", sensors, n)

    def ring_alert(self, peer: str, now: float) -> list[Proposal]:
        """A ring 'silent' alert about an arm. Arms are named after the host they guard."""
        if not br.SAFE_VALUE.fullmatch(peer):
            raise BrainError("bad peer name")
        self._note(peer, "ring", now)
        if self._suspicious_now(peer, now):
            return self._emit([self._escalate(peer, "arm-silent-on-suspicious-host", now)])
        return self._emit([Proposal("watch", peer, "arm-silent", ("ring",), 1)])
