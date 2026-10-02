"""Brain: correlates validated facts and PROPOSES actions only (R4, R5, T1, T2, T7, P3).

- Accepts only facts that pass the shared schema. Anything else is
  treated as evidence of tampering, never as input.
- Can only propose actions from a fixed allowlist. It cannot execute
  anything - arms decide (quorum gate + safety layer).
- Strong actions (isolate) need SUSPICIOUS evidence from at least two
  INDEPENDENT sensors. Normal activity is never counted as evidence,
  and two facts from the same sensor count once.
- Damage signals (Danger Theory) catch attacks with no known signature.
- Adaptive sensitivity (Phase 3c):
    INFLAMMATION - a host with active suspicious evidence uses lower
                   detection thresholds; the rest of the network does not.
    FEVER        - when several hosts are in trouble at once, the whole
                   network uses lower thresholds for a while.
  Both are temporary, have fixed floors, fever is capped with a cooldown,
  and NEITHER ever weakens the two-sensor rule for isolate.
- If the brain dies, arms keep defending on their own (ring heartbeats).
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass

from barrier import barrier as br

ACTIONS = ("watch", "collect_evidence", "deploy_decoy", "limit_access", "isolate")
STRONG = frozenset({"isolate"})
SENSORS = frozenset({"host-log", "ring", "network", "agent", "process", "file"})
REASONS = frozenset({
    "injection-attempt", "brute-force", "login-after-brute-force",
    "privilege-after-suspicious-login", "account-after-suspicious-login",
    "arm-silent", "arm-silent-on-suspicious-host", "invalid-fact",
    "lateral-movement", "lateral-movement-confirmed",
    "agent-anomaly", "agent-anomaly-confirmed",
    "service-spawned-shell", "privilege-granted", "mass-file-change",
})
WINDOW = 300.0          # seconds of memory for correlation (also inflammation length)
CONFIRM_CONFIDENCE = 50 # with a second sensor, at or above this -> isolate (never adapted)
MASS_WINDOW = 120       # file bursts must happen within this many seconds

# Detection thresholds. INFLAMED values are hard floors - never more sensitive.
NORMAL = {"brute_force": 5, "decoy": 70, "mass_modified": 200, "mass_renamed": 50}
FEVER = {"brute_force": 4, "decoy": 60, "mass_modified": 150, "mass_renamed": 40}
INFLAMED = {"brute_force": 3, "decoy": 55, "mass_modified": 100, "mass_renamed": 25}
FEVER_HOSTS = 3          # hosts in trouble at once -> fever
FEVER_DURATION = 900.0   # fever lasts this long after the last trigger
FEVER_MAX = 3600.0       # fever can never run longer than this continuously...
FEVER_COOLDOWN = 1800.0  # ...and then must cool down this long before it can return

# Kept for compatibility with earlier code
BRUTE_FORCE_THRESHOLD = NORMAL["brute_force"]
DECOY_CONFIDENCE = NORMAL["decoy"]


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
        self.fever_log: list[tuple] = []        # (start, end) of past fevers
        self._fails = defaultdict(deque)        # (host, src_ip) -> failure times
        self._bf_alerted: set = set()           # brute-force bursts already reported
        self._evidence = defaultdict(deque)     # host -> (time, sensor) of SUSPICIOUS events only
        self._suspicious: dict[str, float] = {}
        self._fever_start = None
        self._fever_until = float("-inf")
        self._fever_blocked_until = float("-inf")

    # ---- helpers ----
    @staticmethod
    def _prune_times(q, now):
        while q and now - q[0] > WINDOW:
            q.popleft()

    def _note(self, host, sensor, now):
        """Record SUSPICIOUS evidence. Normal activity must never be noted."""
        self._evidence[host].append((now, sensor))
        self._update_fever(now)

    def _sensors(self, host, now):
        q = self._evidence[host]
        while q and now - q[0][0] > WINDOW:
            q.popleft()
        return tuple(sorted({s for _, s in q}))

    def evidence_sensors(self, host: str, now: float) -> set:
        """Sensors that reported SUSPICIOUS evidence about host within the window."""
        return set(self._sensors(host, now))

    def _suspicious_now(self, host, now):
        t = self._suspicious.get(host)
        return t is not None and now - t <= WINDOW

    def _escalate(self, host, reason, now):
        sensors = self._sensors(host, now)
        action = "isolate" if len(sensors) >= 2 else "limit_access"
        return Proposal(action, host, reason, sensors, len(self._evidence[host]))

    def _damage(self, host, sensor, reason, now):
        self._note(host, sensor, now)
        self._suspicious[host] = now
        return self._escalate(host, reason, now)

    def _emit(self, props):
        self.proposals.extend(props)
        return props

    # ---- adaptive sensitivity ----
    def _update_fever(self, now):
        hot = sum(1 for h in list(self._evidence) if self._sensors(h, now))
        if self._fever_start is not None:
            capped = now - self._fever_start >= FEVER_MAX
            if capped or now >= self._fever_until:
                end = min(self._fever_until, self._fever_start + FEVER_MAX)
                self.fever_log.append((self._fever_start, end))
                if capped:
                    self._fever_blocked_until = end + FEVER_COOLDOWN
                self._fever_start = None
        if hot >= FEVER_HOSTS and now >= self._fever_blocked_until:
            if self._fever_start is None:
                self._fever_start = now
            self._fever_until = now + FEVER_DURATION

    def fever_active(self, now: float) -> bool:
        self._update_fever(now)
        return self._fever_start is not None

    def inflamed(self, host: str, now: float) -> bool:
        return bool(self._sensors(host, now))

    def thresholds(self, host: str, now: float) -> dict:
        if self.inflamed(host, now):
            return INFLAMED
        if self.fever_active(now):
            return FEVER
        return NORMAL

    # ---- inputs ----
    def ingest(self, fact, now: float) -> list[Proposal]:
        """Take one validated fact. Returns any new proposals."""
        try:
            br.validate_fact(fact, self.inventory)
        except br.BarrierError:
            return self._emit([Proposal("collect_evidence", "unknown", "invalid-fact", ("host-log",), 1)])
        kind, host = fact["kind"], fact["host"]
        th = self.thresholds(host, now)  # decided BEFORE this event adds evidence
        out = []
        if kind == "injection_attempt":
            self._note(host, "host-log", now)
            out.append(Proposal("collect_evidence", host, "injection-attempt", ("host-log",), 1))
        elif kind == "login_failed":
            key = (host, fact["src_ip"])
            q = self._fails[key]
            q.append(now)
            self._prune_times(q, now)
            if len(q) == 1:
                self._bf_alerted.discard(key)  # a fresh burst
            if len(q) >= th["brute_force"] and key not in self._bf_alerted:
                self._bf_alerted.add(key)
                self._note(host, "host-log", now)
                out.append(Proposal("watch", host, "brute-force", ("host-log",), len(q)))
        elif kind == "login_success":
            q = self._fails.get((host, fact["src_ip"]))
            if q is not None:
                self._prune_times(q, now)
                if len(q) >= th["brute_force"]:
                    self._note(host, "host-log", now)
                    self._suspicious[host] = now
                    out.append(self._escalate(host, "login-after-brute-force", now))
        elif kind in ("privilege_use", "account_created") and self._suspicious_now(host, now):
            self._note(host, "host-log", now)
            reason = ("privilege-after-suspicious-login" if kind == "privilege_use"
                      else "account-after-suspicious-login")
            out.append(self._escalate(host, reason, now))
        elif kind == "lateral_movement":
            out.append(self._network(fact, host, now, th))
        elif kind == "agent_anomaly":
            out.append(self._agent(fact, host, now))
        elif kind == "group_added" and fact["group"] != "other":
            out.append(self._damage(host, "host-log", "privilege-granted", now))
        elif (kind == "process_spawn" and fact["parent"] in br.SERVICE_PROCS
              and fact["child"] in br.SHELLS):
            out.append(self._damage(host, "process", "service-spawned-shell", now))
        elif (kind == "file_burst" and fact["window"] <= MASS_WINDOW
              and (fact["modified"] >= th["mass_modified"] or fact["renamed"] >= th["mass_renamed"])):
            out.append(self._damage(host, "file", "mass-file-change", now))
        return self._emit(out)

    def _network(self, fact, host, now, th):
        if host == "unknown":
            # Source not in our inventory: we cannot act on it, only watch
            return Proposal("watch", "unknown", "lateral-movement", ("network",), 1)
        self._note(host, "network", now)
        self._suspicious[host] = now
        sensors = self._sensors(host, now)
        n = len(self._evidence[host])
        if len(sensors) >= 2 and fact["confidence"] >= CONFIRM_CONFIDENCE:
            return Proposal("isolate", host, "lateral-movement-confirmed", sensors, n)
        if fact["confidence"] >= th["decoy"]:
            return Proposal("deploy_decoy", host, "lateral-movement", sensors, n)
        return Proposal("watch", host, "lateral-movement", sensors, n)

    def _agent(self, fact, host, now):
        if fact["tier"] != "alert":
            # A single weak signal is worth watching, not counting as evidence
            return Proposal("watch", host, "agent-anomaly", ("agent",), 1)
        self._note(host, "agent", now)
        self._suspicious[host] = now
        sensors = self._sensors(host, now)
        reason = "agent-anomaly-confirmed" if len(sensors) >= 2 else "agent-anomaly"
        return self._escalate(host, reason, now)

    def ring_alert(self, peer: str, now: float) -> list[Proposal]:
        """A ring 'silent' alert about an arm. Arms are named after the host they guard."""
        if not br.SAFE_VALUE.fullmatch(peer):
            raise BrainError("bad peer name")
        self._note(peer, "ring", now)
        if self._suspicious_now(peer, now):
            return self._emit([self._escalate(peer, "arm-silent-on-suspicious-host", now)])
        return self._emit([Proposal("watch", peer, "arm-silent", ("ring",), 1)])
