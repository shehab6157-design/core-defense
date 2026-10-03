"""Immune memory + vaccination (Phase 6b).

IMMUNE MEMORY: when the operator confirms an incident, its attacker addresses
are broadcast as a signed message. Every arm stores them; any later fact from
such an address becomes 'known_attacker' evidence after one message hop.
  - only the operator can create memories (an attacker cannot plant a memory
    to turn the system against an innocent address)
  - memories expire (addresses get reassigned): default 7 days, max 30
VACCINATION: a confirmed attack timeline becomes a permanent regression
scenario, so no future learned version may ever stop detecting it.
"""
from __future__ import annotations

import ipaddress

from barrier import barrier as br
from brain import brain as bn
from ring import message as msg

DEFAULT_DAYS = 7
MAX_DAYS = 30
MAX_ADDRESSES = 50
MAX_EVENTS = 200
DAY = 86400.0


class ImmuneError(Exception):
    pass


def _operator_message(raw, ca_cert, operators, cache, mtype):
    try:
        m = msg.verify(raw, ca_cert, cache)
    except msg.MessageError:
        raise ImmuneError("rejected message") from None
    if m.type != mtype or m.sender not in operators:
        raise ImmuneError("untrusted operator")
    return m


class ImmuneMemory:
    def __init__(self, ca_cert, operators):
        self.ca_cert = ca_cert
        self.operators = frozenset(operators)
        self.entries: dict[str, tuple] = {}   # address -> (expires_at, incident)
        self._cache = msg.ReplayCache()

    def learn(self, raw: bytes, now: float) -> int:
        """Store a signed operator memory. Returns how many addresses were remembered."""
        m = _operator_message(raw, self.ca_cert, self.operators, self._cache, "memory")
        b = m.body
        if set(b) != {"incident", "addresses", "days"}:
            raise ImmuneError("bad memory fields")
        if not isinstance(b["incident"], str) or not br.SAFE_VALUE.fullmatch(b["incident"]):
            raise ImmuneError("bad incident name")
        days = b["days"]
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
            raise ImmuneError(f"memory must last 1 to {MAX_DAYS} days")
        addrs = b["addresses"]
        if not isinstance(addrs, list) or not 1 <= len(addrs) <= MAX_ADDRESSES:
            raise ImmuneError(f"1 to {MAX_ADDRESSES} addresses per memory")
        try:
            clean = [str(ipaddress.ip_address(a)) for a in addrs]
        except (ValueError, TypeError):
            raise ImmuneError("bad address in memory") from None
        for a in clean:
            self.entries[a] = (now + days * DAY, b["incident"])
        return len(clean)

    def check(self, fact, now: float):
        """If this fact comes from a remembered address, return a 'known_attacker' fact."""
        if not isinstance(fact, dict) or fact.get("kind") == "known_attacker":
            return None
        ip = fact.get("src_ip")
        entry = self.entries.get(ip) if isinstance(ip, str) else None
        if entry is None or now >= entry[0]:
            return None
        return {"kind": "known_attacker", "host": fact["host"], "src_ip": ip}


def vaccinate(learner, raw: bytes, now: float, ca_cert=None, operators=None) -> bool:
    """Add a signed operator vaccine to the learner's regression suite.
    Returns True if the CURRENT version already detects it, False (plus an alarm) if not."""
    ca_cert = ca_cert or learner.ca_cert
    operators = frozenset(operators or learner.operators)
    m = _operator_message(raw, ca_cert, operators, learner._cache, "vaccine")
    b = m.body
    if set(b) != {"name", "expected", "events"}:
        raise ImmuneError("bad vaccine fields")
    name, expected, events = b["name"], b["expected"], b["events"]
    if not isinstance(name, str) or not br.SAFE_VALUE.fullmatch(name):
        raise ImmuneError("bad vaccine name")
    if any(s[0] == name for s in learner.suite):
        raise ImmuneError("a scenario with this name already exists")
    if not (isinstance(expected, list) and len(expected) == 2
            and expected[0] in bn.ACTIONS and expected[1] in bn.REASONS):
        raise ImmuneError("bad expected result")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise ImmuneError(f"1 to {MAX_EVENTS} events per vaccine")
    timeline = []
    for ev in events:
        if not (isinstance(ev, list) and len(ev) == 2) or isinstance(ev[0], bool) \
                or not isinstance(ev[0], (int, float)) or ev[0] < 0:
            raise ImmuneError("bad event")
        try:
            br.validate_fact(ev[1], learner.inventory)
        except br.BarrierError:
            raise ImmuneError("invalid fact in vaccine") from None
        timeline.append((float(ev[0]), ev[1]))
    learner.suite = list(learner.suite) + [(name, "attack", tuple(expected), timeline)]
    ok, failures = learner.evaluate(learner.params())
    if not ok:
        learner.alarms.append(("current-version-misses-vaccine", tuple(failures)))
    return ok
