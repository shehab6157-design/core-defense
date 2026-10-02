"""Survival mode + last breath (Phase 5c, T3, T16).

TARDIGRADE MODE: under heavy attack (several peers silent, a flood of
rejected messages, or the host running out of resources) the arm drops
everything non-essential and keeps only what keeps the body alive:
detection, evidence, and the ring. It returns to normal only after a calm
period (hysteresis), so an attacker cannot make it flap on and off.

LAST BREATH: an arm keeps a small buffer of recent evidence. If it is being
stopped in a way it can notice (termination signal, failed self-check,
operator), it signs that evidence and sends it to its peers before it goes.
Honest limit: SIGKILL and kernel-level killers cannot be caught by any
process. For those, the ring's silence alarm (Phase 1) is the defense.
"""
from __future__ import annotations

import signal
from collections import deque

from barrier import barrier as br
from ring import message as msg

ESSENTIAL = frozenset({"detection", "evidence", "ring"})
SILENT_PEERS_TRIGGER = 2
REJECTS_PER_MIN_TRIGGER = 50
LOAD_TRIGGER = 0.90
CALM_PERIOD = 300.0
BREATH_REASONS = ("terminated", "self-check-failed", "operator")
MAX_EVIDENCE = 20


class SurvivalError(Exception):
    pass


class Tardigrade:
    def __init__(self, tasks):
        self.tasks = frozenset(tasks)
        if not ESSENTIAL <= self.tasks:
            raise SurvivalError("detection, evidence and ring must always be tasks")
        self.mode = "normal"
        self.log: list[tuple] = []          # (time, "enter"/"exit", why)
        self._last_trigger = float("-inf")
        self._rejects = deque()

    def record_reject(self, now: float):
        self._rejects.append(now)

    def update(self, now: float, silent_peers: int = 0, load: float = 0.0) -> str:
        while self._rejects and now - self._rejects[0] > 60.0:
            self._rejects.popleft()
        why = None
        if silent_peers >= SILENT_PEERS_TRIGGER:
            why = "silent-peers"
        elif len(self._rejects) >= REJECTS_PER_MIN_TRIGGER:
            why = "message-flood"
        elif load >= LOAD_TRIGGER:
            why = "resource-exhaustion"
        if why:
            self._last_trigger = now
            if self.mode == "normal":
                self.mode = "tardigrade"
                self.log.append((now, "enter", why))
        elif self.mode == "tardigrade" and now - self._last_trigger >= CALM_PERIOD:
            self.mode = "normal"
            self.log.append((now, "exit", "calm"))
        return self.mode

    def running(self) -> frozenset:
        return self.tasks if self.mode == "normal" else self.tasks & ESSENTIAL

    def suspended(self) -> frozenset:
        return self.tasks - self.running()


class LastBreath:
    def __init__(self, name, role, key, cert, send, inventory=()):
        self.name, self.role, self.key, self.cert = name, role, key, cert
        self.send = send
        self.inventory = frozenset(inventory)
        self.buffer = deque(maxlen=MAX_EVIDENCE)
        self.sent = False

    def remember(self, fact):
        br.validate_fact(fact, self.inventory)
        self.buffer.append(fact)

    def breathe(self, reason: str):
        """Sign recent evidence and send it to peers. Only ever happens once."""
        if reason not in BREATH_REASONS:
            raise SurvivalError("unknown reason")
        if self.sent:
            return None
        body = {"event": "last-breath", "reason": reason, "evidence": list(self.buffer)}
        raw = msg.sign("alert", body, self.name, self.role, self.key, self.cert)
        self.sent = True
        self.send(raw)
        return raw

    def install(self, signals=(signal.SIGTERM, signal.SIGINT)):
        def handler(signum, frame):
            self.breathe("terminated")
            raise SystemExit(0)
        for s in signals:
            signal.signal(s, handler)


def receive_last_breath(m, brain, now: float, inventory=()) -> dict:
    """A peer receives a VERIFIED last-breath message: keep the evidence, mark the arm."""
    b = m.body
    if m.type != "alert" or set(b) != {"event", "reason", "evidence"} or b["event"] != "last-breath":
        raise SurvivalError("not a last-breath message")
    if b["reason"] not in BREATH_REASONS or not isinstance(b["evidence"], list) \
            or len(b["evidence"]) > MAX_EVIDENCE:
        raise SurvivalError("bad last-breath message")
    accepted = rejected = 0
    for f in b["evidence"]:
        try:
            br.validate_fact(f, frozenset(inventory))
        except br.BarrierError:
            rejected += 1
            continue
        brain.ingest(f, now)
        accepted += 1
    brain.ring_alert(m.sender, now)
    return {"accepted": accepted, "rejected": rejected}
