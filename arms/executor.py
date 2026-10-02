"""Reflexes: turn a validated proposal into a REVERSIBLE action (Phase 2a, P4, T7).

Rules:
- Every action has an undo, an expiry time, and a plain-language
  explanation built ONLY from fixed templates (never from input text).
- One active action per host. Stronger evidence escalates; weaker
  evidence never downgrades an active response.
- Escalation applies the stronger action FIRST, then undoes the weaker
  one, so protection never has a gap.
- Actions expire unless renewed by fresh evidence or pinned by the
  operator, so a false alarm cannot cause permanent damage.
- This step uses a dry-run backend that records what WOULD happen. A real
  backend (firewall rules) comes later and must always keep the
  operator's management access open.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from brain.brain import ACTIONS, REASONS, Proposal

LEVEL = {a: i for i, a in enumerate(ACTIONS)}
TTL = {"watch": 3600, "collect_evidence": 3600, "deploy_decoy": 1800, "limit_access": 900, "isolate": 600}

ACTION_TEXT = {
    "watch": "Watching",
    "collect_evidence": "Collecting evidence on",
    "deploy_decoy": "Deploying decoys around",
    "limit_access": "Limiting access to",
    "isolate": "Isolating",
}
REASON_TEXT = {
    "injection-attempt": "text aimed at manipulating an AI was found in its logs",
    "brute-force": "repeated failed logins were seen",
    "login-after-brute-force": "a login succeeded right after many failed attempts",
    "privilege-after-suspicious-login": "admin privileges were used after a suspicious login",
    "account-after-suspicious-login": "a new account was created after a suspicious login",
    "arm-silent": "its defense agent stopped responding",
    "arm-silent-on-suspicious-host": "its defense agent went silent on an already suspicious machine",
    "invalid-fact": "malformed data was received, which may mean tampering",
    "lateral-movement": "unusual internal network movement was detected",
    "lateral-movement-confirmed": "internal network movement was confirmed by another sensor",
    "agent-anomaly": "an AI agent behaved abnormally",
    "agent-anomaly-confirmed": "an AI agent behaved abnormally, confirmed by another sensor",
}
SENSOR_TEXT = {"host-log": "host logs", "network": "network traffic",
               "agent": "AI agent behavior", "ring": "defense heartbeats"}


class ExecutorError(Exception):
    pass


@dataclass
class ActionRecord:
    id: str
    action: str
    host: str
    reason: str
    sources: tuple
    started_at: float
    expires_at: float
    explanation: str
    state: str = "active"        # active | reverted | superseded
    ended_at: float | None = None
    ended_by: str | None = None  # operator | expired | escalated
    pinned: bool = False


class DryRunBackend:
    """Records what would happen. Touches nothing on the system."""

    def __init__(self):
        self.calls: list[tuple] = []
        self.active: set[tuple] = set()

    def apply(self, action, host):
        self.calls.append(("apply", action, host))
        self.active.add((action, host))

    def undo(self, action, host):
        self.calls.append(("undo", action, host))
        self.active.discard((action, host))


def explain(p: Proposal) -> str:
    sensors = ", ".join(SENSOR_TEXT[s] for s in sorted(set(p.sources)))
    minutes = TTL[p.action] // 60
    return (f"{ACTION_TEXT[p.action]} {p.host} because {REASON_TEXT[p.reason]}. "
            f"Evidence from: {sensors}. Undone automatically in {minutes} minutes "
            f"unless renewed or pinned by the operator.")


class Executor:
    def __init__(self, backend=None):
        self.backend = backend or DryRunBackend()
        self.records: dict[str, ActionRecord] = {}
        self._active: dict[str, str] = {}  # host -> record id

    @staticmethod
    def _t(now):
        return time.monotonic() if now is None else now

    def active_for(self, host):
        rid = self._active.get(host)
        return self.records[rid] if rid else None

    def apply(self, p, now=None) -> ActionRecord:
        if not isinstance(p, Proposal):
            raise ExecutorError("only validated proposals can be executed")
        now = self._t(now)
        cur = self.active_for(p.host)
        if cur and LEVEL[cur.action] > LEVEL[p.action]:
            return cur  # weaker evidence never downgrades an active response
        if cur and cur.action == p.action:
            cur.expires_at = max(cur.expires_at, now + TTL[p.action])  # renew
            return cur
        rec = ActionRecord(
            id=uuid.uuid4().hex[:12], action=p.action, host=p.host, reason=p.reason,
            sources=tuple(sorted(set(p.sources))), started_at=now,
            expires_at=now + TTL[p.action], explanation=explain(p),
        )
        self.backend.apply(p.action, p.host)  # stronger action FIRST...
        if cur:                                # ...then undo the weaker one
            self.backend.undo(cur.action, cur.host)
            cur.state, cur.ended_at, cur.ended_by = "superseded", now, "escalated"
        self.records[rec.id] = rec
        self._active[p.host] = rec.id
        return rec

    def revert(self, record_id, now=None, by="operator") -> ActionRecord:
        rec = self.records.get(record_id)
        if rec is None or rec.state != "active":
            raise ExecutorError("no active action with that id")
        self.backend.undo(rec.action, rec.host)
        rec.state, rec.ended_at, rec.ended_by = "reverted", self._t(now), by
        del self._active[rec.host]
        return rec

    def pin(self, record_id) -> ActionRecord:
        rec = self.records.get(record_id)
        if rec is None or rec.state != "active":
            raise ExecutorError("no active action with that id")
        rec.pinned = True
        return rec

    def tick(self, now=None) -> list[ActionRecord]:
        """Call regularly. Reverts expired, unpinned actions."""
        now = self._t(now)
        due = [r for r in self.records.values()
               if r.state == "active" and not r.pinned and now >= r.expires_at]
        return [self.revert(r.id, now, by="expired") for r in due]


# ---------- Phase 3a wording ----------
REASON_TEXT.update({
    "service-spawned-shell": "a server program started a command shell, a common sign of a successful exploit",
    "privilege-granted": "an account was added to an administrator group",
    "mass-file-change": "a very large number of files changed in a short time, a common sign of ransomware",
})
SENSOR_TEXT.update({"process": "process activity", "file": "file activity"})


# ---------- Phase 4b wording ----------
REASON_TEXT["decoy-touched"] = "someone used a decoy that no legitimate user would ever touch"
SENSOR_TEXT["decoy"] = "decoy tripwires"
