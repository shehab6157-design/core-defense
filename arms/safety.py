"""Safety layer: protected assets + mass-action circuit breaker (Phase 2c, T7).

Stops the defense from being turned into a weapon against its own network:
- Protected hosts: strong actions (limit_access, isolate) are HELD for
  operator approval. Weak actions still run normally.
- Circuit breaker: at most MAX_STRONG strong actions per WINDOW across the
  whole network. Beyond that the breaker trips and every further strong
  action is held until the operator resets it.
- Renewing an action that is already active is never blocked (it was
  already authorized).
- Operator decisions are signed messages from a trusted operator identity.
"""
from __future__ import annotations

import re
import uuid
from collections import deque
from dataclasses import dataclass

from arms.executor import LEVEL
from ring import message as msg

STRONG = frozenset({"limit_access", "isolate"})
OPS = ("approve", "deny", "reset-breaker")
_REQ = re.compile(r"[0-9a-f]{12}")


class SafetyError(Exception):
    pass


@dataclass
class PendingApproval:
    id: str
    proposal: object
    created_at: float
    why: str                  # protected-host | rate-limit
    state: str = "pending"    # pending | approved | denied
    decided_by: str | None = None


class SafeExecutor:
    def __init__(self, executor, ca_cert, operators, protected_hosts=(), max_strong=3, window=600.0):
        self.executor = executor
        self.ca_cert = ca_cert
        self.operators = frozenset(operators)
        self.protected = frozenset(protected_hosts)
        self.max_strong = max_strong
        self.window = window
        self.pending: dict[str, PendingApproval] = {}
        self.tripped = False
        self.rejected: list[str] = []
        self._recent = deque()
        self._cache = msg.ReplayCache()

    # Same reading interface as the plain executor
    def active_for(self, host):
        return self.executor.active_for(host)

    @property
    def records(self):
        return self.executor.records

    def _hold(self, p, now, why) -> PendingApproval:
        for r in self.pending.values():
            if r.state == "pending" and r.proposal.host == p.host and r.proposal.action == p.action:
                return r
        r = PendingApproval(uuid.uuid4().hex[:12], p, now, why)
        self.pending[r.id] = r
        return r

    def apply(self, p, now):
        if p.action not in STRONG:
            return self.executor.apply(p, now)
        cur = self.executor.active_for(p.host)
        if cur and LEVEL[cur.action] >= LEVEL[p.action]:
            return self.executor.apply(p, now)  # renewal of an authorized action
        if p.host in self.protected and not (getattr(self, "autonomy", None) and self.autonomy.allows(p.action)):
            return self._hold(p, now, "protected-host")
        while self._recent and now - self._recent[0] > self.window:
            self._recent.popleft()
        if self.tripped or len(self._recent) >= self.max_strong:
            self.tripped = True
            return self._hold(p, now, "rate-limit")
        self._recent.append(now)
        return self.executor.apply(p, now)

    def handle_operator(self, raw: bytes, now: float):
        try:
            m = msg.verify(raw, self.ca_cert, self._cache)
        except msg.MessageError as e:
            self.rejected.append(str(e))
            raise SafetyError("rejected message") from None
        if m.type != "approval" or m.sender not in self.operators:
            self.rejected.append("untrusted operator")
            raise SafetyError("untrusted operator")
        b = m.body
        if set(b) != {"op", "request"} or b["op"] not in OPS or not isinstance(b["request"], str):
            raise SafetyError("bad operator message")
        if b["op"] == "reset-breaker":
            self.tripped = False
            self._recent.clear()
            return None
        req = self.pending.get(b["request"]) if _REQ.fullmatch(b["request"]) else None
        if req is None or req.state != "pending":
            raise SafetyError("no such pending request")
        req.decided_by = m.sender
        if b["op"] == "deny":
            req.state = "denied"
            return req
        req.state = "approved"
        return self.executor.apply(req.proposal, now)
