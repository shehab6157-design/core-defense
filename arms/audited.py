"""Audit wiring (Phase 2d): every decision and action is written to the trail.

Subclasses add logging only - the tested logic of the gate, executor,
and safety layer is unchanged. Logged values come from enums, validated
names, and fixed explanation templates, never from raw input text.
"""
from __future__ import annotations

from arms.executor import Executor
from arms.gate import Gate
from arms.safety import PendingApproval, SafeExecutor, SafetyError


class AuditedExecutor(Executor):
    def __init__(self, trail, backend=None):
        super().__init__(backend)
        self.trail = trail

    def apply(self, p, now=None):
        before = self.active_for(p.host)
        rec = super().apply(p, now)
        if rec is before:
            self.trail.append({"event": "action-renewed-or-kept", "id": rec.id,
                               "action": rec.action, "host": rec.host})
            return rec
        self.trail.append({"event": "action-started", "id": rec.id, "action": rec.action,
                           "host": rec.host, "reason": rec.reason, "sources": list(rec.sources),
                           "explanation": rec.explanation})
        if before is not None:
            self.trail.append({"event": "action-ended", "id": before.id, "action": before.action,
                               "host": before.host, "by": "escalated"})
        return rec

    def revert(self, record_id, now=None, by="operator"):
        rec = super().revert(record_id, now, by)
        self.trail.append({"event": "action-ended", "id": rec.id, "action": rec.action,
                           "host": rec.host, "by": by})
        return rec


class AuditedSafeExecutor(SafeExecutor):
    def __init__(self, trail, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trail = trail

    def _hold(self, p, now, why):
        n = len(self.pending)
        r = super()._hold(p, now, why)
        if len(self.pending) > n:
            self.trail.append({"event": "action-held", "request": r.id, "action": p.action,
                               "host": p.host, "why": why})
        return r

    def apply(self, p, now):
        was = self.tripped
        r = super().apply(p, now)
        if self.tripped and not was:
            self.trail.append({"event": "breaker-tripped", "action": p.action, "host": p.host})
        return r

    def handle_operator(self, raw, now):
        try:
            result = super().handle_operator(raw, now)
        except SafetyError as e:
            self.trail.append({"event": "operator-message-rejected", "detail": str(e)})
            raise
        if result is None:
            self.trail.append({"event": "breaker-reset"})
        elif isinstance(result, PendingApproval):
            self.trail.append({"event": "operator-denied", "request": result.id,
                               "host": result.proposal.host, "by": result.decided_by})
        else:
            req = next((r for r in reversed(list(self.pending.values()))
                        if r.state == "approved" and r.proposal.host == result.host), None)
            self.trail.append({"event": "operator-approved", "request": req.id if req else "",
                               "action": result.action, "host": result.host,
                               "by": req.decided_by if req else ""})
        return result


class AuditedGate(Gate):
    def __init__(self, trail, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trail = trail

    def decide(self, raw, now):
        d = super().decide(raw, now)
        e = {"event": "proposal-decision", "decision": d.reason}
        if d.proposal is not None:
            e.update(action=d.proposal.action, host=d.proposal.host, reason=d.proposal.reason)
        self.trail.append(e)
        return d
