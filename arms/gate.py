"""Quorum gate: an arm verifies a proposal itself before acting (Phase 2b, T4, T7).

A proposal is NOT an order. Before acting, the arm checks:
  1. it is a valid signed message from a TRUSTED brain (not replayed, not stale)
  2. it is a valid proposal (allowlisted action, known reason, two-sensor rule)
  3. the target host is one THIS arm is responsible for
  4. the arm's OWN copy of the brain independently saw the evidence:
       isolate      -> 2+ of the claimed sensors confirmed locally
       limit_access -> 1+ of the claimed sensors confirmed locally
       weaker       -> no confirmation needed (low harm)
So even a brain with a stolen key cannot make an arm isolate a machine
the arm has no evidence against. Every refusal is kept as evidence.
"""
from __future__ import annotations

from dataclasses import dataclass

from brain.brain import Brain, BrainError, Proposal
from arms.safety import PendingApproval
from ring import message as msg

NEED_CORROBORATION = {"isolate": 2, "limit_access": 1}
_BODY_FIELDS = {"action", "host", "reason", "sources", "evidence"}


@dataclass(frozen=True)
class Decision:
    accepted: bool
    reason: str  # accepted | rejected-message | untrusted-brain | invalid-proposal | not-responsible | not-corroborated
    proposal: Proposal | None = None
    record: object = None


def proposal_from_body(body) -> Proposal:
    if not isinstance(body, dict) or set(body) != _BODY_FIELDS:
        raise BrainError("bad proposal fields")
    if not all(isinstance(body[k], str) for k in ("action", "host", "reason")):
        raise BrainError("bad proposal types")
    src = body["sources"]
    if not isinstance(src, list) or not all(isinstance(s, str) for s in src):
        raise BrainError("bad sources")
    ev = body["evidence"]
    if isinstance(ev, bool) or not isinstance(ev, int) or not 0 <= ev <= 10_000:
        raise BrainError("bad evidence count")
    return Proposal(body["action"], body["host"], body["reason"], tuple(src), ev)


class Gate:
    def __init__(self, ca_cert, trusted_brains, responsible_hosts, local_brain: Brain, executor):
        self.ca_cert = ca_cert
        self.trusted = frozenset(trusted_brains)
        self.hosts = frozenset(responsible_hosts)
        self.brain = local_brain
        self.executor = executor
        self.cache = msg.ReplayCache()
        self.refusals: list[Decision] = []

    # Evidence the arm receives directly feeds its OWN copy of the brain
    def observe_fact(self, fact, now: float):
        return self.brain.ingest(fact, now)

    def observe_ring_silence(self, peer: str, now: float):
        return self.brain.ring_alert(peer, now)

    def _refuse(self, reason, proposal=None) -> Decision:
        d = Decision(False, reason, proposal)
        self.refusals.append(d)
        return d

    def decide(self, raw: bytes, now: float) -> Decision:
        try:
            m = msg.verify(raw, self.ca_cert, self.cache)
        except msg.MessageError:
            return self._refuse("rejected-message")
        if m.type != "proposal" or m.sender not in self.trusted:
            return self._refuse("untrusted-brain")
        try:
            p = proposal_from_body(m.body)
        except BrainError:
            return self._refuse("invalid-proposal")
        if p.host not in self.hosts:
            return self._refuse("not-responsible", p)
        need = NEED_CORROBORATION.get(p.action, 0)
        confirmed = self.brain.evidence_sensors(p.host, now) & set(p.sources)
        if len(confirmed) < need:
            return self._refuse("not-corroborated", p)
        record = self.executor.apply(p, now)
        if isinstance(record, PendingApproval):
            return Decision(False, "awaiting-approval", p, record)
        return Decision(True, "accepted", p, record)
