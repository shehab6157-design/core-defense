"""Adaptive immunity: learn from operator corrections, safely (Phase 6, T9, T10, P5).

- Learns ONLY from signed corrections by a trusted operator.
- Learns ONLY during 'sleep' - never during fever or survival mode (never mid-attack).
- Each sleep cycle moves a threshold by at most ONE step, within hard bounds.
- A candidate version is adopted ONLY if it passes the regression suite:
  every known attack scenario must still be detected, every benign one stay quiet.
- Every adopted version is kept; any version can be rolled back to.
- Too many corrections in one cycle (possible stolen operator key) are capped
  and raised as an alarm.
"""
from __future__ import annotations

import copy
from collections import defaultdict
from dataclasses import dataclass

from barrier import barrier as br
from brain import brain as bn
from ring import message as msg

# Learnable parameters and their hard bounds (lower bounds = inflammation floors)
TUNABLE = {"brute_force": (3, 10), "decoy": (55, 90), "mass_modified": (100, 1000)}
STEP = {"brute_force": 1, "decoy": 5, "mass_modified": 50}
REASON_PARAM = {
    "brute-force": "brute_force", "login-after-brute-force": "brute_force",
    "lateral-movement": "decoy", "mass-file-change": "mass_modified",
}
VERDICTS = ("false-alarm", "missed-attack")
MAX_CORRECTIONS_PER_CYCLE = 20


class LearnError(Exception):
    pass


@dataclass(frozen=True)
class Version:
    number: int
    params: dict      # host -> {param: value}
    parent: int | None
    note: str


class Learner:
    def __init__(self, ca_cert, operators, suite, inventory):
        self.ca_cert = ca_cert
        self.operators = frozenset(operators)
        self.suite = suite
        self.inventory = frozenset(inventory)
        self.versions = [Version(1, {}, None, "baseline")]
        self.current = 1
        self.pending: list[tuple] = []
        self.alarms: list[tuple] = []
        self.rejected_feedback = 0
        self._cache = msg.ReplayCache()

    # ---- state ----
    def params(self) -> dict:
        return self.versions[self.current - 1].params

    def apply_to(self, brain) -> None:
        brain.learned = copy.deepcopy(self.params())

    def rollback(self, number: int) -> None:
        if not 1 <= number <= len(self.versions):
            raise LearnError("no such version")
        self.current = number

    # ---- input: signed operator corrections only ----
    def submit(self, raw: bytes, now: float) -> None:
        try:
            m = msg.verify(raw, self.ca_cert, self._cache)
        except msg.MessageError:
            self.rejected_feedback += 1
            raise LearnError("rejected message") from None
        if m.type != "feedback" or m.sender not in self.operators:
            self.rejected_feedback += 1
            raise LearnError("untrusted operator")
        b = m.body
        if set(b) != {"host", "reason", "verdict"} or not isinstance(b["host"], str) \
                or not br.SAFE_VALUE.fullmatch(b["host"]) or b["reason"] not in REASON_PARAM \
                or b["verdict"] not in VERDICTS:
            self.rejected_feedback += 1
            raise LearnError("bad correction")
        self.pending.append((b["host"], REASON_PARAM[b["reason"]], b["verdict"]))

    # ---- evaluation against the regression suite ----
    def evaluate(self, params: dict) -> tuple[bool, list[str]]:
        failures = []
        for name, label, expected, events in self.suite:
            b = bn.Brain(self.inventory)
            b.learned = params
            for t, fact in events:
                b.ingest(fact, t)
            seen = {(p.action, p.reason) for p in b.proposals}
            if label == "attack" and expected not in seen:
                failures.append(name)
            if label == "benign" and b.proposals:
                failures.append(name)
        return (not failures, failures)

    # ---- learning happens only here ----
    def sleep(self, now: float, fever: bool = False, survival: bool = False) -> str:
        if fever or survival:
            return "postponed"          # never learn mid-attack; corrections are kept
        if not self.pending:
            return "nothing-to-learn"
        if len(self.pending) > MAX_CORRECTIONS_PER_CYCLE:
            self.alarms.append(("correction-flood", len(self.pending)))
        corrections = self.pending[:MAX_CORRECTIONS_PER_CYCLE]
        self.pending = []
        votes = defaultdict(int)
        for host, param, verdict in corrections:
            votes[(host, param)] += 1 if verdict == "false-alarm" else -1
        candidate = copy.deepcopy(self.params())
        for (host, param), v in votes.items():
            if v == 0:
                continue
            current = candidate.get(host, {}).get(param, bn.NORMAL[param])
            lo, hi = TUNABLE[param]
            step = STEP[param] if v > 0 else -STEP[param]
            candidate.setdefault(host, {})[param] = min(hi, max(lo, current + step))
        if candidate == self.params():
            return "no-change"
        ok, failures = self.evaluate(candidate)
        if not ok:
            self.alarms.append(("candidate-rejected", tuple(failures)))
            return "rejected"
        self.versions.append(Version(len(self.versions) + 1, candidate, self.current,
                                     f"learned from {len(corrections)} corrections"))
        self.current = len(self.versions)
        return "adopted"
