"""Earned autonomy (Phase 6c, P4).

Strong actions on protected hosts normally wait for the operator. An action
type can EARN the right to run there without waiting, through a proven
track record of operator verdicts:
  - at least MIN_CORRECT 'correct' verdicts in the last WINDOW
  - score (correct - WRONG_WEIGHT x wrong) of at least MIN_SCORE
  - no 'wrong' verdict in the last CLEAN_RECENT
One wrong verdict therefore revokes autonomy instantly; it returns only
after CLEAN_RECENT clean verdicts.
Hard limits:
  - NEVER_AUTONOMOUS actions (isolate) always wait for the operator on
    protected hosts, whatever their record.
  - Autonomy skips approval only - the circuit breaker still applies.
  - Verdicts are signed operator messages; each action can be judged once.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque

from ring import message as msg

WINDOW = 50
MIN_CORRECT = 20
MIN_SCORE = 15
WRONG_WEIGHT = 5
CLEAN_RECENT = 10
JUDGED = frozenset({"limit_access", "isolate"})
NEVER_AUTONOMOUS = frozenset({"isolate"})
VERDICTS = ("correct", "wrong")
_ID = re.compile(r"[0-9a-f]{12}")


class AutonomyError(Exception):
    pass


class Autonomy:
    def __init__(self, ca_cert, operators):
        self.ca_cert = ca_cert
        self.operators = frozenset(operators)
        self.history = defaultdict(lambda: deque(maxlen=WINDOW))
        self.judged: set[str] = set()
        self.log: list[tuple] = []          # (time, action, "granted" / "revoked")
        self._state: dict[str, bool] = {}
        self._cache = msg.ReplayCache()

    def allows(self, action: str) -> bool:
        return self._state.get(action, False)

    def status(self) -> dict:
        out = {}
        for action in sorted(JUDGED):
            h = list(self.history[action])
            out[action] = {"correct": h.count("correct"), "wrong": h.count("wrong"),
                           "autonomous": self.allows(action)}
        return out

    def _qualifies(self, action: str) -> bool:
        if action in NEVER_AUTONOMOUS:
            return False
        h = list(self.history[action])
        correct, wrong = h.count("correct"), h.count("wrong")
        return (correct >= MIN_CORRECT
                and correct - WRONG_WEIGHT * wrong >= MIN_SCORE
                and "wrong" not in h[-CLEAN_RECENT:])

    def _refresh(self, action: str, now: float) -> None:
        new, old = self._qualifies(action), self._state.get(action, False)
        if new != old:
            self.log.append((now, action, "granted" if new else "revoked"))
            self._state[action] = new

    def handle_operator(self, raw: bytes, now: float) -> bool:
        """A signed operator verdict on one executed action. Returns whether that action type is now autonomous."""
        try:
            m = msg.verify(raw, self.ca_cert, self._cache)
        except msg.MessageError:
            raise AutonomyError("rejected message") from None
        if m.type != "verdict" or m.sender not in self.operators:
            raise AutonomyError("untrusted operator")
        b = m.body
        if set(b) != {"action", "action_id", "verdict"} or b["action"] not in JUDGED \
                or b["verdict"] not in VERDICTS or not isinstance(b["action_id"], str) \
                or not _ID.fullmatch(b["action_id"]):
            raise AutonomyError("bad verdict")
        if b["action_id"] in self.judged:
            raise AutonomyError("this action was already judged")
        self.judged.add(b["action_id"])
        self.history[b["action"]].append(b["verdict"])
        self._refresh(b["action"], now)
        return self.allows(b["action"])
