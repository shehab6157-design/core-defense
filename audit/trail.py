"""Tamper-evident audit trail (R9, T11).

Append-only JSON lines. Each entry contains the hash of the previous
entry, so editing, deleting, or reordering any past entry breaks the
chain and verify() reports exactly where.
Honest limit: cutting entries off the END leaves a valid shorter chain.
That is caught only by comparing against an ANCHOR - the latest head
(seq, hash) kept somewhere else (e.g. shared with ring peers).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

GENESIS = "0" * 64
RESERVED = {"seq", "ts", "prev", "hash"}


class AuditError(Exception):
    pass


def _hash(entry_without_hash: dict) -> str:
    return hashlib.sha256(json.dumps(entry_without_hash, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify(path, expected_head=None):
    """Returns (ok, entries_checked, first_bad_seq or None, head)."""
    prev, seq = GENESIS, 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            seq += 1
            try:
                e = json.loads(line)
                h = e.pop("hash")
            except (ValueError, KeyError, AttributeError):
                return False, seq - 1, seq, (seq - 1, prev)
            if e.get("seq") != seq or e.get("prev") != prev or _hash(e) != h:
                return False, seq - 1, seq, (seq - 1, prev)
            prev = h
    head = (seq, prev)
    if expected_head is not None and tuple(expected_head) != head:
        return False, seq, seq + 1, head  # entries missing from the end
    return True, seq, None, head


class AuditTrail:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seq, self.last = 0, GENESIS
        if self.path.exists():
            ok, _, bad, head = verify(self.path)
            if not ok:
                raise AuditError(f"existing trail is broken at entry {bad}")
            self.seq, self.last = head
        else:
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))

    def append(self, event: dict, wall: float | None = None) -> dict:
        if set(event) & RESERVED:
            raise AuditError("event uses a reserved field")
        entry = {"seq": self.seq + 1, "ts": time.time() if wall is None else wall, "prev": self.last, **event}
        entry["hash"] = _hash(entry)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.seq, self.last = entry["seq"], entry["hash"]
        return entry

    def head(self):
        return (self.seq, self.last)
