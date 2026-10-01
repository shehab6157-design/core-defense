"""Process and file sensors (Phase 3a): structured events -> strict facts.

These adapters define exactly what a process monitor and a file-change
monitor may report (the monitors themselves - auditd / eBPF / inotify -
come later). Known program names stay readable so damage rules can work;
anything else is pseudonymized. Malformed events are rejected and counted.
"""
from __future__ import annotations

import hashlib
import hmac

from barrier import barrier as br


class SensorError(Exception):
    pass


class _Sensor:
    def __init__(self, salt: bytes, host: str):
        if len(salt) < 16:
            raise SensorError("salt must be at least 16 bytes")
        if not br.SAFE_VALUE.fullmatch(host):
            raise SensorError("bad host name")
        self._salt = salt
        self.host = host
        self.rejected = 0

    def _pseudo(self, prefix, value):
        d = hmac.new(self._salt, f"{prefix}:{value}".encode("utf-8", "replace"), hashlib.sha256).hexdigest()
        return f"{prefix}-{d[:8]}"

    @staticmethod
    def _text(v):
        if not isinstance(v, str) or not 0 < len(v) <= 256:
            raise SensorError("bad text field")
        return v

    def _proc(self, name):
        base = self._text(name).rsplit("/", 1)[-1]
        return base if base in br.PROC_NAMES else self._pseudo("proc", base)

    def _user(self, name):
        name = self._text(name)
        return name if name in br.SAFE_USERS else self._pseudo("user", name)

    def _finish(self, fact):
        br.validate_fact(fact, frozenset({self.host}))
        return fact


class ProcessArm(_Sensor):
    """Event: {"parent": "/usr/sbin/nginx", "child": "/bin/sh", "user": "www-data"}"""

    def to_fact(self, ev):
        try:
            if not isinstance(ev, dict):
                raise SensorError("event must be an object")
            return self._finish({"kind": "process_spawn", "host": self.host,
                                 "parent": self._proc(ev.get("parent")),
                                 "child": self._proc(ev.get("child")),
                                 "user": self._user(ev.get("user"))})
        except (SensorError, br.BarrierError):
            self.rejected += 1
            return None


class FileArm(_Sensor):
    """Event: {"modified": 340, "renamed": 120, "window": 60}  (window in seconds)"""

    def to_fact(self, ev):
        try:
            if not isinstance(ev, dict):
                raise SensorError("event must be an object")
            vals = {}
            for k in ("modified", "renamed", "window"):
                v = ev.get(k)
                if isinstance(v, bool) or not isinstance(v, int):
                    raise SensorError(f"{k} must be an integer")
                vals[k] = v
            return self._finish({"kind": "file_burst", "host": self.host, **vals})
        except (SensorError, br.BarrierError):
            self.rejected += 1
            return None
