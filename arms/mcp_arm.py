"""MCP proxy arm adapter: agent-behavior alerts -> strict 'agent_anomaly' facts.

The MCP proxy watches AI agents' tool calls - a sensor independent of
host logs and network traffic. Agent and tool names are attacker-
influenced (a malicious MCP server can name a tool anything), so they
are pseudonymized. target_resource is free text and is never read.
A record claiming tier 'alert' must have 2+ signals, exactly as the
proxy's detector produces; anything inconsistent is treated as tampered.
"""
from __future__ import annotations

import hashlib
import hmac

from barrier import barrier as br

TIERS = ("alert", "observation")


class AdapterError(Exception):
    pass


class McpArm:
    def __init__(self, salt: bytes, host: str):
        if len(salt) < 16:
            raise AdapterError("salt must be at least 16 bytes")
        if not br.SAFE_VALUE.fullmatch(host):
            raise AdapterError("bad host name")
        self._salt = salt
        self.host = host
        self.rejected = 0

    def _pseudo(self, prefix: str, value: str) -> str:
        d = hmac.new(self._salt, f"{prefix}:{value}".encode("utf-8", "replace"), hashlib.sha256).hexdigest()
        return f"{prefix}-{d[:8]}"

    def to_fact(self, alert):
        """One detector alert -> one validated fact, or None (suppressed or rejected)."""
        try:
            if not isinstance(alert, dict):
                raise AdapterError("alert must be an object")
            tier = alert.get("tier")
            if tier == "suppressed":
                return None  # the proxy itself matched a known job
            if tier not in TIERS:
                raise AdapterError("unknown tier")
            agent, tool = alert.get("agent_id"), alert.get("tool_name")
            if not (isinstance(agent, str) and isinstance(tool, str)) or len(agent) > 256 or len(tool) > 256:
                raise AdapterError("bad agent or tool")
            raw = alert.get("signals")
            if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
                raise AdapterError("bad signals")
            signals = sorted({s.lower() for s in raw})
            if (tier == "alert") != (len(signals) >= 2):
                raise AdapterError("tier does not match signals (tampered?)")
            fact = {"kind": "agent_anomaly", "host": self.host,
                    "agent": self._pseudo("agent", agent), "tool": self._pseudo("tool", tool),
                    "signals": signals, "tier": tier}
            br.validate_fact(fact, frozenset({self.host}))
            return fact
        except (AdapterError, br.BarrierError):
            self.rejected += 1
            return None

    def from_detector_output(self, alerts) -> list[dict]:
        if not isinstance(alerts, list):
            self.rejected += 1
            return []
        return [f for f in (self.to_fact(a) for a in alerts) if f is not None]
