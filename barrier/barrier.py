"""Barrier: untrusted log text in, strict typed facts out (R4, T1).

Attackers can write text into logs (usernames, commands, paths). If that
text reached an AI brain it could carry instructions (prompt injection).
The barrier blocks this BY CONSTRUCTION:
  - every output value is an enum, a number, a validated IP address,
    a known name, or a keyed pseudonym like "user-3fa91c02"
  - no attacker-chosen free text ever crosses (no spaces, max 64 chars)
  - text that LOOKS like instructions to an AI is reported as an
    "injection_attempt" fact, so the attempt itself becomes evidence
Honest limit: the injection DETECTOR is a heuristic and can be evaded.
The real protection is structural: nothing but typed values crosses.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import unicodedata

MAX_LINE = 4096
MAX_SCAN = 65536

SAFE_USERS = frozenset({
    "root", "admin", "administrator", "ubuntu", "www-data", "postgres", "mysql",
    "nobody", "daemon", "sshd", "git", "test", "guest", "oracle", "user",
})
SAFE_PROCS = frozenset({
    "bash", "sh", "su", "apt", "apt-get", "systemctl", "cat", "echo", "ls", "id",
    "whoami", "passwd", "useradd", "usermod", "chmod", "chown", "cp", "mv", "rm",
    "curl", "wget", "python3", "nc", "ncat", "ssh", "scp", "tcpdump", "vi", "nano",
    "journalctl", "crontab", "mount", "tee", "docker", "kill", "pkill",
})

_PATTERNS = {pid: re.compile(rx) for pid, rx in {
    "override-instructions": r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instructions?|rules|guidance|prompts?|directives?)\b",
    "role-marker": r"(^|[\s>\]\.;])(system|assistant)\s*:",
    "role-tag": r"</?\s*(system|assistant|instructions?|prompt)\s*>",
    "inst-token": r"\[/?inst\]|#{2,}\s*instructions?\b|<\|im_start\|>|<\|im_end\|>",
    "persona": r"\byou are (now|a|an)\b|\b(as|act as)\s+(the|a|an)\s+(security\s+)?(ai|assistant|model|llm)\b",
    "ai-address": r"\bai\s*:",
    "new-task": r"\bnew (task|instructions?)\s*:",
    "role-json": r"\"role\"\s*:\s*\"(system|assistant|user)\"",
    "suppress-alert": r"\b(do not|don't|must not|never)\s+(alert|report|log|flag)\b",
}.items()}

# Invisible characters attackers use to split words and dodge detection
_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"), None)

PREFIX = re.compile(
    r"(?:\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>[A-Za-z0-9.-]{1,63})"
    r"\s+(?P<prog>[A-Za-z0-9_.-]{1,32}?)(?:\[\d{1,7}\])?:"
    r"\s+(?P<msg>.*)"
)
_SSH_END = r"ssh2(?:: [A-Z0-9-]{1,16} SHA256:[A-Za-z0-9+/=]{1,128})?"
ACCEPTED = re.compile(r"Accepted (?P<method>password|publickey) for (?P<user>\S{1,64}) from (?P<ip>\S{1,64}) port (?P<port>\d{1,5}) " + _SSH_END)
FAILED = re.compile(r"Failed (?P<method>password|publickey) for (?P<invalid>invalid user )?(?P<user>\S{1,64}) from (?P<ip>\S{1,64}) port (?P<port>\d{1,5}) " + _SSH_END)
SUDO = re.compile(r"(?P<user>\S{1,64}) : TTY=\S+ ; PWD=.*? ; USER=(?P<target>\S{1,64}) ; COMMAND=(?P<cmd>\S{1,256})(?: .*)?")
USERADD = re.compile(r"new user: name=(?P<user>[^,\s]{1,64}), UID=(?P<uid>\d{1,10}),.*")

SAFE_VALUE = re.compile(r"[a-z0-9_.:-]{1,64}")


class BarrierError(Exception):
    """A fact failed validation and must never reach the brain."""


def detect_injection(raw: str) -> list[str]:
    text = unicodedata.normalize("NFKC", raw).translate(_INVISIBLE).lower()
    return [pid for pid, rx in _PATTERNS.items() if rx.search(text)]


# ---------- validation: the brain only ever accepts facts that pass this ----------

def _ident(prefix, safe=frozenset()):
    rx = re.compile(prefix + r"-[0-9a-f]{8}")
    return lambda v: isinstance(v, str) and (v in safe or rx.fullmatch(v) is not None)


def _ip(v):
    if not isinstance(v, str):
        return False
    try:
        return str(ipaddress.ip_address(v)) == v
    except ValueError:
        return False


def _int_range(lo, hi):
    return lambda v: isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def _enum(*opts):
    return lambda v: isinstance(v, str) and v in opts


def _hex16(v):
    return isinstance(v, str) and re.fullmatch(r"[0-9a-f]{16}", v) is not None


def _bool(v):
    return isinstance(v, bool)


_USER = _ident("user", SAFE_USERS)
_PROC = _ident("proc", SAFE_PROCS)
_PORT = _int_range(1, 65535)
_METHOD = _enum("password", "publickey")
_LEN = _int_range(0, 2**31)

SCHEMA = {
    "login_success": {"user": _USER, "src_ip": _ip, "port": _PORT, "method": _METHOD},
    "login_failed": {"user": _USER, "src_ip": _ip, "port": _PORT, "method": _METHOD, "invalid_user": _bool},
    "privilege_use": {"user": _USER, "target_user": _USER, "process": _PROC},
    "account_created": {"user": _USER, "uid": _int_range(0, 2**32 - 1)},
    "unparsed": {"length": _LEN, "digest": _hex16},
    "injection_attempt": {"pattern": _enum(*_PATTERNS), "matches": _int_range(1, len(_PATTERNS)), "length": _LEN, "digest": _hex16},
}


def validate_fact(body, inventory=frozenset()) -> None:
    if not isinstance(body, dict) or body.get("kind") not in SCHEMA:
        raise BarrierError("unknown fact kind")
    fields = SCHEMA[body["kind"]]
    if set(body) != {"kind", "host"} | set(fields):
        raise BarrierError(f"unexpected fields in {body['kind']}")
    host = body["host"]
    if not (host == "unknown" or host in inventory or _ident("host")(host)):
        raise BarrierError("invalid host")
    for name, ok in fields.items():
        if not ok(body[name]):
            raise BarrierError(f"invalid {body['kind']}.{name}")


# ---------- the barrier ----------

def _norm_ip(s: str) -> str:
    return str(ipaddress.ip_address(s))


def _norm_port(s: str) -> int:
    p = int(s)
    if not 1 <= p <= 65535:
        raise ValueError("port out of range")
    return p


class Barrier:
    def __init__(self, salt: bytes, inventory=()):
        if len(salt) < 16:
            raise BarrierError("salt must be at least 16 bytes")
        self._salt = salt
        self.inventory = frozenset(h.lower() for h in inventory)
        for h in self.inventory:
            if not SAFE_VALUE.fullmatch(h):
                raise BarrierError(f"bad inventory name: {h!r}")

    def _pseudo(self, prefix: str, value: str) -> str:
        d = hmac.new(self._salt, f"{prefix}:{value}".encode("utf-8", "replace"), hashlib.sha256).hexdigest()
        return f"{prefix}-{d[:8]}"

    def _user(self, v: str) -> str:
        return v if v in SAFE_USERS else self._pseudo("user", v)

    def _proc(self, cmd: str) -> str:
        base = cmd.rsplit("/", 1)[-1]
        return base if base in SAFE_PROCS else self._pseudo("proc", base)

    def _host(self, h: str) -> str:
        h = h.lower()
        return h if h in self.inventory else self._pseudo("host", h)

    def _parse(self, prog: str, text: str):
        try:
            if prog == "sshd":
                if m := ACCEPTED.fullmatch(text):
                    return "login_success", {"user": self._user(m["user"]), "src_ip": _norm_ip(m["ip"]),
                                             "port": _norm_port(m["port"]), "method": m["method"]}
                if m := FAILED.fullmatch(text):
                    return "login_failed", {"user": self._user(m["user"]), "src_ip": _norm_ip(m["ip"]),
                                            "port": _norm_port(m["port"]), "method": m["method"],
                                            "invalid_user": bool(m["invalid"])}
            elif prog == "sudo":
                if m := SUDO.fullmatch(text):
                    return "privilege_use", {"user": self._user(m["user"]),
                                             "target_user": self._user(m["target"]),
                                             "process": self._proc(m["cmd"])}
            elif prog == "useradd":
                if m := USERADD.fullmatch(text):
                    uid = int(m["uid"])
                    if uid >= 2**32:
                        raise ValueError("uid out of range")
                    return "account_created", {"user": self._user(m["user"]), "uid": uid}
            elif prog in ("usermod", "gpasswd"):
                m = USERMOD_GROUP.fullmatch(text) if prog == "usermod" else GPASSWD_ADD.fullmatch(text)
                if m:
                    group = m["group"] if m["group"] in ADMIN_GROUPS else "other"
                    return "group_added", {"user": self._user(m["user"]), "group": group}
        except ValueError:
            return None
        return None

    def process_line(self, raw: str) -> list[dict]:
        """One raw log line in -> one or two validated facts out."""
        length = len(raw)
        line = raw.rstrip("\r\n")[:MAX_LINE]
        digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
        host, parsed, repeat = "unknown", None, 1
        if m := PREFIX.fullmatch(line):
            host = self._host(m["host"])
            text, repeat = _unrepeat(m["msg"])
            parsed = self._parse(m["prog"], text)
        if parsed:
            kind, fields = parsed
            facts = [{"kind": kind, "host": host, **fields} for _ in range(repeat)]
        else:
            facts = [{"kind": "unparsed", "host": host, "length": length, "digest": digest}]
        hits = detect_injection(raw[:MAX_SCAN])
        if hits:
            facts.append({"kind": "injection_attempt", "host": host, "pattern": hits[0],
                          "matches": len(hits), "length": length, "digest": digest})
        # Defense in depth: never emit a fact that fails the schema
        for f in facts:
            validate_fact(f, self.inventory)
        return facts


# ---------- network sensor facts (produced by the APIS arm, not by the barrier) ----------

def _techniques(v):
    return (isinstance(v, list) and len(v) <= 5 and len(set(v)) == len(v)
            and all(isinstance(t, str) and re.fullmatch(r"t\d{4}(?:\.\d{3})?", t) for t in v))


SCHEMA["lateral_movement"] = {
    "src_ip": _ip, "dst_ip": _ip, "confidence": _int_range(0, 100), "techniques": _techniques,
}


# ---------- agent sensor facts (produced by the MCP proxy arm) ----------

AGENT_SIGNALS = ("unknown_agent", "new_tool", "off_pattern", "payload_outlier", "sequence_spike")


def _agent_signals(v):
    return (isinstance(v, list) and 1 <= len(v) <= len(AGENT_SIGNALS) and len(set(v)) == len(v)
            and all(isinstance(s, str) and s in AGENT_SIGNALS for s in v))


SCHEMA["agent_anomaly"] = {
    "agent": _ident("agent"), "tool": _ident("tool"),
    "signals": _agent_signals, "tier": _enum("alert", "observation"),
}


# ---------- Phase 3a: damage signals (Danger Theory) ----------

SERVICE_PROCS = frozenset({"nginx", "apache2", "httpd", "php-fpm", "java", "node", "tomcat", "mysqld",
                           "postgres", "redis-server", "mongod", "dockerd", "containerd"})
SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "python3", "python", "perl", "ruby",
                    "nc", "ncat", "socat", "curl", "wget", "pwsh"})
PROC_NAMES = SAFE_PROCS | SERVICE_PROCS | SHELLS | frozenset({"sshd", "cron", "systemd", "sudo"})
ADMIN_GROUPS = ("sudo", "wheel", "admin", "root", "docker", "lxd", "adm")

USERMOD_GROUP = re.compile(r"add '(?P<user>[^'\s]{1,64})' to (?:shadow )?group '(?P<group>[^'\s]{1,64})'")
GPASSWD_ADD = re.compile(r"user (?P<user>\S{1,64}) added by \S{1,64} to group (?P<group>\S{1,64})")

SCHEMA["group_added"] = {"user": _USER, "group": _enum(*ADMIN_GROUPS, "other")}
SCHEMA["process_spawn"] = {"parent": _ident("proc", PROC_NAMES), "child": _ident("proc", PROC_NAMES), "user": _USER}
SCHEMA["file_burst"] = {"modified": _int_range(0, 10**7), "renamed": _int_range(0, 10**7), "window": _int_range(1, 3600)}


# ---------- Phase 4b: decoy tripwires ----------

DECOY_KINDS = ("honey-credential", "decoy-host", "honey-admin", "honey-files", "honey-tool")
SCHEMA["decoy_touched"] = {"decoy_kind": _enum(*DECOY_KINDS), "src_ip": _ip}


# ---------- Phase 6b: immune memory ----------
SCHEMA["known_attacker"] = {"src_ip": _ip}


# ---------- Phase 7a: rsyslog "message repeated N times" lines ----------
MAX_REPEAT = 50
REPEATED = re.compile(r"message repeated (?P<n>\d{1,9}) times: \[ ?(?P<inner>.*)\]")


def _unrepeat(text: str):
    """'message repeated 4 times: [ X]' -> (X, 4); anything else -> (text, 1). Capped."""
    if r := REPEATED.fullmatch(text):
        return r["inner"], max(1, min(int(r["n"]), MAX_REPEAT))
    return text, 1
