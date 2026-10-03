"""Arm service: every component wired into one long-running process (Phase 7a).

  ring       signed heartbeats to peers; signed messages in
  logs       follows the host's auth log (handles rotation and truncation)
  barrier    every log line -> strict typed facts
  memory     facts from remembered attacker addresses -> known_attacker evidence
  brain      this arm's OWN brain copy (also used by the gate for corroboration)
  gate       signed brain proposals are verified before anything happens
  safety     protected hosts + circuit breaker
  executor   reversible, expiring actions (dry-run backend until Phase 7b)
  audit      every decision and action in the hash-chained trail
  survival   tardigrade mode under heavy attack; last breath on shutdown

Run:  python -m service.arm --config config/arm-01.json
"""
from __future__ import annotations

import argparse
import json
import os
import secrets as pysecrets
import socket
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from arms import audited as au
from audit import trail as at
from barrier import barrier as br
from brain import brain as bn
from learning import memory as mem
from ring import heartbeat as hb
from ring import identity as idn
from ring import message as msg
from survival import tardigrade as tg

REQUIRED = {"name", "host", "bind", "port", "peers", "inventory", "secrets", "auth_log",
            "state_dir", "trusted_brains", "operators", "protected_hosts", "responsible_hosts"}
TASKS = {"detection", "evidence", "ring", "decoys", "triage", "learning"}
MAX_PARTIAL_LINE = 65536


class ServiceError(Exception):
    pass


def _parse_addr(s: str) -> tuple:
    host, port = s.rsplit(":", 1)
    return host, int(port)


def load_config(path) -> dict:
    cfg = json.loads(Path(path).read_text())
    if not isinstance(cfg, dict) or set(cfg) != REQUIRED:
        raise ServiceError(f"config fields must be exactly: {sorted(REQUIRED)}")
    try:
        idn.check_name(cfg["name"])
        for n in cfg["peers"]:
            idn.check_name(n)
            _parse_addr(cfg["peers"][n])
    except (idn.IdentityError, ValueError, AttributeError) as e:
        raise ServiceError(f"bad name or peer: {e}") from None
    for h in [cfg["host"], *cfg["inventory"], *cfg["protected_hosts"], *cfg["responsible_hosts"]]:
        if not isinstance(h, str) or not br.SAFE_VALUE.fullmatch(h):
            raise ServiceError(f"bad host name: {h!r}")
    port = cfg["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ServiceError("port must be 1024-65535")
    return cfg


class LogTailer:
    """Follows a log file from its END; handles rotation (new file) and truncation."""

    def __init__(self, path, from_start: bool = False):
        self.path = Path(path)
        self._ino, self._pos, self._buf = None, 0, b""
        if self.path.exists() and not from_start:
            st = self.path.stat()
            self._ino, self._pos = st.st_ino, st.st_size

    def read_lines(self, max_bytes: int = 1_000_000) -> list[str]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return []
        if st.st_ino != self._ino or st.st_size < self._pos:
            self._ino, self._pos, self._buf = st.st_ino, 0, b""   # rotated or truncated
        with open(self.path, "rb") as f:
            f.seek(self._pos)
            data = f.read(max_bytes)
            self._pos = f.tell()
        *lines, self._buf = (self._buf + data).split(b"\n")
        if len(self._buf) > MAX_PARTIAL_LINE:
            self._buf = b""   # never let one endless line eat memory
        return [line.decode("utf-8", "replace") for line in lines]


class ArmService:
    def __init__(self, cfg: dict, now: float | None = None):
        self.cfg = cfg
        now = time.monotonic() if now is None else now
        sec, state = Path(cfg["secrets"]), Path(cfg["state_dir"])
        state.mkdir(parents=True, exist_ok=True)
        try:
            self.key = serialization.load_pem_private_key((sec / f"{cfg['name']}.key").read_bytes(), password=None)
            self.cert = x509.load_pem_x509_certificate((sec / f"{cfg['name']}.crt").read_bytes())
            self.ca_cert = x509.load_pem_x509_certificate((sec / "ca.crt").read_bytes())
        except FileNotFoundError as e:
            raise ServiceError(f"missing identity file: {e.filename}") from None
        name, self.role = idn.verify(self.cert, self.ca_cert)   # refuse to start with a bad identity
        if name != cfg["name"]:
            raise ServiceError(f"certificate is for {name}, not {cfg['name']}")

        self.barrier = br.Barrier(self._salt(sec), cfg["inventory"])
        self.trail = at.AuditTrail(state / "audit.jsonl")
        inner = au.AuditedExecutor(self.trail)
        self.executor = au.AuditedSafeExecutor(self.trail, inner, self.ca_cert,
                                               operators=cfg["operators"], protected_hosts=cfg["protected_hosts"])
        self.brain = bn.Brain(cfg["inventory"])
        self.gate = au.AuditedGate(self.trail, self.ca_cert, cfg["trusted_brains"],
                                   cfg["responsible_hosts"], self.brain, self.executor)
        self.memory = mem.ImmuneMemory(self.ca_cert, cfg["operators"])
        self.peers = {n: _parse_addr(a) for n, a in cfg["peers"].items()}
        self.monitor = hb.HeartbeatMonitor(list(self.peers), now=now)
        self.survival = tg.Tardigrade(TASKS)
        self.breath = tg.LastBreath(cfg["name"], self.role, self.key, self.cert,
                                    self._broadcast, cfg["inventory"])
        self.tailer = LogTailer(cfg["auth_log"])
        self.cache = msg.ReplayCache()
        self.sock = None
        self.outbox: list[bytes] = []   # used when no socket is open (tests)
        self._mode = self.survival.mode

    # ---------- helpers ----------
    @staticmethod
    def _salt(sec: Path) -> bytes:
        p = sec / "barrier.salt"
        if not p.exists():
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pysecrets.token_bytes(32))
        return p.read_bytes()

    def _log(self, text: str) -> None:
        print(f"{time.strftime('%H:%M:%S')} [{self.cfg['name']}] {text}", flush=True)

    def open_socket(self) -> int:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.cfg["bind"], self.cfg["port"]))
        self.sock.settimeout(0.2)
        return self.sock.getsockname()[1]

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def _broadcast(self, raw: bytes) -> None:
        if self.sock is None:
            self.outbox.append(raw)
            return
        for addr in self.peers.values():
            try:
                self.sock.sendto(raw, addr)
            except OSError:
                pass

    # ---------- inputs ----------
    def heartbeat(self) -> None:
        self._broadcast(msg.sign("heartbeat", {}, self.cfg["name"], self.role, self.key, self.cert))

    def ingest_fact(self, fact: dict, now: float) -> list:
        props = self.gate.observe_fact(fact, now)
        hit = self.memory.check(fact, now)
        if hit:
            props += self.gate.observe_fact(hit, now)
        if props:
            self.breath.remember(fact)
            for p in props:
                self._log(f"{p.action} {p.host} ({p.reason}) sensors={p.body()['sources']}")
        return props

    def poll_logs(self, now: float) -> int:
        n = 0
        for line in self.tailer.read_lines():
            for fact in self.barrier.process_line(line):
                self.ingest_fact(fact, now)
                n += 1
        return n

    def handle_raw(self, raw: bytes, now: float) -> str:
        try:
            m = msg.verify(raw, self.ca_cert, self.cache)
        except msg.MessageError as e:
            self.monitor.rejected(str(e), now=now)
            self.survival.record_reject(now)
            self._log(f"REJECTED message: {e}")
            return "rejected"
        if m.type == "heartbeat":
            for al in self.monitor.observe(m, now):
                self._log(f"ALERT {al.kind}: {al.peer} ({al.detail})")
            return "heartbeat"
        if m.type == "proposal":
            d = self.gate.decide(raw, now)
            what = f"{d.proposal.action} {d.proposal.host}" if d.proposal else "?"
            self._log(f"proposal {what} -> {d.reason}")
            return d.reason
        try:
            if m.type == "memory":
                n = self.memory.learn(raw, now)
                self._log(f"immune memory learned {n} address(es)")
                return "memory"
            if m.type == "alert" and isinstance(m.body, dict) and m.body.get("event") == "last-breath":
                r = tg.receive_last_breath(m, self.brain, now, self.cfg["inventory"])
                self._log(f"last breath from {m.sender}: {r}")
                return "last-breath"
        except (mem.ImmuneError, tg.SurvivalError) as e:
            self._log(f"REFUSED {m.type}: {e}")
            return "refused"
        return "ignored"

    def receive_once(self, now: float):
        try:
            data, _ = self.sock.recvfrom(65535)
        except OSError:
            return None
        return self.handle_raw(data, now)

    # ---------- housekeeping ----------
    def tick(self, now: float) -> str:
        for al in self.monitor.check(now):
            self._log(f"ALERT {al.kind}: {al.peer} ({al.detail})")
            if al.kind == "silent":
                self.brain.ring_alert(al.peer, now)
        mode = self.survival.update(now, silent_peers=len(self.monitor.silent))
        if mode != self._mode:
            self._log(f"MODE {self._mode} -> {mode}; running: {sorted(self.survival.running())}")
            self._mode = mode
        self.executor.executor.tick(now)
        return mode

    def run(self) -> None:
        self.open_socket()
        self.breath.install()
        self._log(f"started as {self.role}; peers: {', '.join(self.peers) or 'none'}; "
                  f"watching {self.cfg['auth_log']}")
        next_beat = next_poll = 0.0
        while True:
            now = time.monotonic()
            if now >= next_beat:
                self.heartbeat()
                next_beat = now + hb.INTERVAL
            if now >= next_poll:
                self.poll_logs(now)
                next_poll = now + 1.0
            self.receive_once(now)
            self.tick(now)


def main() -> None:
    p = argparse.ArgumentParser(description="core-defense arm service")
    p.add_argument("--config", required=True)
    a = p.parse_args()
    try:
        ArmService(load_config(a.config)).run()
    except (ServiceError, idn.IdentityError) as e:
        raise SystemExit(f"cannot start: {e}")


if __name__ == "__main__":
    main()
