"""A ring node: sends signed heartbeats to peers and watches them.

Usage:
  python -m ring.node NAME --port 9001 --peer arm-02=127.0.0.1:9002 --peer ...
"""
from __future__ import annotations

import argparse
import socket
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ring import heartbeat as hb
from ring import identity as idn
from ring import message as msg


def load_identity(secrets: Path, name: str):
    idn.check_name(name)
    key = serialization.load_pem_private_key((secrets / f"{name}.key").read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate((secrets / f"{name}.crt").read_bytes())
    ca_cert = x509.load_pem_x509_certificate((secrets / "ca.crt").read_bytes())
    # Refuse to start with an invalid or expired identity (R6)
    my_name, role = idn.verify(cert, ca_cert)
    if my_name != name:
        raise SystemExit(f"certificate is for {my_name}, not {name}")
    return key, cert, ca_cert, role


def parse_peer(s: str):
    name, addr = s.split("=", 1)
    host, port = addr.rsplit(":", 1)
    idn.check_name(name)
    return name, (host, int(port))


def log(name: str, text: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} [{name}] {text}", flush=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("name")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--peer", action="append", default=[], type=parse_peer)
    p.add_argument("--secrets", default="secrets")
    p.add_argument("--bind", default="127.0.0.1")
    a = p.parse_args()

    key, cert, ca_cert, role = load_identity(Path(a.secrets), a.name)
    peers = dict(a.peer)
    mon = hb.HeartbeatMonitor(list(peers))
    cache = msg.ReplayCache()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((a.bind, a.port))
    sock.settimeout(0.25)
    log(a.name, f"started as {role}, watching: {', '.join(peers) or 'nobody'}")

    seen: set[str] = set()
    next_beat = 0.0
    try:
        while True:
            now = time.monotonic()
            if now >= next_beat:
                raw = msg.sign("heartbeat", {}, a.name, role, key, cert)
                for addr in peers.values():
                    try:
                        sock.sendto(raw, addr)
                    except OSError:
                        pass
                next_beat = now + hb.INTERVAL
            try:
                data, src = sock.recvfrom(65535)
            except OSError:  # timeout, or a dead peer's port refused
                data = None
            if data is not None:
                try:
                    m = msg.verify(data, ca_cert, cache)
                except msg.MessageError as e:
                    for al in mon.rejected(str(e), source=f"{src[0]}:{src[1]}"):
                        log(a.name, f"ALERT rejected message from {al.peer}: {al.detail}")
                else:
                    if m.sender in peers and m.sender not in seen:
                        seen.add(m.sender)
                        log(a.name, f"{m.sender} is alive")
                    for al in mon.observe(m):
                        log(a.name, f"ALERT {al.kind}: {al.peer} ({al.detail})")
            for al in mon.check():
                log(a.name, f"ALERT {al.kind}: {al.peer} ({al.detail})")
    except KeyboardInterrupt:
        log(a.name, "stopped")


if __name__ == "__main__":
    main()
