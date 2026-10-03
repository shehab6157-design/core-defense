"""Real firewall backend (nftables) with built-in safety (Phase 7b).

Actions (only on THIS host - it cannot firewall other machines):
  isolate        drop all traffic in and out, except management + ring peers
  limit_access   drop NEW inbound connections, except management + ring peers
  anything else  no firewall change (recorded only)

Safety design:
  - management addresses and ring peers are ALWAYS allowed, and the backend
    refuses to run without at least one management address
  - loopback is always allowed
  - every blocking rule only applies while this host's address is in a TIMED
    kernel set. When the timeout passes, the KERNEL itself switches the block
    off - even if this service crashes or is killed (dead-man switch)
  - the ruleset is replaced atomically (never half-applied)
Honest limits: IPv4 only for now; renewing an action does not yet extend the
kernel timer (wired in Phase 7b part 2).

CLI (needs root or CAP_NET_ADMIN):
  python -m arms.nft_backend install --own-ip IP --mgmt IP [--peer IP]
  python -m arms.nft_backend apply isolate --own-ip IP --mgmt IP --deadman 120
  python -m arms.nft_backend undo isolate --own-ip IP --mgmt IP
  python -m arms.nft_backend status | remove
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
import subprocess

TABLE = "coredefense"
SETS = {"isolate": "iso_on", "limit_access": "limit_on"}
MIN_DEADMAN, MAX_DEADMAN = 30, 3600
NFT = "/usr/sbin/nft"


class FirewallError(Exception):
    pass


def _ip(v) -> str:
    try:
        return str(ipaddress.IPv4Address(v))
    except (ipaddress.AddressValueError, ValueError, TypeError):
        raise FirewallError(f"not an IPv4 address: {v!r}") from None


def run_nft(script: str) -> str:
    r = subprocess.run([NFT, "-f", "-"], input=script, text=True, capture_output=True, timeout=10)
    if r.returncode != 0:
        raise FirewallError(f"nft failed: {r.stderr.strip()[:300]}")
    return r.stdout


class NftBackend:
    def __init__(self, own_host: str, own_ip: str, management, peers=(), deadman: int = 900, runner=None):
        if not management:
            raise FirewallError("refusing to run without a management address")
        if not MIN_DEADMAN <= deadman <= MAX_DEADMAN:
            raise FirewallError(f"dead-man timeout must be {MIN_DEADMAN}-{MAX_DEADMAN} seconds")
        self.own_host = own_host
        self.own_ip = _ip(own_ip)
        self.allow = sorted({_ip(a) for a in [*management, *peers]})
        self.deadman = deadman
        self.runner = runner or run_nft
        self.calls: list[tuple] = []
        self.active: set[tuple] = set()

    def ruleset(self) -> str:
        allow = ", ".join(self.allow)
        return (
            f"add table inet {TABLE}\n"
            f"delete table inet {TABLE}\n"
            f"table inet {TABLE} {{\n"
            f"    set allow {{ type ipv4_addr; elements = {{ {allow} }} }}\n"
            f"    set iso_on {{ type ipv4_addr; flags timeout; }}\n"
            f"    set limit_on {{ type ipv4_addr; flags timeout; }}\n"
            f"    chain input {{\n"
            f"        type filter hook input priority -10; policy accept;\n"
            f"        iif \"lo\" accept\n"
            f"        ip saddr @allow accept\n"
            f"        ip daddr @iso_on drop\n"
            f"        ip daddr @limit_on ct state new drop\n"
            f"    }}\n"
            f"    chain output {{\n"
            f"        type filter hook output priority -10; policy accept;\n"
            f"        oif \"lo\" accept\n"
            f"        ip daddr @allow accept\n"
            f"        ip saddr @iso_on drop\n"
            f"    }}\n"
            f"}}\n"
        )

    def install(self) -> None:
        self.runner(self.ruleset())

    def apply(self, action: str, host: str) -> None:
        self.calls.append(("apply", action, host))
        if host != self.own_host:
            raise FirewallError(f"can only act on own host {self.own_host}, not {host}")
        if action not in SETS:
            return  # no firewall change for weaker actions
        self.runner(f"add element inet {TABLE} {SETS[action]} {{ {self.own_ip} timeout {self.deadman}s }}\n")
        self.active.add((action, host))

    def undo(self, action: str, host: str) -> None:
        self.calls.append(("undo", action, host))
        if action not in SETS or host != self.own_host:
            return
        try:
            self.runner(f"delete element inet {TABLE} {SETS[action]} {{ {self.own_ip} }}\n")
        except FirewallError:
            pass  # the kernel timer already removed it - that is fine
        self.active.discard((action, host))

    def remove(self) -> None:
        self.runner(f"delete table inet {TABLE}\n")


def main() -> None:
    p = argparse.ArgumentParser(prog="nft_backend")
    p.add_argument("cmd", choices=["install", "apply", "undo", "status", "remove"])
    p.add_argument("action", nargs="?", choices=sorted(SETS))
    p.add_argument("--own-host", default=socket.gethostname())
    p.add_argument("--own-ip")
    p.add_argument("--mgmt", action="append", default=[])
    p.add_argument("--peer", action="append", default=[])
    p.add_argument("--deadman", type=int, default=900)
    a = p.parse_args()
    try:
        if a.cmd == "status":
            r = subprocess.run([NFT, "list", "table", "inet", TABLE], text=True, capture_output=True)
            print(r.stdout or "(no core-defense table)")
            return
        if a.cmd == "remove":
            run_nft(f"delete table inet {TABLE}\n")
            print("core-defense table removed")
            return
        b = NftBackend(a.own_host, a.own_ip, a.mgmt, a.peer, a.deadman)
        if a.cmd == "install":
            b.install()
            print(f"installed; always allowed: {b.allow}")
        elif a.cmd == "apply":
            b.apply(a.action, a.own_host)
            print(f"{a.action} ON for {a.own_host}; kernel switches it off in {a.deadman}s")
        else:
            b.undo(a.action, a.own_host)
            print(f"{a.action} OFF for {a.own_host}")
    except FirewallError as e:
        raise SystemExit(f"REFUSED: {e}")


if __name__ == "__main__":
    main()
