"""Lab tool: send ONE signed message to an arm (stands in for a brain or the operator).

  python -m tools.send --as brain-01 --role brain --type proposal \
      --body '{"action": "isolate", "host": "mcp-proxy", "reason": "known-attacker",
               "sources": ["host-log", "memory"], "evidence": 3}'

The arm verifies the signature, role and freshness itself - this tool has no
special powers. It only works with identities issued by your own CA.
"""
import argparse
import json
import socket
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ring import identity as idn
from ring import message as msg


def main() -> None:
    p = argparse.ArgumentParser(prog="send")
    p.add_argument("--as", dest="name", required=True)
    p.add_argument("--role", required=True, choices=sorted(idn.ROLES))
    p.add_argument("--type", required=True)
    p.add_argument("--body", required=True, help="JSON object")
    p.add_argument("--to", default="127.0.0.1:9101")
    p.add_argument("--secrets", default="secrets")
    a = p.parse_args()
    idn.check_name(a.name)
    sec = Path(a.secrets)
    key = serialization.load_pem_private_key((sec / f"{a.name}.key").read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate((sec / f"{a.name}.crt").read_bytes())
    body = json.loads(a.body)
    raw = msg.sign(a.type, body, a.name, a.role, key, cert)
    host, port = a.to.rsplit(":", 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(raw, (host, int(port)))
    print(f"sent signed {a.type} from {a.name} ({len(raw)} bytes) to {a.to}")


if __name__ == "__main__":
    main()
