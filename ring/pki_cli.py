"""Identity CLI:  python -m ring.pki_cli init | issue NAME ROLE | verify NAME"""
import argparse
from pathlib import Path

from cryptography import x509

from ring import identity as idn

SECRETS = Path("secrets")


def main() -> None:
    p = argparse.ArgumentParser(prog="pki")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the private CA (once)")
    i = sub.add_parser("issue", help="issue a component certificate")
    i.add_argument("name")
    i.add_argument("role", choices=sorted(idn.ROLES))
    i.add_argument("--hours", type=int, default=idn.DEFAULT_CERT_HOURS)
    v = sub.add_parser("verify", help="check a component certificate")
    v.add_argument("name")
    a = p.parse_args()
    try:
        if a.cmd == "init":
            if (SECRETS / "ca.key").exists():
                raise SystemExit("CA already exists - refusing to overwrite it")
            idn.create_ca(SECRETS)
            print("CA created in secrets/ (ca.key is private, mode 600)")
        elif a.cmd == "issue":
            ca_key, ca_cert = idn.load_ca(SECRETS)
            key, cert = idn.issue(ca_key, ca_cert, a.name, a.role, a.hours)
            idn.save_identity(SECRETS, a.name, key, cert)
            print(f"Issued {a.name} ({a.role}), valid until {cert.not_valid_after_utc:%Y-%m-%d %H:%M} UTC")
        else:
            idn.check_name(a.name)
            _, ca_cert = idn.load_ca(SECRETS)
            cert = x509.load_pem_x509_certificate((SECRETS / f"{a.name}.crt").read_bytes())
            name, role = idn.verify(cert, ca_cert)
            print(f"VALID: {name} ({role})")
    except idn.IdentityError as e:
        raise SystemExit(f"REJECTED: {e}")


if __name__ == "__main__":
    main()
