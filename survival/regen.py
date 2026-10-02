"""Regeneration: rebuild an arm from a clean, signed image (Phase 5b, R6, T4).

- A RELEASE MANIFEST lists every code file of an arm with its SHA-256 hash,
  signed by a trusted operator.
- Before an arm is admitted to the ring, its installed files are checked
  against the signed manifest: modified, missing, or unexpected extra code
  files mean it is NOT clean and it is refused.
- Regeneration restores an arm from a clean image: the image itself is
  verified first, damaged files are restored, unexpected files are MOVED to
  .quarantine/ (kept as evidence, never run), and the result is verified
  again before admission.
Honest limit: manifests are signed with an operator identity (max 7 days).
A real deployment would use a separate long-lived, offline release key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
from pathlib import Path, PurePosixPath

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ring import identity as idn

CODE_SUFFIXES = (".py",)
QUARANTINE = ".quarantine"
_PATH_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*")
_HASH_RE = re.compile(r"[0-9a-f]{64}")


class RegenError(Exception):
    pass


def _safe_rel(p) -> str:
    if not isinstance(p, str) or not _PATH_RE.fullmatch(p) or ".." in PurePosixPath(p).parts:
        raise RegenError(f"unsafe path in manifest: {p!r}")
    return p


def _sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _canon(d) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _code_files(root: Path):
    for f in sorted(root.rglob("*")):
        parts = f.relative_to(root).parts
        if f.is_file() and f.suffix in CODE_SUFFIXES and QUARANTINE not in parts and "__pycache__" not in parts:
            yield f


def build_manifest(root, version: str) -> dict:
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RegenError("version must look like 1.2.3")
    root = Path(root)
    files = {_safe_rel(f.relative_to(root).as_posix()): _sha(f) for f in _code_files(root)}
    if not files:
        raise RegenError("no code files found")
    return {"version": version, "files": files}


def sign_manifest(manifest: dict, key, cert) -> dict:
    sig = key.sign(_canon(manifest), ec.ECDSA(hashes.SHA256()))
    return {"manifest": manifest, "cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "sig": base64.b64encode(sig).decode()}


def _check_shape(m) -> dict:
    if not isinstance(m, dict) or set(m) != {"version", "files"}:
        raise RegenError("bad manifest structure")
    if not isinstance(m["version"], str) or not isinstance(m["files"], dict) or not m["files"]:
        raise RegenError("bad manifest structure")
    for p, h in m["files"].items():
        _safe_rel(p)
        if not isinstance(h, str) or not _HASH_RE.fullmatch(h):
            raise RegenError("bad hash in manifest")
    return m


def verify_manifest(signed, ca_cert, trusted_operators) -> dict:
    """Return the manifest if signed by a trusted operator, else raise RegenError."""
    try:
        cert = x509.load_pem_x509_certificate(signed["cert"].encode())
        name, _ = idn.verify(cert, ca_cert, expected_role="operator")
    except (KeyError, TypeError, ValueError, AttributeError, idn.IdentityError) as e:
        raise RegenError(f"untrusted signer: {e}") from None
    if name not in trusted_operators:
        raise RegenError("signer is not a trusted operator")
    m = signed.get("manifest")
    try:
        cert.public_key().verify(base64.b64decode(signed["sig"], validate=True), _canon(m), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        raise RegenError("bad signature: manifest altered or forged") from None
    return _check_shape(m)


def check_install(root, manifest: dict) -> list[str]:
    """Problems found: 'missing:...', 'modified:...', 'unexpected:...'. Empty = clean."""
    root = Path(root)
    problems = []
    for rel, h in manifest["files"].items():
        p = root / rel
        if not p.is_file() or p.is_symlink():
            problems.append(f"missing:{rel}")
        elif _sha(p) != h:
            problems.append(f"modified:{rel}")
    for f in _code_files(root):
        rel = f.relative_to(root).as_posix()
        if rel not in manifest["files"]:
            problems.append(f"unexpected:{rel}")
    return sorted(problems)


def regenerate(image_dir, target_dir, manifest: dict) -> dict:
    """Restore target_dir to exactly the signed release, using a verified clean image."""
    image_dir, target_dir = Path(image_dir), Path(target_dir)
    if check_install(image_dir, manifest):
        raise RegenError("clean image does not match the signed manifest - refusing")
    target_dir.mkdir(parents=True, exist_ok=True)
    quarantined, restored = [], []
    for prob in check_install(target_dir, manifest):
        kind, rel = prob.split(":", 1)
        if kind == "unexpected":
            dst = target_dir / QUARANTINE / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target_dir / rel), str(dst))
            quarantined.append(rel)
    for rel, h in manifest["files"].items():
        dst = target_dir / rel
        if dst.is_symlink() or not dst.is_file() or _sha(dst) != h:
            if dst.is_symlink() or dst.exists():
                dst.unlink()  # never write THROUGH a planted symlink
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(image_dir / rel, dst)
            restored.append(rel)
    remaining = check_install(target_dir, manifest)
    if remaining:
        raise RegenError(f"still not clean after regeneration: {remaining}")
    return {"restored": sorted(restored), "quarantined": sorted(quarantined)}


class Admission:
    """Ring admission: only arms whose installed code matches the signed release may join."""

    def __init__(self, signed_manifest, ca_cert, trusted_operators):
        self.manifest = verify_manifest(signed_manifest, ca_cert, frozenset(trusted_operators))

    def admit(self, root) -> tuple[bool, list[str]]:
        problems = check_install(root, self.manifest)
        return (not problems, problems)
