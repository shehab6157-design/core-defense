import json
import shutil

import pytest

from arms import bait as bt
from ring import identity as idn
from survival import regen as rg

ARM_FILES = {
    "arm/__init__.py": "",
    "arm/core.py": "def run():\n    return 'defending'\n",
    "arm/sensors/net.py": "def sense():\n    return []\n",
}


def write_tree(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


@pytest.fixture
def world(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path / "pki")
    ids = {n: idn.issue(ca_key, ca_cert, n, r) for n, r in [
        ("op-shehab", "operator"), ("op-unknown", "operator"), ("arm-01", "arm")]}
    image = tmp_path / "image"
    write_tree(image, ARM_FILES)
    manifest = rg.build_manifest(image, "1.0.0")
    k, c = ids["op-shehab"]
    signed = rg.sign_manifest(manifest, k, c)
    installed = tmp_path / "installed"
    shutil.copytree(image, installed)
    return {"ca": (ca_key, ca_cert), "ids": ids, "image": image, "installed": installed,
            "manifest": manifest, "signed": signed}


def test_manifest_lists_every_code_file(world):
    assert sorted(world["manifest"]["files"]) == sorted(ARM_FILES)


def test_trusted_signed_manifest_verifies(world):
    m = rg.verify_manifest(world["signed"], world["ca"][1], {"op-shehab"})
    assert m == world["manifest"]


def test_altered_manifest_rejected(world):
    s = json.loads(json.dumps(world["signed"]))
    s["manifest"]["files"]["arm/core.py"] = "0" * 64
    with pytest.raises(rg.RegenError, match="signature"):
        rg.verify_manifest(s, world["ca"][1], {"op-shehab"})


@pytest.mark.parametrize("who", ["op-unknown", "arm-01"])
def test_untrusted_signers_rejected(world, who):
    k, c = world["ids"][who]
    with pytest.raises(rg.RegenError):
        rg.verify_manifest(rg.sign_manifest(world["manifest"], k, c), world["ca"][1], {"op-shehab"})


def test_foreign_ca_signer_rejected(world, tmp_path):
    evil_key, evil_ca = idn.create_ca(tmp_path / "evil")
    k, c = idn.issue(evil_key, evil_ca, "op-shehab", "operator")
    with pytest.raises(rg.RegenError, match="untrusted signer"):
        rg.verify_manifest(rg.sign_manifest(world["manifest"], k, c), world["ca"][1], {"op-shehab"})


@pytest.mark.parametrize("bad", ["../evil.py", "/etc/passwd", "arm/../../x.py", ".hidden/x.py"])
def test_unsafe_paths_rejected(bad):
    with pytest.raises(rg.RegenError):
        rg._safe_rel(bad)


def test_clean_install_admitted(world):
    adm = rg.Admission(world["signed"], world["ca"][1], {"op-shehab"})
    assert adm.admit(world["installed"]) == (True, [])


def test_tampering_detected(world):
    inst = world["installed"]
    (inst / "arm/core.py").write_text("def run():\n    return 'backdoored'\n")
    (inst / "arm/sensors/net.py").unlink()
    (inst / "arm/helper_evil.py").write_text("import os\n")
    adm = rg.Admission(world["signed"], world["ca"][1], {"op-shehab"})
    ok, problems = adm.admit(inst)
    assert not ok and problems == ["missing:arm/sensors/net.py", "modified:arm/core.py",
                                   "unexpected:arm/helper_evil.py"]


def test_regeneration_restores_and_quarantines(world):
    inst = world["installed"]
    (inst / "arm/core.py").write_text("backdoor = True\n")
    (inst / "arm/sensors/net.py").unlink()
    (inst / "arm/helper_evil.py").write_text("import os\n")
    result = rg.regenerate(world["image"], inst, world["manifest"])
    assert result == {"restored": ["arm/core.py", "arm/sensors/net.py"], "quarantined": ["arm/helper_evil.py"]}
    assert rg.check_install(inst, world["manifest"]) == []
    assert (inst / ".quarantine/arm/helper_evil.py").read_text() == "import os\n"   # evidence kept


def test_planted_symlink_is_replaced_not_followed(world, tmp_path):
    inst = world["installed"]
    outside = tmp_path / "outside.txt"
    outside.write_text("must not change")
    (inst / "arm/core.py").unlink()
    (inst / "arm/core.py").symlink_to(outside)
    rg.regenerate(world["image"], inst, world["manifest"])
    assert outside.read_text() == "must not change"
    assert not (inst / "arm/core.py").is_symlink()


def test_poisoned_clean_image_refused(world):
    (world["image"] / "arm/core.py").write_text("poisoned = True\n")
    with pytest.raises(rg.RegenError, match="clean image"):
        rg.regenerate(world["image"], world["installed"], world["manifest"])


def test_regeneration_story(world, tmp_path):
    """arm-02 is captured; its install is tampered; it is rebuilt from the signed image."""
    q = bt.Quarantine()
    replacement = q.capture("arm-02", 0.0, "contradiction")
    inst = tmp_path / "arm-02-install"
    shutil.copytree(world["image"], inst)
    (inst / "arm/core.py").write_text("def run():\n    exfiltrate()\n")
    (inst / "arm/persist.py").write_text("# attacker persistence\n")
    adm = rg.Admission(world["signed"], world["ca"][1], {"op-shehab"})
    before = adm.admit(inst)
    result = rg.regenerate(world["image"], inst, adm.manifest)
    after = adm.admit(inst)
    ca_key, ca_cert = world["ca"]
    _, cert = bt.issue_replacement(ca_key, ca_cert, replacement)
    print("\nREGENERATION STORY:")
    print(f"  captured arm-02 -> admission check: {before}")
    print(f"  regenerated from signed image v{adm.manifest['version']}: {result}")
    print(f"  admission after regeneration: {after}")
    print(f"  rejoins as {idn.verify(cert, ca_cert, expected_role='arm')[0]} with a fresh identity")
    assert before[0] is False and after == (True, [])
