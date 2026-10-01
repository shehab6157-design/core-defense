import datetime as dt
import stat

import pytest

from ring import identity as idn


@pytest.fixture
def ca(tmp_path):
    return idn.create_ca(tmp_path)


def test_valid_identity_accepted(ca):
    ca_key, ca_cert = ca
    _, cert = idn.issue(ca_key, ca_cert, "arm-01", "arm")
    assert idn.verify(cert, ca_cert, expected_role="arm") == ("arm-01", "arm")


def test_foreign_ca_rejected(ca, tmp_path):
    # Attacker builds their own CA with the same name and forges an arm
    _, ca_cert = ca
    evil_key, evil_cert = idn.create_ca(tmp_path / "evil")
    _, forged = idn.issue(evil_key, evil_cert, "arm-01", "arm")
    with pytest.raises(idn.IdentityError, match="signature"):
        idn.verify(forged, ca_cert)


def test_expired_rejected(ca):
    ca_key, ca_cert = ca
    _, cert = idn.issue(ca_key, ca_cert, "arm-01", "arm", hours=1)
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)
    with pytest.raises(idn.IdentityError, match="expired"):
        idn.verify(cert, ca_cert, now=later)


def test_role_mismatch_rejected(ca):
    # A captured arm cannot pretend to be the brain
    ca_key, ca_cert = ca
    _, cert = idn.issue(ca_key, ca_cert, "arm-01", "arm")
    with pytest.raises(idn.IdentityError, match="role mismatch"):
        idn.verify(cert, ca_cert, expected_role="brain")


@pytest.mark.parametrize("bad", ["../ca", "ca", "Arm", "a" * 40, ""])
def test_bad_names_blocked(ca, bad):
    ca_key, ca_cert = ca
    with pytest.raises(idn.IdentityError):
        idn.issue(ca_key, ca_cert, bad, "arm")


def test_unknown_role_blocked(ca):
    ca_key, ca_cert = ca
    with pytest.raises(idn.IdentityError):
        idn.issue(ca_key, ca_cert, "arm-01", "admin")


def test_private_keys_are_owner_only(ca, tmp_path):
    ca_key, ca_cert = ca
    key, cert = idn.issue(ca_key, ca_cert, "arm-01", "arm")
    idn.save_identity(tmp_path, "arm-01", key, cert)
    for f in ("ca.key", "arm-01.key"):
        assert stat.S_IMODE((tmp_path / f).stat().st_mode) == 0o600
