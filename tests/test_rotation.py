import datetime as dt
import stat

import pytest

from ring import identity as idn
from ring import message as msg
from ring import rotation as rt

PASS = "correct horse battery staple"


@pytest.fixture
def world(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path)
    return rt.Rotation(ca_key, ca_cert, hours=4), ca_cert, tmp_path


def test_fresh_cert_does_not_need_renewal(world):
    rot, *_ = world
    _, cert = rot.issue("arm-01", "arm")
    assert not rot.needs_renewal(cert, cert.not_valid_before_utc + dt.timedelta(hours=1))


def test_cert_near_end_needs_renewal(world):
    rot, *_ = world
    _, cert = rot.issue("arm-01", "arm")
    assert rot.needs_renewal(cert, cert.not_valid_after_utc - dt.timedelta(minutes=30))


def test_renewal_retires_old_key(world):
    rot, *_ = world
    _, old = rot.issue("arm-01", "arm")
    _, new = rot.renew("arm-01", "arm", old)
    assert new.serial_number != old.serial_number
    assert rot.current["arm-01"] == new.serial_number and old.serial_number in rot.retired


def test_current_key_accepted(world):
    rot, ca_cert, _ = world
    k, c = rot.issue("arm-01", "arm")
    raw = msg.sign("heartbeat", {}, "arm-01", "arm", k, c)
    assert rot.check(raw, msg.verify(raw, ca_cert, msg.ReplayCache())) is None


def test_copied_retired_key_raises_alarm(world):
    rot, ca_cert, _ = world
    old_k, old_c = rot.issue("arm-01", "arm")
    rot.renew("arm-01", "arm", old_c)
    raw = msg.sign("heartbeat", {}, "arm-01", "arm", old_k, old_c)   # attacker's stolen copy
    m = msg.verify(raw, ca_cert, msg.ReplayCache())                  # still time-valid...
    assert rot.check(raw, m) == "retired-key-in-use"                 # ...but caught
    assert rot.alarms == [("retired-key-in-use", "arm-01")]


def test_expired_key_raises_alarm(world, monkeypatch):
    rot, ca_cert, _ = world
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=10)
    monkeypatch.setattr(idn, "_now", lambda: past)
    k, c = rot.issue("arm-01", "arm")          # issued 10 h ago, lived 4 h -> expired
    monkeypatch.undo()
    raw = msg.sign("heartbeat", {}, "arm-01", "arm", k, c)
    with pytest.raises(msg.MessageError) as e:
        msg.verify(raw, ca_cert, msg.ReplayCache())
    assert rot.classify_rejection(str(e.value), "arm-01") == "expired-key-in-use"


def test_other_rejections_are_not_key_alarms(world):
    rot, *_ = world
    assert rot.classify_rejection("replayed message") is None


# ---------------- CA key protection ----------------

def test_protect_encrypts_ca_key(world):
    _, _, d = world
    idn.protect_ca(d, PASS)
    data = (d / "ca.key").read_bytes()
    assert b"ENCRYPTED" in data and stat.S_IMODE((d / "ca.key").stat().st_mode) == 0o600


def test_encrypted_ca_needs_passphrase(world):
    _, _, d = world
    idn.protect_ca(d, PASS)
    with pytest.raises(idn.IdentityError, match="passphrase required"):
        idn.load_ca(d)


def test_wrong_passphrase_rejected(world):
    _, _, d = world
    idn.protect_ca(d, PASS)
    with pytest.raises(idn.IdentityError, match="wrong passphrase"):
        idn.load_ca(d, "not the right passphrase")


def test_right_passphrase_can_still_issue(world):
    _, _, d = world
    idn.protect_ca(d, PASS)
    ca_key, ca_cert = idn.load_ca(d, PASS)
    _, cert = idn.issue(ca_key, ca_cert, "arm-09", "arm")
    assert idn.verify(cert, ca_cert) == ("arm-09", "arm")


def test_short_passphrase_refused(world):
    _, _, d = world
    with pytest.raises(idn.IdentityError):
        idn.protect_ca(d, "short")


def test_cannot_protect_twice(world):
    _, _, d = world
    idn.protect_ca(d, PASS)
    with pytest.raises(idn.IdentityError):
        idn.protect_ca(d, PASS)
