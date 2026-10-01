import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from ring import identity as idn
from ring import message as msg


@pytest.fixture
def pki(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path)
    arm = idn.issue(ca_key, ca_cert, "arm-01", "arm")
    brain = idn.issue(ca_key, ca_cert, "brain-01", "brain")
    return ca_cert, arm, brain


def arm_msg(pki, mtype="report", body=None, **kw):
    _, (k, c), _ = pki
    return msg.sign(mtype, body or {"event": "ok"}, "arm-01", "arm", k, c, **kw)


def test_valid_message_accepted(pki):
    m = msg.verify(arm_msg(pki), pki[0], msg.ReplayCache())
    assert (m.sender, m.role, m.type, m.body) == ("arm-01", "arm", "report", {"event": "ok"})


def test_altered_body_rejected(pki):
    # Attacker intercepts a report and changes it to "all clear"
    data = json.loads(arm_msg(pki, body={"event": "intrusion"}))
    data["body"] = {"event": "all clear"}
    with pytest.raises(msg.MessageError, match="signature"):
        msg.verify(json.dumps(data).encode(), pki[0], msg.ReplayCache())


def test_replay_rejected(pki):
    raw, cache = arm_msg(pki), msg.ReplayCache()
    msg.verify(raw, pki[0], cache)
    with pytest.raises(msg.MessageError, match="replayed"):
        msg.verify(raw, pki[0], cache)


def test_stale_rejected(pki):
    raw = arm_msg(pki, now=time.time() - 120)
    with pytest.raises(msg.MessageError, match="stale"):
        msg.verify(raw, pki[0], msg.ReplayCache())


def test_foreign_ca_rejected(pki, tmp_path):
    evil_key, evil_ca = idn.create_ca(tmp_path / "evil")
    k, c = idn.issue(evil_key, evil_ca, "arm-01", "arm")
    raw = msg.sign("report", {"event": "ok"}, "arm-01", "arm", k, c)
    with pytest.raises(msg.MessageError, match="untrusted sender"):
        msg.verify(raw, pki[0], msg.ReplayCache())


def test_stolen_cert_without_key_rejected(pki):
    # Attacker copies arm-01's public certificate but signs with their own key
    _, (_, arm_cert), _ = pki
    fake_key = ec.generate_private_key(ec.SECP256R1())
    raw = msg.sign("report", {"event": "ok"}, "arm-01", "arm", fake_key, arm_cert)
    with pytest.raises(msg.MessageError, match="signature"):
        msg.verify(raw, pki[0], msg.ReplayCache())


def test_impersonation_rejected(pki):
    # arm-01 claims to be arm-02
    _, (k, c), _ = pki
    raw = msg.sign("report", {"event": "ok"}, "arm-02", "arm", k, c)
    with pytest.raises(msg.MessageError, match="does not match"):
        msg.verify(raw, pki[0], msg.ReplayCache())


def test_arm_cannot_send_proposals(pki):
    with pytest.raises(msg.MessageError, match="may not send"):
        msg.verify(arm_msg(pki, "proposal"), pki[0], msg.ReplayCache())


def test_brain_can_send_proposals(pki):
    ca_cert, _, (bk, bc) = pki
    raw = msg.sign("proposal", {"action": "watch", "host": "arm-01"}, "brain-01", "brain", bk, bc)
    assert msg.verify(raw, ca_cert, msg.ReplayCache()).type == "proposal"


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"{}", b"x" * (70 * 1024)], ids=["not-json", "list", "empty", "oversized"])
def test_garbage_rejected(pki, raw):
    with pytest.raises(msg.MessageError):
        msg.verify(raw, pki[0], msg.ReplayCache())
