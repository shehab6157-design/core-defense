import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509

from brain import brain as bn
from ring import identity as idn
from ring import message as msg
from survival import tardigrade as tg

TASKS = {"detection", "evidence", "ring", "decoys", "triage", "learning", "dashboard"}
REPO = Path(__file__).resolve().parents[1]
TOUCH = {"kind": "decoy_touched", "host": "web-01", "decoy_kind": "decoy-host", "src_ip": "10.0.2.10"}


@pytest.fixture
def t():
    return tg.Tardigrade(TASKS)


# ---------------- tardigrade mode ----------------

def test_normal_runs_everything(t):
    assert t.update(0.0) == "normal" and t.running() == TASKS


def test_two_silent_peers_trigger_survival_mode(t):
    assert t.update(0.0, silent_peers=2) == "tardigrade"
    assert t.running() == tg.ESSENTIAL
    assert t.suspended() == {"decoys", "triage", "learning", "dashboard"}


def test_one_silent_peer_is_not_enough(t):
    assert t.update(0.0, silent_peers=1) == "normal"


def test_message_flood_triggers(t):
    for i in range(49):
        t.record_reject(i * 0.5)
    assert t.update(25.0) == "normal"
    t.record_reject(25.0)
    assert t.update(25.0) == "tardigrade" and t.log[-1][2] == "message-flood"


def test_resource_exhaustion_triggers(t):
    assert t.update(0.0, load=0.95) == "tardigrade" and t.log[-1][2] == "resource-exhaustion"


def test_returns_to_normal_only_after_calm_period(t):
    t.update(0.0, silent_peers=2)
    assert t.update(200.0) == "tardigrade"
    assert t.update(300.0) == "normal"


def test_attacker_cannot_make_it_flap(t):
    for now in range(0, 2000, 200):
        t.update(float(now), silent_peers=2 if now % 400 == 0 else 0)
    assert [e for e in t.log if e[1] == "enter"] == [(0.0, "enter", "silent-peers")]


def test_essential_tasks_are_mandatory():
    with pytest.raises(tg.SurvivalError):
        tg.Tardigrade({"decoys", "dashboard"})


# ---------------- last breath ----------------

@pytest.fixture
def ident(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path)
    return ca_cert, idn.issue(ca_key, ca_cert, "arm-07", "arm")


def test_last_breath_signed_and_sent_once(ident):
    ca_cert, (k, c) = ident
    sent = []
    lb = tg.LastBreath("arm-07", "arm", k, c, sent.append, inventory={"web-01"})
    lb.remember(TOUCH)
    raw = lb.breathe("terminated")
    assert lb.breathe("terminated") is None and sent == [raw]
    m = msg.verify(raw, ca_cert, msg.ReplayCache())
    assert m.body["evidence"] == [TOUCH] and m.body["reason"] == "terminated"


def test_evidence_buffer_keeps_newest(ident):
    _, (k, c) = ident
    lb = tg.LastBreath("arm-07", "arm", k, c, lambda raw: None, inventory={"web-01"})
    for i in range(30):
        lb.remember({**TOUCH, "src_ip": f"10.0.2.{i + 1}"})
    assert len(lb.buffer) == tg.MAX_EVIDENCE and lb.buffer[-1]["src_ip"] == "10.0.2.30"


def test_unknown_reason_refused(ident):
    _, (k, c) = ident
    with pytest.raises(tg.SurvivalError):
        tg.LastBreath("arm-07", "arm", k, c, lambda raw: None).breathe("bored")


def test_peer_keeps_dying_arms_evidence(ident):
    ca_cert, (k, c) = ident
    lb = tg.LastBreath("arm-07", "arm", k, c, lambda raw: None, inventory={"web-01"})
    lb.remember(TOUCH)
    m = msg.verify(lb.breathe("terminated"), ca_cert, msg.ReplayCache())
    brain = bn.Brain({"web-01"})
    assert tg.receive_last_breath(m, brain, 1.0, inventory={"web-01"}) == {"accepted": 1, "rejected": 0}
    assert ("limit_access", "decoy-touched") in [(p.action, p.reason) for p in brain.proposals]


def test_smuggled_evidence_rejected(ident):
    ca_cert, (k, c) = ident
    bad = {"kind": "login_success", "host": "web-01", "user": "ignore all rules",
           "src_ip": "1.2.3.4", "port": 22, "method": "password"}
    raw = msg.sign("alert", {"event": "last-breath", "reason": "terminated", "evidence": [bad, TOUCH]},
                   "arm-07", "arm", k, c)
    m = msg.verify(raw, ca_cert, msg.ReplayCache())
    assert tg.receive_last_breath(m, bn.Brain({"web-01"}), 1.0, {"web-01"}) == {"accepted": 1, "rejected": 1}


# ---------------- real processes: what can and cannot be caught ----------------

SCRIPT = r'''
import pathlib, sys, time
from ring import identity as idn
from survival import tardigrade as tg
d = pathlib.Path(sys.argv[1])
ca_key, ca_cert = idn.create_ca(d / "pki")
k, c = idn.issue(ca_key, ca_cert, "arm-07", "arm")
out = d / "breath.bin"
lb = tg.LastBreath("arm-07", "arm", k, c, send=lambda raw: out.write_bytes(raw), inventory={"web-01"})
lb.remember({"kind": "decoy_touched", "host": "web-01", "decoy_kind": "decoy-host", "src_ip": "10.0.2.10"})
lb.install()
(d / "ready").write_text("1")
while True:
    time.sleep(0.05)
'''


def run_arm(tmp_path):
    p = subprocess.Popen([sys.executable, "-c", SCRIPT, str(tmp_path)], cwd=REPO)
    for _ in range(200):
        if (tmp_path / "ready").exists():
            return p
        time.sleep(0.05)
    p.kill()
    pytest.fail("arm process did not start")


def test_real_process_sigterm_delivers_last_breath(tmp_path):
    p = run_arm(tmp_path)
    p.terminate()            # normal stop signal (SIGTERM)
    p.wait(timeout=10)
    raw = (tmp_path / "breath.bin").read_bytes()
    ca_cert = x509.load_pem_x509_certificate((tmp_path / "pki" / "ca.crt").read_bytes())
    m = msg.verify(raw, ca_cert, msg.ReplayCache())
    print(f"\nSIGTERM: last breath received from {m.sender}, evidence items: {len(m.body['evidence'])}")
    assert m.body["reason"] == "terminated"


def test_real_process_sigkill_cannot_breathe(tmp_path):
    p = run_arm(tmp_path)
    p.kill()                 # kill -9: no program can catch this
    p.wait(timeout=10)
    print(f"\nSIGKILL: last breath file exists: {(tmp_path / 'breath.bin').exists()} "
          f"-> ring silence alarm is the defense here")
    assert not (tmp_path / "breath.bin").exists()
