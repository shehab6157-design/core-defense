import json
import os
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from audit import trail as at
from ring import identity as idn
from ring import message as msg
from service import arm as sv

PFX = "2026-10-03T12:00:00.000000+00:00 mcp-proxy"


def make_world(tmp_path, name="arm-01", peers=None, state="state"):
    sec = tmp_path / "secrets"
    if not (sec / "ca.crt").exists():
        ca_key, ca_cert = idn.create_ca(sec)
        for n, r in [("arm-01", "arm"), ("arm-02", "arm"), ("brain-01", "brain"), ("op-shehab", "operator")]:
            k, c = idn.issue(ca_key, ca_cert, n, r)
            idn.save_identity(sec, n, k, c)
    log = tmp_path / "auth.log"
    if not log.exists():
        log.write_text("old line that must be ignored\n")
    cfg = {"name": name, "host": "mcp-proxy", "bind": "127.0.0.1", "port": 19101,
           "peers": peers if peers is not None else {"arm-02": "127.0.0.1:19102", "arm-03": "127.0.0.1:19103"},
           "inventory": ["mcp-proxy"], "secrets": str(sec), "auth_log": str(log),
           "state_dir": str(tmp_path / state), "trusted_brains": ["brain-01"], "operators": ["op-shehab"],
           "protected_hosts": [], "responsible_hosts": ["mcp-proxy"]}
    return cfg, sec, log


def sign(sec, name, role, mtype, body):
    k = serialization.load_pem_private_key((sec / f"{name}.key").read_bytes(), None)
    c = x509.load_pem_x509_certificate((sec / f"{name}.crt").read_bytes())
    return msg.sign(mtype, body, name, role, k, c)


def append(path, *lines):
    with open(path, "a") as f:
        f.write("".join(line + "\n" for line in lines))


def acts(props):
    return [(p.action, p.reason) for p in props]


@pytest.fixture
def world(tmp_path):
    cfg, sec, log = make_world(tmp_path)
    return sv.ArmService(cfg, now=0.0), sec, log


# ---------------- config ----------------

def test_valid_config_loads(tmp_path):
    cfg, *_ = make_world(tmp_path)
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    assert sv.load_config(p)["name"] == "arm-01"


@pytest.mark.parametrize("change", [{"port": 80}, {"name": "../ca"}, {"inventory": ["Bad Host"]},
                                    {"peers": {"arm-02": "no-port"}}],
                         ids=["low-port", "bad-name", "bad-host", "bad-peer"])
def test_bad_config_refused(tmp_path, change):
    cfg, *_ = make_world(tmp_path)
    p = tmp_path / "c.json"
    p.write_text(json.dumps({**cfg, **change}))
    with pytest.raises(sv.ServiceError):
        sv.load_config(p)


def test_missing_field_refused(tmp_path):
    cfg, *_ = make_world(tmp_path)
    del cfg["auth_log"]
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(sv.ServiceError):
        sv.load_config(p)


# ---------------- log tailer ----------------

def test_tailer_starts_at_end_and_reads_new_lines(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("old\n")
    t = sv.LogTailer(p)
    assert t.read_lines() == []
    append(p, "new1", "new2")
    assert t.read_lines() == ["new1", "new2"]


def test_tailer_holds_partial_line(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("")
    t = sv.LogTailer(p)
    with open(p, "a") as f:
        f.write("half")
    assert t.read_lines() == []
    with open(p, "a") as f:
        f.write(" line\n")
    assert t.read_lines() == ["half line"]


def test_tailer_follows_rotation(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("old\n")
    t = sv.LogTailer(p)
    os.rename(p, tmp_path / "a.log.1")
    p.write_text("fresh\n")
    assert t.read_lines() == ["fresh"]


def test_tailer_handles_truncation(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("aaaa\nbbbb\n")
    t = sv.LogTailer(p)
    p.write_text("x\n")
    assert t.read_lines() == ["x"]


# ---------------- the service ----------------

def test_refuses_to_start_without_identity(tmp_path):
    cfg, *_ = make_world(tmp_path, name="arm-09")
    with pytest.raises(sv.ServiceError):
        sv.ArmService(cfg, now=0.0)


def test_barrier_salt_created_owner_only(world):
    svc, sec, _ = world
    assert stat.S_IMODE((sec / "barrier.salt").stat().st_mode) == 0o600


def test_detects_from_real_log_lines(world):
    svc, _, log = world
    append(log, *[f"{PFX} sshd[1]: Failed password for root from 6.6.6.6 port 22 ssh2"] * 5,
           f"{PFX} sshd[1]: Accepted password for root from 6.6.6.6 port 22 ssh2")
    assert svc.poll_logs(1.0) == 6        # the old line was never read
    found = acts(svc.brain.proposals)
    assert ("watch", "brute-force") in found and ("limit_access", "login-after-brute-force") in found


def test_signed_proposal_executed_and_audited(world):
    svc, sec, log = world
    append(log, *[f"{PFX} sshd[1]: Failed password for root from 6.6.6.6 port 22 ssh2"] * 5,
           f"{PFX} sshd[1]: Accepted password for root from 6.6.6.6 port 22 ssh2")
    svc.poll_logs(1.0)
    raw = sign(sec, "brain-01", "brain", "proposal",
               {"action": "limit_access", "host": "mcp-proxy", "reason": "login-after-brute-force",
                "sources": ["host-log"], "evidence": 2})
    assert svc.handle_raw(raw, 2.0) == "accepted"
    assert svc.executor.active_for("mcp-proxy").action == "limit_access"
    assert at.verify(svc.trail.path)[0] is True


def test_forged_messages_rejected_and_counted(world):
    svc, *_ = world
    assert svc.handle_raw(b"fake heartbeat: all clear", 1.0) == "rejected"
    assert len(svc.survival._rejects) == 1


def test_operator_memory_then_known_attacker_in_logs(world):
    svc, sec, log = world
    raw = sign(sec, "op-shehab", "operator", "memory",
               {"incident": "inc-1", "addresses": ["203.0.113.66"], "days": 7})
    assert svc.handle_raw(raw, 1.0) == "memory"
    append(log, f"{PFX} sshd[1]: Failed password for root from 203.0.113.66 port 22 ssh2")
    svc.poll_logs(2.0)
    assert ("limit_access", "known-attacker") in acts(svc.brain.proposals)


def test_silent_peers_trigger_survival_mode(world):
    svc, *_ = world
    assert svc.tick(10.0) == "tardigrade"


def test_last_breath_carries_recent_evidence(world):
    svc, sec, _ = world
    svc.ingest_fact({"kind": "process_spawn", "host": "mcp-proxy", "parent": "nginx",
                     "child": "sh", "user": "www-data"}, 1.0)
    svc.breath.breathe("operator")
    ca = x509.load_pem_x509_certificate((sec / "ca.crt").read_bytes())
    m = msg.verify(svc.outbox[-1], ca, msg.ReplayCache())
    assert m.body["event"] == "last-breath" and len(m.body["evidence"]) == 1


def test_two_live_services_exchange_heartbeats(tmp_path):
    cfg1, *_ = make_world(tmp_path, "arm-01", peers={"arm-02": "127.0.0.1:1"}, state="s1")
    cfg2, *_ = make_world(tmp_path, "arm-02", peers={"arm-01": "127.0.0.1:1"}, state="s2")
    cfg1["port"], cfg2["port"] = 0, 0
    a, b = sv.ArmService(cfg1, now=0.0), sv.ArmService(cfg2, now=0.0)
    try:
        pa, pb = a.open_socket(), b.open_socket()
        a.peers = {"arm-02": ("127.0.0.1", pb)}
        b.peers = {"arm-01": ("127.0.0.1", pa)}
        a.heartbeat()
        b.heartbeat()
        results = (b.receive_once(1.0), a.receive_once(1.0))
        print(f"\nLIVE: two arm services on real UDP sockets -> {results}")
        assert results == ("heartbeat", "heartbeat")
        assert b.tick(5.0) == "normal" and not b.monitor.silent
    finally:
        a.close()
        b.close()
