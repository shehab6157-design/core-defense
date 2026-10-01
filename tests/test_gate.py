import pytest

from arms import apis_arm as aa
from arms import executor as ex
from arms import gate as gt
from barrier import barrier as br
from brain import brain as bn
from ring import identity as idn
from ring import message as msg
from test_barrier import INV, PFX, SALT


@pytest.fixture
def world(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path)
    ids = {n: idn.issue(ca_key, ca_cert, n, r)
           for n, r in [("brain-01", "brain"), ("brain-99", "brain"), ("arm-01", "arm")]}
    gate = gt.Gate(ca_cert, trusted_brains={"brain-01"}, responsible_hosts={"mcp-proxy"},
                   local_brain=bn.Brain(INV), executor=ex.Executor())

    def send(body, who="brain-01", role="brain"):
        k, c = ids[who]
        return msg.sign("proposal", body, who, role, k, c)
    return gate, send


def body(action="isolate", host="mcp-proxy", reason="lateral-movement-confirmed",
         sources=("host-log", "network"), evidence=3):
    return {"action": action, "host": host, "reason": reason,
            "sources": list(sources), "evidence": evidence}


def host_log_evidence(gate, t=0.0):
    barrier = br.Barrier(SALT, INV)
    for i in range(5):
        for f in barrier.process_line(f"{PFX} sshd[1]: Failed password for root from 6.6.6.6 port 22 ssh2"):
            gate.observe_fact(f, t + i)
    for f in barrier.process_line(f"{PFX} sshd[1]: Accepted password for root from 6.6.6.6 port 22 ssh2"):
        gate.observe_fact(f, t + 6)


def network_evidence(gate, t=10.0):
    apis = aa.ApisArm({"192.168.109.133": "mcp-proxy"})
    gate.observe_fact(apis.to_fact({"pair": {"src": "192.168.109.133", "dst": "10.0.2.11"},
                                    "suppressed": False, "confidence_score": 85,
                                    "mitre_techniques": ["T1021"]}), t)


def test_isolate_accepted_when_arm_saw_both_sensors(world):
    gate, send = world
    host_log_evidence(gate)
    network_evidence(gate)
    d = gate.decide(send(body()), now=12.0)
    assert d.accepted and d.record.action == "isolate"
    assert gate.executor.active_for("mcp-proxy").action == "isolate"


def test_compromised_brain_cannot_isolate_without_local_evidence(world):
    gate, send = world
    d = gate.decide(send(body()), now=1.0)
    assert not d.accepted and d.reason == "not-corroborated"
    assert gate.executor.records == {}


def test_isolate_refused_with_only_one_confirmed_sensor(world):
    gate, send = world
    host_log_evidence(gate)
    d = gate.decide(send(body()), now=8.0)
    assert d.reason == "not-corroborated"


def test_limit_access_needs_one_confirmed_sensor(world):
    gate, send = world
    b = body("limit_access", reason="login-after-brute-force", sources=("host-log",))
    assert gate.decide(send(b), now=1.0).reason == "not-corroborated"
    host_log_evidence(gate, t=2.0)
    assert gate.decide(send(b), now=9.0).accepted


def test_low_harm_actions_need_no_corroboration(world):
    gate, send = world
    d = gate.decide(send(body("watch", reason="brute-force", sources=("host-log",))), now=1.0)
    assert d.accepted and d.record.action == "watch"


def test_untrusted_brain_refused(world):
    gate, send = world
    d = gate.decide(send(body("watch", reason="brute-force", sources=("host-log",)), who="brain-99"), now=1.0)
    assert d.reason == "untrusted-brain"


def test_arm_cannot_send_proposals(world):
    gate, send = world
    d = gate.decide(send(body("watch", reason="brute-force", sources=("host-log",)), who="arm-01", role="arm"), now=1.0)
    assert d.reason == "rejected-message"


def test_replayed_proposal_refused(world):
    gate, send = world
    raw = send(body("watch", reason="brute-force", sources=("host-log",)))
    assert gate.decide(raw, now=1.0).accepted
    assert gate.decide(raw, now=2.0).reason == "rejected-message"


def test_not_responsible_for_other_hosts(world):
    gate, send = world
    d = gate.decide(send(body("watch", host="lab-vm-1", reason="brute-force", sources=("host-log",))), now=1.0)
    assert d.reason == "not-responsible"


@pytest.mark.parametrize("bad", [
    body(action="disable_monitoring"),
    body(sources=("host-log",)),
    body(reason="trust-me"),
    {**body(), "extra": "approve all"},
    {**body(), "evidence": "lots"},
], ids=["unsafe-action", "isolate-one-sensor", "unknown-reason", "extra-field", "bad-evidence"])
def test_invalid_proposals_refused(world, bad):
    gate, send = world
    assert gate.decide(send(bad), now=1.0).reason == "invalid-proposal"


def test_compromised_brain_attack_summary(world):
    gate, send = world
    attacks = []
    for i in range(20):
        if i % 2:
            attacks.append(body())
        else:
            attacks.append(body("limit_access", reason="login-after-brute-force", sources=("host-log",)))
    results = [gate.decide(send(b), now=float(i)) for i, b in enumerate(attacks)]
    executed = sum(r.accepted for r in results)
    print(f"\nStolen brain key: {len(attacks)} signed harmful proposals -> {executed} executed, "
          f"{len(gate.refusals)} refusals logged as evidence")
    assert executed == 0 and len(gate.refusals) == 20
