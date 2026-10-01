import pytest

from arms import executor as ex
from arms import gate as gt
from arms import safety as sf
from brain import brain as bn
from brain.brain import Proposal
from ring import identity as idn
from ring import message as msg
from test_gate import body, host_log_evidence, network_evidence
from test_barrier import INV


def ISO(host):
    return Proposal("isolate", host, "lateral-movement-confirmed", ("host-log", "network"), 3)


@pytest.fixture
def world(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path)
    ids = {n: idn.issue(ca_key, ca_cert, n, r) for n, r in [
        ("op-shehab", "operator"), ("op-unknown", "operator"), ("arm-01", "arm"), ("brain-01", "brain")]}
    safe = sf.SafeExecutor(ex.Executor(), ca_cert, operators={"op-shehab"},
                           protected_hosts={"db-01"}, max_strong=3, window=600.0)

    def op(operation, request="", who="op-shehab", role="operator"):
        k, c = ids[who]
        return msg.sign("approval", {"op": operation, "request": request}, who, role, k, c)
    return safe, op, ids, ca_cert


def test_weak_actions_on_protected_host_still_run(world):
    safe, *_ = world
    rec = safe.apply(Proposal("watch", "db-01", "brute-force", ("host-log",), 1), now=0.0)
    assert isinstance(rec, ex.ActionRecord) and rec.action == "watch"


def test_isolating_protected_host_is_held(world):
    safe, *_ = world
    held = safe.apply(ISO("db-01"), now=0.0)
    assert isinstance(held, sf.PendingApproval) and held.why == "protected-host"
    assert safe.records == {}


def test_operator_approval_executes(world):
    safe, op, *_ = world
    held = safe.apply(ISO("db-01"), now=0.0)
    rec = safe.handle_operator(op("approve", held.id), now=5.0)
    assert rec.action == "isolate" and held.state == "approved" and held.decided_by == "op-shehab"


def test_operator_denial_executes_nothing(world):
    safe, op, *_ = world
    held = safe.apply(ISO("db-01"), now=0.0)
    safe.handle_operator(op("deny", held.id), now=5.0)
    assert held.state == "denied" and safe.records == {}


@pytest.mark.parametrize("who,role", [("arm-01", "arm"), ("brain-01", "brain"), ("op-unknown", "operator")],
                         ids=["arm", "brain", "untrusted-operator"])
def test_only_trusted_operator_can_approve(world, who, role):
    safe, op, *_ = world
    held = safe.apply(ISO("db-01"), now=0.0)
    with pytest.raises(sf.SafetyError):
        safe.handle_operator(op("approve", held.id, who=who, role=role), now=5.0)
    assert held.state == "pending" and safe.records == {}


def test_replayed_approval_rejected(world):
    safe, op, *_ = world
    a = safe.apply(ISO("db-01"), now=0.0)
    raw = op("approve", a.id)
    safe.handle_operator(raw, now=1.0)
    with pytest.raises(sf.SafetyError):
        safe.handle_operator(raw, now=2.0)


def test_circuit_breaker_trips_and_stays_tripped(world):
    safe, *_ = world
    results = [safe.apply(ISO(f"h-{i:02d}"), now=float(i)) for i in range(5)]
    assert [isinstance(r, ex.ActionRecord) for r in results] == [True, True, True, False, False]
    assert safe.tripped and results[3].why == "rate-limit"
    # Even after the window passes, it stays tripped until the operator resets
    assert isinstance(safe.apply(ISO("h-09"), now=5000.0), sf.PendingApproval)


def test_operator_reset_reopens_breaker(world):
    safe, op, *_ = world
    for i in range(4):
        safe.apply(ISO(f"h-{i:02d}"), now=float(i))
    safe.handle_operator(op("reset-breaker"), now=10.0)
    assert isinstance(safe.apply(ISO("h-20"), now=11.0), ex.ActionRecord)


def test_renewals_are_not_counted_or_blocked(world):
    safe, *_ = world
    for t in range(5):
        assert isinstance(safe.apply(ISO("h-00"), now=float(t)), ex.ActionRecord)
    assert not safe.tripped


def test_mass_isolation_attack_summary(world):
    safe, *_ = world
    results = [safe.apply(ISO(f"h-{i:02d}"), now=float(i)) for i in range(20)]
    executed = sum(isinstance(r, ex.ActionRecord) for r in results)
    held = sum(isinstance(r, sf.PendingApproval) for r in results)
    print(f"\nMass-isolation attack: 20 isolate requests -> {executed} executed, "
          f"{held} held for operator, breaker tripped: {safe.tripped}")
    assert executed == 3 and held == 17 and safe.tripped


def test_gate_reports_awaiting_approval(world, tmp_path):
    safe, _, ids, ca_cert = world
    safe.protected = frozenset({"mcp-proxy"})
    gate = gt.Gate(ca_cert, trusted_brains={"brain-01"}, responsible_hosts={"mcp-proxy"},
                   local_brain=bn.Brain(INV), executor=safe)
    host_log_evidence(gate)
    network_evidence(gate)
    k, c = ids["brain-01"]
    d = gate.decide(msg.sign("proposal", body(), "brain-01", "brain", k, c), now=12.0)
    assert not d.accepted and d.reason == "awaiting-approval"
    assert d not in gate.refusals
