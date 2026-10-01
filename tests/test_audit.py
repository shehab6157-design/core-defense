import json
import stat

import pytest

from arms import apis_arm as aa
from arms import audited as au
from audit import trail as at
from brain import brain as bn
from ring import identity as idn
from ring import message as msg
from test_barrier import INV
from test_gate import body, host_log_evidence, network_evidence


@pytest.fixture
def filled(tmp_path):
    t = at.AuditTrail(tmp_path / "audit.jsonl")
    for i in range(5):
        t.append({"event": "test", "n": i}, wall=1000.0 + i)
    return t


def lines(t):
    return t.path.read_text().splitlines()


def write(t, ls):
    t.path.write_text("\n".join(ls) + "\n")


def test_intact_trail_verifies(filled):
    ok, n, bad, head = at.verify(filled.path)
    assert ok and n == 5 and bad is None and head == filled.head()


def test_edited_entry_detected(filled):
    ls = lines(filled)
    ls[2] = ls[2].replace('"n": 2', '"n": 99')
    write(filled, ls)
    assert at.verify(filled.path)[:3] == (False, 2, 3)


def test_deleted_entry_detected(filled):
    ls = lines(filled)
    del ls[1]
    write(filled, ls)
    assert at.verify(filled.path)[2] == 2


def test_reordered_entries_detected(filled):
    ls = lines(filled)
    ls[1], ls[2] = ls[2], ls[1]
    write(filled, ls)
    assert at.verify(filled.path)[2] == 2


def test_truncation_needs_anchor(filled):
    anchor = filled.head()
    write(filled, lines(filled)[:3])
    assert at.verify(filled.path)[0] is True           # honest limit: chain alone can't see it
    assert at.verify(filled.path, expected_head=anchor)[0] is False   # anchor catches it


def test_reopen_continues_chain(filled):
    t2 = at.AuditTrail(filled.path)
    t2.append({"event": "after-restart"})
    assert at.verify(t2.path)[:2] == (True, 6)


def test_reopen_refuses_broken_trail(filled):
    ls = lines(filled)
    ls[0] = ls[0].replace('"n": 0', '"n": 7')
    write(filled, ls)
    with pytest.raises(at.AuditError):
        at.AuditTrail(filled.path)


def test_reserved_fields_rejected(filled):
    with pytest.raises(at.AuditError):
        filled.append({"event": "x", "hash": "fake"})


def test_trail_file_owner_only(filled):
    assert stat.S_IMODE(filled.path.stat().st_mode) == 0o600


def test_phase2_story_fully_audited_and_tamper_evident(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path / "pki")
    ids = {n: idn.issue(ca_key, ca_cert, n, r) for n, r in [("brain-01", "brain"), ("op-shehab", "operator")]}
    trail = at.AuditTrail(tmp_path / "audit.jsonl")
    safe = au.AuditedSafeExecutor(trail, au.AuditedExecutor(trail), ca_cert,
                                  operators={"op-shehab"}, protected_hosts={"db-01"})
    gate = au.AuditedGate(trail, ca_cert, {"brain-01"}, {"mcp-proxy", "db-01"},
                          bn.Brain(INV | {"db-01"}), safe)

    def propose(b):
        k, c = ids["brain-01"]
        return msg.sign("proposal", b, "brain-01", "brain", k, c)

    def operator(op, req):
        k, c = ids["op-shehab"]
        return msg.sign("approval", {"op": op, "request": req}, "op-shehab", "operator", k, c)

    # 1. Real attack on mcp-proxy, seen by host logs + network -> isolated
    host_log_evidence(gate)
    network_evidence(gate)
    gate.decide(propose(body()), now=12.0)
    # 2. Stolen brain key tries to isolate db-01 with no evidence -> refused
    gate.decide(propose(body(host="db-01")), now=13.0)
    # 3. Real evidence on db-01 (network + its arm goes silent) -> protected, so held
    apis = aa.ApisArm({"10.0.2.20": "db-01"})
    gate.observe_fact(apis.to_fact({"pair": {"src": "10.0.2.20", "dst": "10.0.2.11"}, "suppressed": False,
                                    "confidence_score": 90, "mitre_techniques": ["T1021"]}), 20.0)
    gate.observe_ring_silence("db-01", 21.0)
    held = gate.decide(propose(body(host="db-01", sources=("network", "ring"))), now=22.0)
    # 4. Operator approves -> executed
    safe.handle_operator(operator("approve", held.record.id), now=30.0)
    # 5. Time passes, no fresh evidence -> both actions expire
    safe.executor.tick(now=700.0)

    entries = [json.loads(x) for x in trail.path.read_text().splitlines()]
    print("\nAUDIT TIMELINE:")
    for e in entries:
        detail = e.get("decision") or e.get("by") or e.get("why") or ""
        print(f"  {e['seq']:>2}. {e['event']:<24} {e.get('host', ''):<10} {detail}")
        if e["event"] == "action-started":
            print(f"      -> {e['explanation']}")

    assert [e["event"] for e in entries] == [
        "action-started", "proposal-decision",
        "proposal-decision",
        "action-held", "proposal-decision",
        "action-started", "operator-approved",
        "action-ended", "action-ended",
    ]
    assert at.verify(trail.path, expected_head=trail.head())[0]

    # Attacker edits the log to hide the refused stolen-key attempt
    ls = trail.path.read_text().splitlines()
    ls[2] = ls[2].replace("not-corroborated", "accepted")
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_text("\n".join(ls) + "\n")
    ok, checked, bad, _ = at.verify(tampered)
    print(f"TAMPER TEST: edited entry 3 -> verify ok={ok}, chain breaks at entry {bad}")
    assert not ok and bad == 3
