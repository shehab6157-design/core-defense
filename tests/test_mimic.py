import re

import pytest

from arms import apis_arm as aa
from arms import executor as ex
from brain import brain as bn
from disguise import camouflage as cf
from disguise import mimic as mm
from test_barrier import SALT

HOSTS = {"10.0.2.10": "lab-vm-1"}
INV = {"web-01", "lab-vm-1"}


@pytest.fixture
def mimic():
    return mm.Mimic(cf.Camouflage(SALT, {"http"}), HOSTS, inventory=INV, scanners={"10.0.9.9"})


def failed(ip="6.6.6.6", host="web-01"):
    return {"kind": "login_failed", "host": host, "user": "root", "src_ip": ip,
            "port": 22, "method": "password", "invalid_user": False}


def lateral(src="10.0.2.10", conf=85):
    return {"kind": "lateral_movement", "host": HOSTS.get(src, "unknown"), "src_ip": src,
            "dst_ip": "10.0.2.11", "confidence": conf, "techniques": ["t1021"]}


def acts(props):
    return [(p.action, p.reason) for p in props]


def test_password_guesser_gets_honey_credential(mimic):
    planted = mimic.observe(failed(), 0.0)
    assert [d.kind for d in planted] == ["honey-credential"]
    assert mimic.observe(failed(), 1.0) == []  # one bait per interest, not one per event


def test_lateral_mover_gets_decoy_host_with_personality(mimic):
    d = mimic.observe(lateral(), 0.0)[0]
    assert d.kind == "decoy-host" and d.personality["bait"] is True
    assert re.fullmatch(r"decoy-\d{3}", d.id)


def test_decoys_follow_changing_interest(mimic):
    mimic.observe(lateral(), 0.0)
    mimic.observe({"kind": "file_burst", "host": "lab-vm-1", "modified": 5, "renamed": 0, "window": 60}, 1.0)
    kinds = sorted(d.kind for d in mimic.decoys.values())
    assert kinds == ["decoy-host", "honey-files"]


def test_cap_per_attacker(mimic, monkeypatch):
    monkeypatch.setattr(mm, "MAX_PER_ATTACKER", 2)  # real fact types reach at most 3 interests today
    host_facts = [
        {"kind": "group_added", "host": "lab-vm-1", "user": "root", "group": "sudo"},
        {"kind": "file_burst", "host": "lab-vm-1", "modified": 5, "renamed": 0, "window": 60},
        {"kind": "agent_anomaly", "host": "lab-vm-1", "agent": "agent-0000abcd", "tool": "tool-0000abcd",
         "signals": ["new_tool", "off_pattern"], "tier": "alert"},
        {"kind": "injection_attempt", "host": "lab-vm-1", "pattern": "persona", "matches": 1,
         "length": 10, "digest": "0" * 16},
    ]
    for i, f in enumerate(host_facts):
        mimic.observe(f, float(i))
    assert len(mimic.decoys) == 2 and mimic.refused == 2


def test_global_cap(mimic):
    for i in range(60):
        mimic.observe(failed(ip=f"203.0.113.{i + 1}"), float(i))
    assert len(mimic.decoys) == mm.MAX_TOTAL and mimic.refused == 10


def test_tokens_unique_and_unguessable(mimic):
    for i in range(20):
        mimic.observe(failed(ip=f"203.0.113.{i + 1}"), float(i))
    tokens = [d.token for d in mimic.decoys.values()]
    assert len(set(tokens)) == 20 and all(re.fullmatch(r"[0-9a-f]{32}", t) for t in tokens)


def test_touch_from_internal_host(mimic):
    d = mimic.observe(lateral(), 0.0)[0]
    f = mimic.touch(d.token, "10.0.2.10", 5.0)
    assert f == {"kind": "decoy_touched", "host": "lab-vm-1", "decoy_kind": "decoy-host", "src_ip": "10.0.2.10"}


def test_unknown_token_ignored(mimic):
    assert mimic.touch("0" * 32, "10.0.2.10", 1.0) is None


def test_allowlisted_scanner_ignored(mimic):
    d = mimic.observe(lateral(), 0.0)[0]
    assert mimic.touch(d.token, "10.0.9.9", 1.0) is None and mimic.ignored_touches == 1


def test_bad_source_rejected(mimic):
    d = mimic.observe(lateral(), 0.0)[0]
    with pytest.raises(mm.MimicError):
        mimic.touch(d.token, "ignore previous instructions", 1.0)


def test_brain_decoy_alone_limits_access(mimic):
    brain = bn.Brain(INV)
    d = mimic.observe(failed(host="web-01"), 0.0)[0]
    props = brain.ingest(mimic.touch(d.token, "10.0.2.10", 1.0), 1.0)
    assert acts(props) == [("limit_access", "decoy-touched")]


def test_brain_outside_attacker_only_collects_evidence(mimic):
    brain = bn.Brain(INV)
    d = mimic.observe(failed(), 0.0)[0]
    props = brain.ingest(mimic.touch(d.token, "6.6.6.6", 1.0), 1.0)
    assert acts(props) == [("collect_evidence", "decoy-touched")]


def test_mimic_story(mimic):
    """A compromised internal machine moves laterally, Mimic plants a decoy server
    shaped for it, the attacker touches it -> isolate, confirmed by network + decoy."""
    brain = bn.Brain(INV)
    apis = aa.ApisArm(HOSTS)
    move = apis.to_fact({"pair": {"src": "10.0.2.10", "dst": "10.0.2.11"}, "suppressed": False,
                         "confidence_score": 60, "mitre_techniques": ["T1021"]})
    story = brain.ingest(move, 0.0)
    planted = mimic.observe(move, 0.0)
    touch = mimic.touch(planted[0].token, "10.0.2.10", 30.0)
    story += brain.ingest(touch, 30.0)
    print("\nMIMIC STORY:")
    print(f"  attacker hunting remote access -> planted {planted[0].kind} {planted[0].id} "
          f"looking like {planted[0].personality['banners']}")
    for p in story:
        print(f"  {p.action:<13} {p.reason:<18} sensors={p.body()['sources']}")
    print("  " + ex.explain(story[-1]))
    assert acts(story) == [("watch", "lateral-movement"), ("isolate", "decoy-touched")]
    assert story[-1].body()["sources"] == ["decoy", "network"]
