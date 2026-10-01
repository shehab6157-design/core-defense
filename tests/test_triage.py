import random

import pytest

from brain import triage as tr
from brain.brain import Proposal
from ring import identity as idn
from ring import message as msg


def P(action="watch", host="h-01", reason="brute-force", sources=("host-log",)):
    return Proposal(action, host, reason, sources, 1)


@pytest.fixture
def world(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path)
    ids = {n: idn.issue(ca_key, ca_cert, n, r) for n, r in [
        ("op-shehab", "operator"), ("op-unknown", "operator"), ("brain-01", "brain")]}
    tri = tr.Triage(ca_cert, operators={"op-shehab"})

    def tolerate(host, reason, hours=24, who="op-shehab", role="operator"):
        k, c = ids[who]
        return msg.sign("tolerance", {"host": host, "reason": reason, "hours": hours}, who, role, k, c)
    return tri, tolerate


@pytest.fixture
def tri():
    return tr.Triage()


def test_single_weak_alert_is_never_shown(tri):
    tri.add(P(), 0.0)
    assert tri.visible(0.0) == []


def test_quickly_reinforced_alert_is_shown(tri):
    tri.add(P(), 0.0)
    tri.add(P(), 60.0)
    assert [t.reason for t in tri.visible(60.0)] == ["brute-force"]


def test_reinforcement_must_be_timely(tri):
    tri.add(P(), 0.0)
    tri.add(P(), 3000.0)  # five half-lives later: the first trail has faded
    assert tri.visible(3000.0) == []


def test_strong_actions_always_shown(tri):
    tri.add(P("limit_access", reason="login-after-brute-force"), 0.0)
    assert len(tri.visible(100_000.0)) == 1


def test_stronger_evidence_ranks_first(tri):
    tri.add(P("deploy_decoy", host="h-02", reason="lateral-movement", sources=("network",)), 0.0)
    tri.add(P("isolate", host="h-03", reason="lateral-movement-confirmed", sources=("network", "process")), 0.0)
    assert [t.host for t in tri.visible(1.0)] == ["h-03", "h-02"]


def test_tolerance_hides_known_noise(world):
    tri, tolerate = world
    tri.handle_operator(tolerate("h-01", "brute-force"), 0.0)
    for t in range(0, 300, 30):
        tri.add(P(), float(t))
    assert tri.visible(300.0) == []


def test_tolerance_never_hides_escalation(world):
    tri, tolerate = world
    tri.handle_operator(tolerate("h-01", "lateral-movement"), 0.0)
    tri.add(P("deploy_decoy", reason="lateral-movement", sources=("network",)), 1.0)
    assert tri.visible(2.0) == []
    tri.add(P("limit_access", reason="lateral-movement", sources=("network",)), 3.0)
    assert len(tri.visible(4.0)) == 1


def test_tolerance_expires(world):
    tri, tolerate = world
    tri.handle_operator(tolerate("h-01", "brute-force", hours=1), 0.0)
    tri.add(P(), 3700.0)
    tri.add(P(), 3710.0)
    assert len(tri.visible(3710.0)) == 1


@pytest.mark.parametrize("reason", ["service-spawned-shell", "mass-file-change", "privilege-granted",
                                    "lateral-movement-confirmed", "injection-attempt"])
def test_damage_and_serious_alerts_can_never_be_tolerated(world, reason):
    tri, tolerate = world
    with pytest.raises(tr.TriageError):
        tri.handle_operator(tolerate("h-01", reason), 0.0)


@pytest.mark.parametrize("who,role,hours", [("brain-01", "brain", 24), ("op-unknown", "operator", 24),
                                             ("op-shehab", "operator", 1000)],
                         ids=["brain-cannot", "untrusted-operator", "too-long"])
def test_bad_tolerance_requests_refused(world, who, role, hours):
    tri, tolerate = world
    with pytest.raises(tr.TriageError):
        tri.handle_operator(tolerate("h-01", "brute-force", hours=hours, who=who, role=role), 0.0)
    assert tri.tolerated == {}


def test_replayed_tolerance_refused(world):
    tri, tolerate = world
    raw = tolerate("h-01", "brute-force")
    tri.handle_operator(raw, 0.0)
    with pytest.raises(tr.TriageError):
        tri.handle_operator(raw, 1.0)


def test_noisy_day_summary(tri):
    rng = random.Random(7)
    noise = sorted((rng.uniform(0, 86_400), f"h-{rng.randrange(60):02d}",
                    rng.choice(["brute-force", "arm-silent", "lateral-movement"])) for _ in range(300))
    attack_at = 50_000.0
    attack = [(attack_at, P("watch", "web-01", "brute-force")),
              (attack_at + 10, P("limit_access", "web-01", "login-after-brute-force")),
              (attack_at + 50, P("isolate", "web-01", "lateral-movement-confirmed", ("host-log", "network")))]
    events = [(t, P("watch", h, r, ("network",) if r == "lateral-movement" else ("host-log",)))
              for t, h, r in noise] + attack
    events.sort(key=lambda e: e[0])

    pages, attack_paged = 0, False
    for t, p in events:
        trail = tri.add(p, t)
        if tri.is_visible(trail, t):
            pages += 1
            if p.host == "web-01" and p.action == "isolate":
                attack_paged = True
    raw = len(events)
    print(f"\nNOISY DAY (synthetic): {raw} raw alerts -> {pages} pages "
          f"({100 * (1 - pages / raw):.0f}% less noise), real attack paged: {attack_paged}")
    assert attack_paged and pages < raw * 0.2
