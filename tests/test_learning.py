import pytest

from brain import brain as bn
from learning import learner as ln
from learning import suite as st
from ring import identity as idn
from ring import message as msg


@pytest.fixture
def world(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path)
    ids = {n: idn.issue(ca_key, ca_cert, n, r) for n, r in [
        ("op-shehab", "operator"), ("op-unknown", "operator"), ("brain-01", "brain")]}
    lr = ln.Learner(ca_cert, {"op-shehab"}, st.SUITE, st.INVENTORY | {"db-01"})

    def fb(host, reason, verdict, who="op-shehab", role="operator"):
        k, c = ids[who]
        return msg.sign("feedback", {"host": host, "reason": reason, "verdict": verdict}, who, role, k, c)
    return lr, fb


def bf(lr, host):
    return lr.params().get(host, {}).get("brute_force", bn.NORMAL["brute_force"])


def test_baseline_passes_suite(world):
    lr, _ = world
    assert lr.evaluate({}) == (True, [])


@pytest.mark.parametrize("who,role", [("op-unknown", "operator"), ("brain-01", "brain")],
                         ids=["untrusted-operator", "brain"])
def test_only_trusted_operator_can_teach(world, who, role):
    lr, fb = world
    with pytest.raises(ln.LearnError):
        lr.submit(fb("web-01", "brute-force", "false-alarm", who=who, role=role), 0.0)
    assert lr.pending == [] and lr.rejected_feedback == 1


def test_bad_correction_refused(world):
    lr, fb = world
    with pytest.raises(ln.LearnError):
        lr.submit(fb("web-01", "service-spawned-shell", "false-alarm"), 0.0)  # damage is not tunable


def test_false_alarm_makes_one_host_less_sensitive(world):
    lr, fb = world
    lr.submit(fb("web-01", "brute-force", "false-alarm"), 0.0)
    assert lr.sleep(10.0) == "adopted"
    assert bf(lr, "web-01") == 6 and bf(lr, "db-01") == 5


def test_missed_attack_makes_host_more_sensitive(world):
    lr, fb = world
    lr.submit(fb("web-01", "brute-force", "missed-attack"), 0.0)
    assert lr.sleep(10.0) == "adopted" and bf(lr, "web-01") == 4


def test_never_below_hard_floor(world):
    lr, fb = world
    for cycle in range(5):
        lr.submit(fb("web-01", "brute-force", "missed-attack"), float(cycle))
        lr.sleep(float(cycle) + 0.5)
    assert bf(lr, "web-01") == ln.TUNABLE["brute_force"][0] == 3


def test_no_learning_during_fever_or_survival(world):
    lr, fb = world
    lr.submit(fb("web-01", "brute-force", "false-alarm"), 0.0)
    assert lr.sleep(1.0, fever=True) == "postponed"
    assert lr.sleep(2.0, survival=True) == "postponed"
    assert len(lr.pending) == 1 and lr.sleep(3.0) == "adopted"


def test_one_step_per_cycle(world):
    lr, fb = world
    for _ in range(10):
        lr.submit(fb("web-01", "brute-force", "false-alarm"), 0.0)
    lr.sleep(1.0)
    assert bf(lr, "web-01") == 6


def test_conflicting_corrections_cancel(world):
    lr, fb = world
    lr.submit(fb("web-01", "brute-force", "false-alarm"), 0.0)
    lr.submit(fb("web-01", "brute-force", "missed-attack"), 0.0)
    assert lr.sleep(1.0) == "no-change"


def test_change_that_hides_known_attack_is_refused(world):
    lr, fb = world
    lr.submit(fb("web-01", "brute-force", "false-alarm"), 0.0)
    lr.sleep(1.0)                                   # 5 -> 6: suite still passes
    lr.submit(fb("web-01", "brute-force", "false-alarm"), 2.0)
    assert lr.sleep(3.0) == "rejected"              # 6 -> 7 would miss "brute-force-6"
    assert bf(lr, "web-01") == 6
    assert lr.alarms[-1][0] == "candidate-rejected"


def test_correction_flood_raises_alarm(world):
    lr, fb = world
    for _ in range(25):
        lr.submit(fb("web-01", "brute-force", "false-alarm"), 0.0)
    lr.sleep(1.0)
    assert ("correction-flood", 25) in lr.alarms and bf(lr, "web-01") == 6


def test_rollback(world):
    lr, fb = world
    lr.submit(fb("web-01", "brute-force", "false-alarm"), 0.0)
    lr.sleep(1.0)
    lr.rollback(1)
    assert lr.params() == {} and len(lr.versions) == 2


def test_learned_settings_reach_the_brain(world):
    lr, fb = world
    lr.submit(fb("web-01", "brute-force", "false-alarm"), 0.0)
    lr.sleep(1.0)
    b = bn.Brain(st.INVENTORY)
    lr.apply_to(b)
    assert b.thresholds("web-01", 0.0)["brute_force"] == 6


def test_inflammation_still_overrides_learning(world):
    lr, fb = world
    lr.submit(fb("web-01", "brute-force", "false-alarm"), 0.0)
    lr.sleep(1.0)
    b = bn.Brain(st.INVENTORY)
    lr.apply_to(b)
    b.ring_alert("web-01", 0.0)
    assert b.thresholds("web-01", 1.0) == bn.INFLAMED


def test_stolen_key_poisoning_summary(world):
    """Attacker with a stolen operator key tries to blind brute-force detection."""
    lr, fb = world
    results = []
    for cycle in range(10):
        for _ in range(5):
            lr.submit(fb("web-01", "brute-force", "false-alarm"), float(cycle))
        results.append(lr.sleep(float(cycle) + 0.5))
    ok, failures = lr.evaluate(lr.params())
    detected = sum(1 for s in st.SUITE if s[1] == "attack") - len(failures)
    attacks = sum(1 for s in st.SUITE if s[1] == "attack")
    print(f"\nSTOLEN-KEY POISONING: 50 signed 'false alarm' corrections over 10 sleep cycles")
    print(f"  brute-force threshold: 5 -> {bf(lr, 'web-01')} (attacker wanted it as high as possible)")
    print(f"  versions adopted: {results.count('adopted')}, refused by regression suite: {results.count('rejected')}")
    print(f"  known attack scenarios still detected: {detected}/{attacks}")
    assert bf(lr, "web-01") == 6 and ok and detected == attacks
