import pytest

from arms import host_sensors as hs
from brain import brain as bn
from test_barrier import SALT

HOSTS = {"h-01", "h-02", "h-03", "h-04"}


@pytest.fixture
def brain():
    return bn.Brain(HOSTS)


def fails(brain, host, n, start=0.0, ip="6.6.6.6"):
    out = []
    for i in range(n):
        out += brain.ingest({"kind": "login_failed", "host": host, "user": "root", "src_ip": ip,
                             "port": 22, "method": "password", "invalid_user": False}, start + i)
    return out


def lateral(host, conf):
    return {"kind": "lateral_movement", "host": host, "src_ip": "10.0.2.10",
            "dst_ip": "10.0.2.11", "confidence": conf, "techniques": []}


def acts(props):
    return [(p.action, p.reason) for p in props]


def test_normal_host_needs_five_failures(brain):
    assert fails(brain, "h-01", 4) == []
    assert acts(fails(brain, "h-01", 1, start=4.0)) == [("watch", "brute-force")]


def test_inflamed_host_needs_only_three(brain):
    brain.ring_alert("h-01", 0.0)  # h-01 already shows trouble
    assert acts(fails(brain, "h-01", 3, start=1.0)) == [("watch", "brute-force")]


def test_inflammation_is_local(brain):
    brain.ring_alert("h-01", 0.0)
    assert fails(brain, "h-02", 4, start=1.0) == []


def test_inflammation_cools_down(brain):
    brain.ring_alert("h-01", 0.0)
    assert brain.inflamed("h-01", 100.0) and not brain.inflamed("h-01", 400.0)
    assert fails(brain, "h-01", 4, start=400.0) == []


def test_fever_when_three_hosts_in_trouble(brain):
    for h in ("h-01", "h-02", "h-03"):
        brain.ring_alert(h, 0.0)
    assert brain.fever_active(1.0)
    assert brain.thresholds("h-04", 1.0) == bn.FEVER
    assert acts(fails(brain, "h-04", 4, start=1.0)) == [("watch", "brute-force")]


def test_two_hosts_is_not_fever(brain):
    brain.ring_alert("h-01", 0.0)
    brain.ring_alert("h-02", 0.0)
    assert not brain.fever_active(1.0)


def test_fever_cools_down_by_itself(brain):
    for h in ("h-01", "h-02", "h-03"):
        brain.ring_alert(h, 0.0)
    assert brain.fever_active(500.0)
    assert not brain.fever_active(1000.0)
    assert brain.fever_log == [(0.0, 900.0)]


def test_fever_is_capped_then_must_cool_down(brain):
    def keep_hot(until, start=0.0):
        t = start
        while t <= until:
            for h in ("h-01", "h-02", "h-03"):
                brain.ring_alert(h, t)
            t += 100.0
    keep_hot(3500.0)
    assert brain.fever_active(3500.0)
    keep_hot(5000.0, start=3600.0)
    assert not brain.fever_active(5000.0)   # capped at 1 h, cooling down
    keep_hot(5500.0, start=5100.0)
    assert brain.fever_active(5500.0)       # cooldown over, can return


def test_inflamed_lowers_decoy_threshold(brain):
    assert acts(brain.ingest(lateral("h-02", 60), 0.0)) == [("watch", "lateral-movement")]
    brain.ingest(lateral("h-01", 40), 0.0)  # same sensor inflames the host: tests the threshold alone
    assert acts(brain.ingest(lateral("h-01", 60), 1.0)) == [("deploy_decoy", "lateral-movement")]


def test_inflamed_lowers_mass_file_threshold(brain):
    files_h1, files_h2 = hs.FileArm(SALT, "h-01"), hs.FileArm(SALT, "h-02")
    burst = {"modified": 120, "renamed": 0, "window": 60}
    assert brain.ingest(files_h2.to_fact(burst), 0.0) == []
    brain.ring_alert("h-01", 0.0)
    # ring silence + file burst = two independent sensors, so isolate is the correct answer
    assert acts(brain.ingest(files_h1.to_fact(burst), 1.0)) == [("isolate", "mass-file-change")]


def test_never_more_sensitive_than_the_floors():
    assert all(bn.INFLAMED[k] <= bn.FEVER[k] <= bn.NORMAL[k] for k in bn.NORMAL)
    assert bn.INFLAMED["brute_force"] >= 3


def test_fever_and_inflammation_never_weaken_two_sensor_rule(brain):
    for h in ("h-01", "h-02", "h-03"):
        brain.ring_alert(h, 0.0)
    assert brain.fever_active(1.0)
    files = hs.FileArm(SALT, "h-04")
    props = brain.ingest(files.to_fact({"modified": 5000, "renamed": 5000, "window": 10}), 1.0)
    assert acts(props) == [("limit_access", "mass-file-change")]  # one sensor -> never isolate


def test_sensitivity_summary(brain):
    normal = len(fails(bn.Brain(HOSTS), "h-01", 3))
    b = bn.Brain(HOSTS)
    b.ring_alert("h-01", 0.0)
    inflamed = len(fails(b, "h-01", 3, start=1.0))
    print(f"\nSAME 3 FAILED LOGINS: normal host -> {normal} alerts, inflamed host -> {inflamed} alert")
    print(f"THRESHOLDS  normal={bn.NORMAL}\n            fever={bn.FEVER}\n            inflamed={bn.INFLAMED}")
    assert normal == 0 and inflamed == 1
