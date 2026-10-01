from cryptography.hazmat.primitives.asymmetric import ec

from ring import heartbeat as hb
from ring import identity as idn
from ring import message as msg


def beat(peer, role="arm"):
    return msg.Message("heartbeat", peer, role, 0.0, "n", {})


def run(mon, alive_until, end, step=0.5):
    """Simulate time: peers beat every 2s until their 'death', monitor checks every 0.5s."""
    t = 0.0
    while t <= end:
        for peer, until in alive_until.items():
            if t <= until and t % 2.0 == 0:
                mon.observe(beat(peer), now=t)
        mon.check(now=t)
        t = round(t + step, 3)


def kinds(mon, kind):
    return [a for a in mon.alerts if a.kind == kind]


def test_healthy_peer_no_alerts():
    mon = hb.HeartbeatMonitor(["arm-01"], now=0.0)
    run(mon, {"arm-01": 100}, end=30)
    assert mon.alerts == []


def test_killed_arm_detected_once_with_measured_time():
    mon = hb.HeartbeatMonitor(["arm-01"], now=0.0)
    run(mon, {"arm-01": 10.0}, end=30)
    silent = kinds(mon, "silent")
    assert len(silent) == 1, "alert must fire once, not spam"
    time_to_alert = silent[0].at - 10.0
    print(f"\ntime-to-alert: {time_to_alert:.1f}s")
    assert mon.timeout < time_to_alert <= mon.timeout + 0.5


def test_only_dead_peer_is_flagged():
    mon = hb.HeartbeatMonitor(["arm-01", "arm-02"], now=0.0)
    run(mon, {"arm-01": 100, "arm-02": 10.0}, end=30)
    assert [a.peer for a in kinds(mon, "silent")] == ["arm-02"]


def test_peer_that_never_starts_is_flagged():
    mon = hb.HeartbeatMonitor(["arm-01", "arm-02"], now=0.0)
    run(mon, {"arm-01": 100}, end=10)
    assert [a.peer for a in kinds(mon, "silent")] == ["arm-02"]


def test_recovery_is_reported():
    mon = hb.HeartbeatMonitor(["arm-01"], now=0.0)
    run(mon, {"arm-01": 10.0}, end=20)
    mon.observe(beat("arm-01"), now=21.0)
    assert len(kinds(mon, "recovered")) == 1


def test_unexpected_peer_flagged_once():
    mon = hb.HeartbeatMonitor(["arm-01"], now=0.0)
    mon.observe(beat("arm-99"), now=1.0)
    mon.observe(beat("arm-99"), now=2.0)
    assert len(kinds(mon, "unexpected-peer")) == 1


def test_forged_heartbeats_cannot_fake_life(tmp_path):
    # Arm is killed; attacker replays its public certificate with their own key
    ca_key, ca_cert = idn.create_ca(tmp_path)
    k, c = idn.issue(ca_key, ca_cert, "arm-01", "arm")
    cache = msg.ReplayCache()
    mon = hb.HeartbeatMonitor(["arm-01"], now=0.0)
    real = msg.sign("heartbeat", {}, "arm-01", "arm", k, c)
    mon.observe(msg.verify(real, ca_cert, cache), now=0.0)
    fake_key = ec.generate_private_key(ec.SECP256R1())
    for t in (2.0, 4.0, 6.0, 8.0):
        forged = msg.sign("heartbeat", {}, "arm-01", "arm", fake_key, c)
        try:
            mon.observe(msg.verify(forged, ca_cert, cache), now=t)
        except msg.MessageError as e:
            mon.rejected(str(e), now=t, source="claims arm-01")
    mon.check(now=8.0)
    assert len(kinds(mon, "silent")) == 1
    assert len(kinds(mon, "rejected-message")) == 4
