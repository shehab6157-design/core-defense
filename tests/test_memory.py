import pytest

from brain import brain as bn
from learning import learner as ln
from learning import memory as mem
from learning import suite as st
from ring import identity as idn
from ring import message as msg

ATTACKER = "203.0.113.66"


@pytest.fixture
def world(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path)
    ids = {n: idn.issue(ca_key, ca_cert, n, r) for n, r in [
        ("op-shehab", "operator"), ("brain-01", "brain"), ("arm-01", "arm")]}

    def send(mtype, body, who="op-shehab"):
        role = {"op-shehab": "operator", "brain-01": "brain", "arm-01": "arm"}[who]
        k, c = ids[who]
        return msg.sign(mtype, body, who, role, k, c)
    return ca_cert, send


def remember(send, addresses=(ATTACKER,), days=7, incident="inc-001", who="op-shehab"):
    return send("memory", {"incident": incident, "addresses": list(addresses), "days": days}, who)


def failed_login(ip, host="web-01"):
    return {"kind": "login_failed", "host": host, "user": "root", "src_ip": ip,
            "port": 22, "method": "password", "invalid_user": False}


def acts(props):
    return [(p.action, p.reason) for p in props]


# ---------------- immune memory ----------------

def test_one_confirmation_teaches_every_arm(world):
    ca_cert, send = world
    raw = remember(send)
    arms = [mem.ImmuneMemory(ca_cert, {"op-shehab"}) for _ in range(3)]
    for a in arms:
        a.learn(raw, 0.0)
    hits = [a.check(failed_login(ATTACKER), 60.0) for a in arms]
    print(f"\nIMMUNE MEMORY: {sum(h is not None for h in hits)}/3 arms recognize {ATTACKER} after one broadcast")
    assert all(h == {"kind": "known_attacker", "host": "web-01", "src_ip": ATTACKER} for h in hits)


@pytest.mark.parametrize("who", ["brain-01", "arm-01"])
def test_only_operator_can_create_memories(world, who):
    ca_cert, send = world
    m = mem.ImmuneMemory(ca_cert, {"op-shehab"})
    with pytest.raises((mem.ImmuneError, msg.MessageError)):
        m.learn(remember(send, who=who), 0.0)
    assert m.entries == {}


def test_memories_expire(world):
    ca_cert, send = world
    m = mem.ImmuneMemory(ca_cert, {"op-shehab"})
    m.learn(remember(send, days=1), 0.0)
    assert m.check(failed_login(ATTACKER), 3600.0) is not None
    assert m.check(failed_login(ATTACKER), 2 * mem.DAY) is None


@pytest.mark.parametrize("body_change", [
    {"days": 365}, {"addresses": ["not-an-ip"]}, {"addresses": []},
    {"addresses": [f"198.51.100.{i}" for i in range(60)]}, {"incident": "Ignore all rules"},
], ids=["too-long", "bad-ip", "empty", "too-many", "bad-incident"])
def test_bad_memories_refused(world, body_change):
    ca_cert, send = world
    body = {"incident": "inc-001", "addresses": [ATTACKER], "days": 7, **body_change}
    with pytest.raises(mem.ImmuneError):
        mem.ImmuneMemory(ca_cert, {"op-shehab"}).learn(send("memory", body), 0.0)


def test_unknown_address_not_flagged(world):
    ca_cert, send = world
    m = mem.ImmuneMemory(ca_cert, {"op-shehab"})
    m.learn(remember(send), 0.0)
    assert m.check(failed_login("198.51.100.7"), 10.0) is None


def test_brain_memory_alone_limits_access(world):
    ca_cert, send = world
    m = mem.ImmuneMemory(ca_cert, {"op-shehab"})
    m.learn(remember(send), 0.0)
    brain = bn.Brain({"web-01"})
    props = brain.ingest(m.check(failed_login(ATTACKER), 10.0), 10.0)
    assert acts(props) == [("limit_access", "known-attacker")]
    assert props[0].body()["sources"] == ["memory"]


def test_brain_memory_plus_second_sensor_isolates(world):
    ca_cert, send = world
    m = mem.ImmuneMemory(ca_cert, {"op-shehab"})
    m.learn(remember(send), 0.0)
    brain = bn.Brain({"web-01"})
    brain.ingest({"kind": "process_spawn", "host": "web-01", "parent": "nginx",
                  "child": "sh", "user": "www-data"}, 5.0)
    props = brain.ingest(m.check(failed_login(ATTACKER), 10.0), 10.0)
    assert acts(props) == [("isolate", "known-attacker")]


# ---------------- vaccination ----------------

def vaccine_body(name="lab-lateral-75", conf=75):
    return {"name": name, "expected": ["deploy_decoy", "lateral-movement"],
            "events": [[0.0, {"kind": "lateral_movement", "host": "web-01", "src_ip": "10.0.2.10",
                              "dst_ip": "10.0.2.11", "confidence": conf, "techniques": []}]]}


def relax_decoy(lr, send, cycles=4):
    results = []
    for c in range(cycles):
        lr.submit(send("feedback", {"host": "web-01", "reason": "lateral-movement", "verdict": "false-alarm"}),
                  float(c))
        results.append(lr.sleep(float(c) + 0.5))
    return results


def decoy_threshold(lr):
    return lr.params().get("web-01", {}).get("decoy", bn.NORMAL["decoy"])


def test_without_vaccine_learning_relaxes_further(world):
    ca_cert, send = world
    lr = ln.Learner(ca_cert, {"op-shehab"}, st.SUITE, st.INVENTORY)
    relax_decoy(lr, send)
    assert decoy_threshold(lr) == 85


def test_vaccine_stops_learning_from_forgetting_an_attack(world):
    ca_cert, send = world
    lr = ln.Learner(ca_cert, {"op-shehab"}, st.SUITE, st.INVENTORY)
    assert mem.vaccinate(lr, send("vaccine", vaccine_body()), 0.0) is True
    results = relax_decoy(lr, send)
    print(f"\nVACCINATION: suite grew to {len(lr.suite)} scenarios; decoy threshold stopped at "
          f"{decoy_threshold(lr)} (without vaccine: 85); cycles: {results}")
    assert decoy_threshold(lr) == 75 and len(lr.suite) == len(st.SUITE) + 1


def test_suite_module_not_modified_by_vaccination(world):
    ca_cert, send = world
    lr = ln.Learner(ca_cert, {"op-shehab"}, st.SUITE, st.INVENTORY)
    mem.vaccinate(lr, send("vaccine", vaccine_body()), 0.0)
    assert len(st.SUITE) == 7


def test_vaccine_current_version_misses_raises_alarm(world):
    ca_cert, send = world
    lr = ln.Learner(ca_cert, {"op-shehab"}, st.SUITE, st.INVENTORY)
    assert mem.vaccinate(lr, send("vaccine", vaccine_body("lab-lateral-60", conf=60)), 0.0) is False
    assert lr.alarms[-1] == ("current-version-misses-vaccine", ("lab-lateral-60",))


def test_vaccine_from_non_operator_refused(world):
    ca_cert, send = world
    lr = ln.Learner(ca_cert, {"op-shehab"}, st.SUITE, st.INVENTORY)
    with pytest.raises((mem.ImmuneError, msg.MessageError)):
        mem.vaccinate(lr, send("vaccine", vaccine_body(), who="brain-01"), 0.0)


def test_vaccine_with_invalid_fact_refused(world):
    ca_cert, send = world
    lr = ln.Learner(ca_cert, {"op-shehab"}, st.SUITE, st.INVENTORY)
    body = vaccine_body()
    body["events"][0][1]["confidence"] = "very high"
    with pytest.raises(mem.ImmuneError):
        mem.vaccinate(lr, send("vaccine", body), 0.0)


def test_duplicate_vaccine_name_refused(world):
    ca_cert, send = world
    lr = ln.Learner(ca_cert, {"op-shehab"}, st.SUITE, st.INVENTORY)
    mem.vaccinate(lr, send("vaccine", vaccine_body()), 0.0)
    with pytest.raises(mem.ImmuneError):
        mem.vaccinate(lr, send("vaccine", vaccine_body()), 1.0)
