import pytest

from arms import executor as ex
from arms import host_sensors as hs
from barrier import barrier as br
from brain import brain as bn
from test_barrier import INV, PFX, SALT

HOST = "web-01"


@pytest.fixture
def brain():
    return bn.Brain(INV | {HOST})


@pytest.fixture
def proc():
    return hs.ProcessArm(SALT, HOST)


@pytest.fixture
def files():
    return hs.FileArm(SALT, HOST)


def acts(props):
    return [(p.action, p.reason) for p in props]


# ---------------- admin group changes (host logs) ----------------

@pytest.mark.parametrize("line,group", [
    (f"{PFX} usermod[50]: add 'bob' to group 'sudo'", "sudo"),
    (f"{PFX} usermod[50]: add 'bob' to shadow group 'docker'", "docker"),
    (f"{PFX} gpasswd[51]: user bob added by root to group wheel", "wheel"),
    (f"{PFX} usermod[50]: add 'bob' to group 'video'", "other"),
], ids=["sudo", "shadow-docker", "gpasswd-wheel", "harmless-group"])
def test_group_changes_parsed(line, group):
    f = br.Barrier(SALT, INV).process_line(line)[0]
    assert f["kind"] == "group_added" and f["group"] == group and f["user"].startswith("user-")


def test_admin_group_is_damage_harmless_group_is_not():
    b = br.Barrier(SALT, INV)
    brain = bn.Brain(INV)
    admin = brain.ingest(b.process_line(f"{PFX} usermod[50]: add 'bob' to group 'sudo'")[0], 1.0)
    other = brain.ingest(b.process_line(f"{PFX} usermod[50]: add 'bob' to group 'video'")[0], 2.0)
    assert acts(admin) == [("limit_access", "privilege-granted")] and other == []


# ---------------- process sensor ----------------

def test_process_event_converted(proc):
    f = proc.to_fact({"parent": "/usr/sbin/nginx", "child": "/bin/sh", "user": "www-data"})
    assert f == {"kind": "process_spawn", "host": HOST, "parent": "nginx", "child": "sh", "user": "www-data"}


def test_unknown_or_hostile_names_pseudonymized(proc):
    f = proc.to_fact({"parent": "/opt/app/ignore_previous_instructions", "child": "/tmp/.x", "user": "alice"})
    assert all(f[k].startswith(p) for k, p in [("parent", "proc-"), ("child", "proc-"), ("user", "user-")])


@pytest.mark.parametrize("bad", [
    {"parent": "nginx", "child": "sh"},
    {"parent": "nginx", "child": 5, "user": "root"},
    {"parent": "", "child": "sh", "user": "root"},
    "nginx->sh",
], ids=["missing-user", "child-not-text", "empty-parent", "not-an-object"])
def test_malformed_process_events_rejected(proc, bad):
    assert proc.to_fact(bad) is None and proc.rejected == 1


def test_server_spawning_shell_is_damage(proc, brain):
    f = proc.to_fact({"parent": "nginx", "child": "bash", "user": "www-data"})
    props = brain.ingest(f, 1.0)
    assert acts(props) == [("limit_access", "service-spawned-shell")]
    assert props[0].body()["sources"] == ["process"]


BENIGN_SPAWNS = [("sshd", "bash", "ubuntu"), ("cron", "sh", "root"), ("nginx", "nginx", "www-data"),
                 ("systemd", "nginx", "root"), ("bash", "ls", "ubuntu"), ("sudo", "apt", "root")]


@pytest.mark.parametrize("parent,child,user", BENIGN_SPAWNS, ids=[f"{p}->{c}" for p, c, _ in BENIGN_SPAWNS])
def test_normal_process_activity_is_not_damage(proc, brain, parent, child, user):
    assert brain.ingest(proc.to_fact({"parent": parent, "child": child, "user": user}), 1.0) == []


# ---------------- file sensor ----------------

def test_file_event_converted(files):
    assert files.to_fact({"modified": 340, "renamed": 120, "window": 60}) == {
        "kind": "file_burst", "host": HOST, "modified": 340, "renamed": 120, "window": 60}


@pytest.mark.parametrize("bad", [
    {"modified": -1, "renamed": 0, "window": 60},
    {"modified": True, "renamed": 0, "window": 60},
    {"modified": "lots", "renamed": 0, "window": 60},
    {"modified": 5, "renamed": 0, "window": 0},
], ids=["negative", "bool", "text", "zero-window"])
def test_malformed_file_events_rejected(files, bad):
    assert files.to_fact(bad) is None and files.rejected == 1


@pytest.mark.parametrize("ev,expected", [
    ({"modified": 340, "renamed": 0, "window": 60}, [("limit_access", "mass-file-change")]),
    ({"modified": 10, "renamed": 80, "window": 60}, [("limit_access", "mass-file-change")]),
    ({"modified": 10, "renamed": 2, "window": 60}, []),
    ({"modified": 300, "renamed": 0, "window": 3600}, []),
], ids=["many-modified", "many-renamed", "normal-work", "slow-over-an-hour"])
def test_mass_file_change_rules(files, brain, ev, expected):
    assert acts(brain.ingest(files.to_fact(ev), 1.0)) == expected


# ---------------- the zero-day story ----------------

def test_zero_day_caught_by_damage_alone(proc, files, brain):
    """No brute force, no CVE, no signature: an unknown exploit is caught by what it DOES."""
    story = []
    story += brain.ingest(proc.to_fact({"parent": "/usr/sbin/nginx", "child": "/bin/sh", "user": "www-data"}), 10.0)
    story += brain.ingest(files.to_fact({"modified": 850, "renamed": 400, "window": 45}), 40.0)
    print("\nZERO-DAY STORY (no signature, no CVE):")
    for p in story:
        print(f"  {p.action:<13} {p.reason:<22} sensors={p.body()['sources']}")
    print("  " + ex.explain(story[-1]))
    assert acts(story) == [("limit_access", "service-spawned-shell"), ("isolate", "mass-file-change")]
    assert story[-1].body()["sources"] == ["file", "process"]
