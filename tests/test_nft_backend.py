import pytest

from arms import executor as ex
from arms import nft_backend as nb
from brain.brain import Proposal

MGMT = "192.168.109.1"
OWN = "192.168.109.133"


class FakeNft:
    def __init__(self, fail_on=None):
        self.scripts = []
        self.fail_on = fail_on

    def __call__(self, script):
        if self.fail_on and self.fail_on in script:
            raise nb.FirewallError("nft failed: No such file or directory")
        self.scripts.append(script)
        return ""


@pytest.fixture
def fake():
    return FakeNft()


@pytest.fixture
def b(fake):
    return nb.NftBackend("mcp-proxy", OWN, [MGMT], peers=["192.168.109.140"], deadman=120, runner=fake)


def test_refuses_without_management_address(fake):
    with pytest.raises(nb.FirewallError, match="management"):
        nb.NftBackend("mcp-proxy", OWN, [], runner=fake)


@pytest.mark.parametrize("bad", ["not-an-ip", "999.1.1.1", "::1"])
def test_bad_addresses_refused(fake, bad):
    with pytest.raises(nb.FirewallError):
        nb.NftBackend("mcp-proxy", bad, [MGMT], runner=fake)


@pytest.mark.parametrize("seconds", [5, 99999])
def test_deadman_must_be_bounded(fake, seconds):
    with pytest.raises(nb.FirewallError):
        nb.NftBackend("mcp-proxy", OWN, [MGMT], deadman=seconds, runner=fake)


def test_ruleset_is_atomic_and_safe(b):
    r = b.ruleset()
    assert r.startswith("add table inet coredefense\ndelete table inet coredefense\n")
    assert "elements = { 192.168.109.1, 192.168.109.140 }" in r
    # loopback and management are accepted BEFORE any drop rule, in both directions
    for chain in ("chain input", "chain output"):
        body = r.split(chain)[1].split("}")[0]
        lines = [line.strip() for line in body.splitlines() if line.strip()]
        first_drop = next(i for i, line in enumerate(lines) if "drop" in line)
        assert any("lo" in line and "accept" in line for line in lines[:first_drop])
        assert any("@allow accept" in line for line in lines[:first_drop])
    # every drop is conditional on a TIMED set (dead-man switch)
    for line in r.splitlines():
        if "drop" in line:
            assert "@iso_on" in line or "@limit_on" in line


def test_isolate_adds_timed_element(b, fake):
    b.apply("isolate", "mcp-proxy")
    assert fake.scripts[-1] == "add element inet coredefense iso_on { 192.168.109.133 timeout 120s }\n"


def test_limit_access_adds_timed_element(b, fake):
    b.apply("limit_access", "mcp-proxy")
    assert "limit_on { 192.168.109.133 timeout 120s }" in fake.scripts[-1]


@pytest.mark.parametrize("action", ["watch", "collect_evidence", "deploy_decoy"])
def test_weak_actions_change_no_firewall(b, fake, action):
    b.apply(action, "mcp-proxy")
    assert fake.scripts == []


def test_cannot_act_on_other_hosts(b):
    with pytest.raises(nb.FirewallError, match="own host"):
        b.apply("isolate", "db-01")


def test_undo_removes_element(b, fake):
    b.apply("isolate", "mcp-proxy")
    b.undo("isolate", "mcp-proxy")
    assert fake.scripts[-1] == "delete element inet coredefense iso_on { 192.168.109.133 }\n"
    assert b.active == set()


def test_undo_after_kernel_already_expired_is_fine():
    fake = FakeNft(fail_on="delete element")
    b = nb.NftBackend("mcp-proxy", OWN, [MGMT], deadman=120, runner=fake)
    b.apply("isolate", "mcp-proxy")
    b.undo("isolate", "mcp-proxy")   # must not raise
    assert b.active == set()


def test_works_inside_the_executor(b, fake):
    e = ex.Executor(backend=b)
    rec = e.apply(Proposal("isolate", "mcp-proxy", "lateral-movement-confirmed", ("host-log", "network"), 2), 0.0)
    e.revert(rec.id, 30.0)
    assert [s.split()[0] for s in fake.scripts] == ["add", "delete"]
    print("\nFIREWALL SCRIPTS SENT:\n  " + "  ".join(fake.scripts))
