import json

import pytest

from arms import executor as ex
from arms import nft_backend as nb
from brain.brain import Proposal
from service import arm as sv
from test_service import PFX, append, make_world, sign

OWN = "192.168.109.133"
MGMT = "192.168.109.1"


class FakeNft:
    def __init__(self, fail_on=None):
        self.scripts = []
        self.fail_on = fail_on

    def __call__(self, script):
        if self.fail_on and self.fail_on in script:
            raise nb.FirewallError("nft failed: No such file or directory")
        self.scripts.append(script)
        return ""


def fw_cfg(enabled=True, management=(MGMT,)):
    return {"enabled": enabled, "own_ip": OWN, "management": list(management), "deadman": 180}


# ---------------- renewal refreshes the kernel timer ----------------

def test_renew_restarts_kernel_timer():
    fake = FakeNft()
    b = nb.NftBackend("mcp-proxy", OWN, [MGMT], deadman=120, runner=fake)
    b.apply("isolate", "mcp-proxy")
    b.renew("isolate", "mcp-proxy")
    assert fake.scripts[-1] == ("delete element inet coredefense iso_on { 192.168.109.133 }\n"
                                "add element inet coredefense iso_on { 192.168.109.133 timeout 120s }\n")


def test_renew_after_kernel_expiry_re_adds():
    fake = FakeNft(fail_on="delete element")
    b = nb.NftBackend("mcp-proxy", OWN, [MGMT], deadman=120, runner=fake)
    b.renew("isolate", "mcp-proxy")
    assert fake.scripts[-1] == "add element inet coredefense iso_on { 192.168.109.133 timeout 120s }\n"


def test_executor_renewal_calls_backend_renew():
    fake = FakeNft()
    b = nb.NftBackend("mcp-proxy", OWN, [MGMT], deadman=120, runner=fake)
    e = ex.Executor(backend=b)
    p = Proposal("isolate", "mcp-proxy", "lateral-movement-confirmed", ("host-log", "network"), 2)
    e.apply(p, 0.0)
    e.apply(p, 60.0)
    assert [c[0] for c in b.calls] == ["apply", "renew"]


# ---------------- config ----------------

def test_firewall_config_loads(tmp_path):
    cfg, *_ = make_world(tmp_path)
    cfg["firewall"] = fw_cfg()
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    assert sv.load_config(p)["firewall"]["enabled"] is True


@pytest.mark.parametrize("fw", [fw_cfg(management=()), {"enabled": True}, {**fw_cfg(), "extra": 1}],
                         ids=["no-management", "missing-fields", "extra-field"])
def test_bad_firewall_config_refused(tmp_path, fw):
    cfg, *_ = make_world(tmp_path)
    cfg["firewall"] = fw
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(sv.ServiceError):
        sv.load_config(p)


def test_unknown_config_field_refused(tmp_path):
    cfg, *_ = make_world(tmp_path)
    cfg["backdoor"] = True
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    with pytest.raises(sv.ServiceError):
        sv.load_config(p)


def test_dry_run_is_the_default(tmp_path):
    cfg, *_ = make_world(tmp_path)
    assert isinstance(sv.ArmService(cfg, now=0.0).backend, ex.DryRunBackend)


# ---------------- the full chain, with a fake kernel ----------------

def test_full_chain_gate_refuses_then_isolates(tmp_path):
    cfg, sec, log = make_world(tmp_path)
    fake = FakeNft()
    backend = nb.NftBackend("mcp-proxy", OWN, [MGMT], deadman=180, runner=fake)
    svc = sv.ArmService(cfg, now=0.0, backend=backend)
    iso = {"action": "isolate", "host": "mcp-proxy", "reason": "known-attacker",
           "sources": ["host-log", "memory"], "evidence": 3}

    append(log, *[f"{PFX} sshd[1]: Failed password for root from 6.6.6.9 port 5100{i} ssh2" for i in range(5)])
    svc.poll_logs(1.0)
    first = svc.handle_raw(sign(sec, "brain-01", "brain", "proposal", iso), 2.0)

    svc.handle_raw(sign(sec, "op-shehab", "operator", "memory",
                        {"incident": "inc-live", "addresses": ["6.6.6.9"], "days": 1}), 3.0)
    append(log, f"{PFX} sshd[1]: Failed password for root from 6.6.6.9 port 51099 ssh2")
    svc.poll_logs(4.0)
    second = svc.handle_raw(sign(sec, "brain-01", "brain", "proposal", iso), 5.0)

    print(f"\nFULL CHAIN: first isolate -> {first}; after operator memory -> {second}")
    print(f"  kernel command: {fake.scripts[-1].strip()}")
    assert first == "not-corroborated" and second == "accepted"
    assert fake.scripts[-1] == "add element inet coredefense iso_on { 192.168.109.133 timeout 180s }\n"
