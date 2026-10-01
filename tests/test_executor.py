import pytest

from arms import executor as ex
from brain.brain import ACTIONS, REASONS, Proposal


def P(action="watch", host="mcp-proxy", reason="brute-force", sources=("host-log",)):
    return Proposal(action, host, reason, sources, 1)


def ISO(host="mcp-proxy"):
    return Proposal("isolate", host, "lateral-movement-confirmed", ("host-log", "network"), 3)


@pytest.fixture
def e():
    return ex.Executor()


def test_every_reason_and_action_has_plain_language():
    assert set(ex.REASON_TEXT) == REASONS
    assert set(ex.ACTION_TEXT) == set(ACTIONS)


def test_action_is_explained_in_plain_language(e):
    rec = e.apply(ISO(), now=0.0)
    print("\n" + rec.explanation)
    assert rec.explanation == (
        "Isolating mcp-proxy because internal network movement was confirmed by another sensor. "
        "Evidence from: host logs, network traffic. Undone automatically in 10 minutes "
        "unless renewed or pinned by the operator.")
    assert rec.state == "active" and e.backend.calls == [("apply", "isolate", "mcp-proxy")]


def test_same_proposal_renews_not_duplicates(e):
    a = e.apply(P(), now=0.0)
    b = e.apply(P(), now=100.0)
    assert a.id == b.id and b.expires_at == 100.0 + ex.TTL["watch"]
    assert e.backend.calls == [("apply", "watch", "mcp-proxy")]


def test_escalation_applies_stronger_first_then_undoes_weaker(e):
    old = e.apply(P(), now=0.0)
    new = e.apply(ISO(), now=10.0)
    assert e.backend.calls == [("apply", "watch", "mcp-proxy"),
                               ("apply", "isolate", "mcp-proxy"),
                               ("undo", "watch", "mcp-proxy")]
    assert old.state == "superseded" and old.ended_by == "escalated"
    assert e.active_for("mcp-proxy") is new


def test_weaker_evidence_never_downgrades(e):
    iso = e.apply(ISO(), now=0.0)
    assert e.apply(P(), now=5.0) is iso
    assert e.backend.calls == [("apply", "isolate", "mcp-proxy")]


def test_operator_can_revert(e):
    rec = e.apply(ISO(), now=0.0)
    e.revert(rec.id, now=30.0)
    assert rec.state == "reverted" and rec.ended_by == "operator"
    assert e.backend.active == set() and e.active_for("mcp-proxy") is None


def test_actions_expire_automatically(e):
    rec = e.apply(ISO(), now=0.0)
    assert e.tick(now=599.0) == []
    assert e.tick(now=600.0) == [rec] and rec.ended_by == "expired"


def test_pinned_action_does_not_expire(e):
    rec = e.apply(ISO(), now=0.0)
    e.pin(rec.id)
    assert e.tick(now=10_000.0) == [] and rec.state == "active"


def test_fresh_evidence_extends_expiry(e):
    rec = e.apply(ISO(), now=0.0)
    e.apply(ISO(), now=500.0)
    assert e.tick(now=700.0) == []
    assert e.tick(now=1100.0) == [rec]


def test_cannot_revert_twice_or_unknown(e):
    rec = e.apply(P(), now=0.0)
    e.revert(rec.id, now=1.0)
    with pytest.raises(ex.ExecutorError):
        e.revert(rec.id, now=2.0)
    with pytest.raises(ex.ExecutorError):
        e.revert("does-not-exist")


def test_only_validated_proposals_execute(e):
    with pytest.raises(ex.ExecutorError):
        e.apply({"action": "isolate", "host": "mcp-proxy"})


@pytest.mark.parametrize("action", ACTIONS)
def test_every_action_is_fully_reversible(e, action):
    sources = ("host-log", "network") if action == "isolate" else ("host-log",)
    rec = e.apply(P(action, sources=sources), now=0.0)
    e.revert(rec.id, now=1.0)
    assert e.backend.active == set()


def test_hosts_are_independent(e):
    e.apply(ISO("mcp-proxy"), now=0.0)
    other = e.apply(P(host="lab-vm-1"), now=1.0)
    assert e.active_for("mcp-proxy").action == "isolate" and other.action == "watch"
