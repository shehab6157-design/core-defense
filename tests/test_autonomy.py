import pytest

from arms import executor as ex
from arms import safety as sf
from brain.brain import Proposal
from learning import autonomy as au
from ring import identity as idn
from ring import message as msg

PROTECTED = {"db-01", "db-02", "db-03", "db-04"}


@pytest.fixture
def world(tmp_path):
    ca_key, ca_cert = idn.create_ca(tmp_path)
    ids = {n: idn.issue(ca_key, ca_cert, n, r) for n, r in [
        ("op-shehab", "operator"), ("brain-01", "brain")]}
    auto = au.Autonomy(ca_cert, {"op-shehab"})
    safe = sf.SafeExecutor(ex.Executor(), ca_cert, {"op-shehab"}, protected_hosts=PROTECTED, max_strong=3)
    safe.autonomy = auto
    counter = {"n": 0}

    def verdict(action, result, who="op-shehab", action_id=None):
        counter["n"] += 1
        role = "operator" if who == "op-shehab" else "brain"
        k, c = ids[who]
        body = {"action": action, "action_id": action_id or f"{counter['n']:012x}", "verdict": result}
        return msg.sign("verdict", body, who, role, k, c)

    def judge(action, results):
        for i, r in enumerate(results):
            auto.handle_operator(verdict(action, r), float(i))
    return auto, safe, verdict, judge


def LIMIT(host="db-01"):
    return Proposal("limit_access", host, "login-after-brute-force", ("host-log",), 1)


def ISO(host="db-01"):
    return Proposal("isolate", host, "lateral-movement-confirmed", ("host-log", "network"), 2)


def held(r):
    return isinstance(r, sf.PendingApproval)


def test_starts_manual(world):
    auto, safe, *_ = world
    assert not auto.allows("limit_access") and held(safe.apply(LIMIT(), 0.0))


def test_nineteen_correct_is_not_enough(world):
    auto, safe, _, judge = world
    judge("limit_access", ["correct"] * 19)
    assert not auto.allows("limit_access")


def test_twenty_correct_earns_autonomy(world):
    auto, safe, _, judge = world
    judge("limit_access", ["correct"] * 20)
    assert auto.allows("limit_access")
    assert isinstance(safe.apply(LIMIT(), 100.0), ex.ActionRecord)   # runs without waiting


def test_isolate_never_autonomous_on_protected_hosts(world):
    auto, safe, _, judge = world
    judge("isolate", ["correct"] * 50)
    assert not auto.allows("isolate") and held(safe.apply(ISO(), 100.0))


def test_one_wrong_revokes_instantly(world):
    auto, safe, _, judge = world
    judge("limit_access", ["correct"] * 20)
    judge("limit_access", ["wrong"])
    assert not auto.allows("limit_access") and held(safe.apply(LIMIT(), 100.0))


def test_autonomy_returns_after_ten_clean_verdicts(world):
    auto, _, _, judge = world
    judge("limit_access", ["correct"] * 20 + ["wrong"] + ["correct"] * 9)
    assert not auto.allows("limit_access")
    judge("limit_access", ["correct"])
    assert auto.allows("limit_access")


def test_wrong_verdicts_cost_more_than_correct_ones_earn(world):
    auto, _, _, judge = world
    judge("limit_access", ["wrong", "wrong"] + ["correct"] * 20)
    assert not auto.allows("limit_access")          # 20 - 2x5 = 10 < 15
    judge("limit_access", ["correct"] * 5)
    assert auto.allows("limit_access")              # 25 - 10 = 15


def test_breaker_still_applies_when_autonomous(world):
    auto, safe, _, judge = world
    judge("limit_access", ["correct"] * 20)
    results = [safe.apply(LIMIT(h), float(i)) for i, h in enumerate(sorted(PROTECTED))]
    assert [held(r) for r in results] == [False, False, False, True]
    assert results[3].why == "rate-limit"


def test_only_operator_can_give_verdicts(world):
    auto, _, verdict, _ = world
    with pytest.raises(au.AutonomyError):
        auto.handle_operator(verdict("limit_access", "correct", who="brain-01"), 0.0)


def test_each_action_judged_once(world):
    auto, _, verdict, _ = world
    auto.handle_operator(verdict("limit_access", "correct", action_id="0" * 12), 0.0)
    with pytest.raises(au.AutonomyError):
        auto.handle_operator(verdict("limit_access", "correct", action_id="0" * 12), 1.0)


@pytest.mark.parametrize("action,result", [("watch", "correct"), ("limit_access", "great")],
                         ids=["unjudged-action", "bad-verdict"])
def test_bad_verdicts_refused(world, action, result):
    auto, _, verdict, _ = world
    with pytest.raises(au.AutonomyError):
        auto.handle_operator(verdict(action, result), 0.0)


def test_earned_autonomy_summary(world):
    auto, safe, _, judge = world
    judge("limit_access", ["correct"] * 20)
    granted = auto.allows("limit_access")
    judge("isolate", ["correct"] * 50)
    judge("limit_access", ["wrong"])
    revoked = not auto.allows("limit_access")
    judge("limit_access", ["correct"] * 10)
    print("\nEARNED AUTONOMY:")
    print(f"  limit_access: earned after 20 correct -> {granted}; one wrong -> revoked: {revoked}; "
          f"10 clean later -> regained: {auto.allows('limit_access')}")
    print(f"  isolate after 50 correct verdicts -> autonomous: {auto.allows('isolate')} (hard limit)")
    print(f"  history: {[(a, e) for _, a, e in auto.log]}")
    assert granted and revoked and auto.allows("limit_access") and not auto.allows("isolate")
