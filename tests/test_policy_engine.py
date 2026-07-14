import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sentragate.policy.engine import PolicyEngine, RequestContext

POLICIES = [
    {
        "name": "block-high-risk",
        "effect": "deny",
        "when": {"risk_level": ["high"]},
    },
    {
        "name": "block-noncompliant-frontier",
        "effect": "deny",
        "when": {"model": ["gpt-4o"], "device_compliant": [False]},
    },
    {
        "name": "allow-employees",
        "effect": "allow",
        "when": {"groups": ["employees"], "model": ["gpt-4o", "gpt-3.5-turbo"]},
    },
    {
        "name": "allow-interns-sandbox",
        "effect": "allow",
        "when": {"groups": ["interns"], "model": ["gpt-3.5-sandbox"]},
    },
]


def make_context(**overrides):
    base = dict(
        subject="user@example.com",
        groups=["employees"],
        risk_level="low",
        device_compliant=True,
        model="gpt-4o",
    )
    base.update(overrides)
    return RequestContext(**base)


def test_default_deny_when_nothing_matches():
    engine = PolicyEngine(POLICIES)
    ctx = make_context(groups=["unknown-group"], model="unknown-model")
    decision = engine.evaluate(ctx)
    assert decision.allowed is False
    assert decision.matched_policy == "__default_deny__"


def test_allow_matches_correct_policy():
    engine = PolicyEngine(POLICIES)
    ctx = make_context()
    decision = engine.evaluate(ctx)
    assert decision.allowed is True
    assert decision.matched_policy == "allow-employees"


def test_high_risk_deny_overrides_allow():
    engine = PolicyEngine(POLICIES)
    ctx = make_context(risk_level="high")
    decision = engine.evaluate(ctx)
    assert decision.allowed is False
    assert decision.matched_policy == "block-high-risk"


def test_noncompliant_device_blocks_frontier_model():
    engine = PolicyEngine(POLICIES)
    ctx = make_context(device_compliant=False)
    decision = engine.evaluate(ctx)
    assert decision.allowed is False
    assert decision.matched_policy == "block-noncompliant-frontier"


def test_intern_sandbox_allowed():
    engine = PolicyEngine(POLICIES)
    ctx = make_context(groups=["interns"], model="gpt-3.5-sandbox")
    decision = engine.evaluate(ctx)
    assert decision.allowed is True
    assert decision.matched_policy == "allow-interns-sandbox"


def test_intern_cannot_reach_frontier_model():
    engine = PolicyEngine(POLICIES)
    ctx = make_context(groups=["interns"], model="gpt-4o")
    decision = engine.evaluate(ctx)
    assert decision.allowed is False
