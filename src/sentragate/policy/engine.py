"""
Policy engine for SentraGate.

Modeled on Microsoft Entra ID Conditional Access: a request context (who,
what device posture, what risk level, what model they are asking for) is
evaluated against an ordered list of policies. Deny always wins over allow
when both match, and the default when nothing matches is deny.

Zero Trust principle in code: access is denied by default and only granted
by an explicit, auditable rule. There is no implicit allow path.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RequestContext:
    subject: str
    groups: list[str]
    risk_level: str
    device_compliant: bool
    model: str


@dataclass
class PolicyDecision:
    allowed: bool
    matched_policy: str
    reason: str


def _condition_matches(condition: dict[str, Any], context: RequestContext) -> bool:
    """A condition matches if every key in 'when' matches the context.

    List-valued fields (groups) match if there is any overlap.
    Scalar-valued fields (risk_level, device_compliant, model) match if the
    context value is present in the allowed list for that field.
    """
    ctx_map: dict[str, Any] = {
        "groups": context.groups,
        "risk_level": context.risk_level,
        "device_compliant": context.device_compliant,
        "model": context.model,
        "subject": context.subject,
    }

    for field, allowed_values in condition.items():
        if field not in ctx_map:
            return False
        ctx_value = ctx_map[field]

        if isinstance(ctx_value, list):
            if not set(ctx_value) & set(allowed_values):
                return False
        else:
            if ctx_value not in allowed_values:
                return False

    return True


class PolicyEngine:
    def __init__(self, policies: list[dict[str, Any]]) -> None:
        self.policies = policies

    def evaluate(self, context: RequestContext) -> PolicyDecision:
        # Deny rules are evaluated first and win outright. In Zero Trust
        # architectures an explicit deny always overrides an explicit allow.
        deny_rules = [p for p in self.policies if p["effect"] == "deny"]
        allow_rules = [p for p in self.policies if p["effect"] == "allow"]

        for rule in deny_rules:
            if _condition_matches(rule.get("when", {}), context):
                return PolicyDecision(
                    allowed=False,
                    matched_policy=rule["name"],
                    reason=f"Denied by policy '{rule['name']}'",
                )

        for rule in allow_rules:
            if _condition_matches(rule.get("when", {}), context):
                return PolicyDecision(
                    allowed=True,
                    matched_policy=rule["name"],
                    reason=f"Allowed by policy '{rule['name']}'",
                )

        # Default deny. No matching rule means no established trust.
        return PolicyDecision(
            allowed=False,
            matched_policy="__default_deny__",
            reason="No policy matched; default deny under Zero Trust posture",
        )
