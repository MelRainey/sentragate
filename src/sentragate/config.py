"""
Configuration loader for SentraGate.

Loads Zero Trust policy definitions and runtime settings from YAML and
environment variables. Fails closed: if the policy file is missing or
malformed, the gateway refuses to start rather than run with an undefined
security posture.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or unsafe."""


@dataclass
class GatewaySettings:
    tenant_id: str
    client_id: str
    auth_mode: str  # "online" (real Entra ID) or "offline" (local demo keypair)
    upstream_url: str | None
    upstream_api_key: str | None
    rate_limit_per_minute: int
    audit_log_path: str
    policy_path: str


def load_policies(policy_path: str) -> list[dict[str, Any]]:
    path = Path(policy_path)
    if not path.exists():
        raise ConfigError(f"Policy file not found: {policy_path}")

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not data or "policies" not in data:
        raise ConfigError("Policy file must define a top-level 'policies' list")

    policies = data["policies"]
    if not isinstance(policies, list) or len(policies) == 0:
        raise ConfigError("'policies' must be a non-empty list")

    for i, p in enumerate(policies):
        if "name" not in p or "effect" not in p:
            raise ConfigError(f"Policy at index {i} missing required 'name' or 'effect'")
        if p["effect"] not in ("allow", "deny"):
            raise ConfigError(f"Policy '{p.get('name')}' has invalid effect: {p['effect']}")

    return policies


def load_settings() -> GatewaySettings:
    """Load runtime settings from environment variables with safe defaults.

    Zero Trust default: auth_mode defaults to 'offline' (demo) rather than
    silently trusting a misconfigured production Entra ID tenant.
    """
    return GatewaySettings(
        tenant_id=os.getenv("SENTRAGATE_TENANT_ID", "demo-tenant"),
        client_id=os.getenv("SENTRAGATE_CLIENT_ID", "demo-client"),
        auth_mode=os.getenv("SENTRAGATE_AUTH_MODE", "offline"),
        upstream_url=os.getenv("SENTRAGATE_UPSTREAM_URL"),
        upstream_api_key=os.getenv("SENTRAGATE_UPSTREAM_API_KEY"),
        rate_limit_per_minute=int(os.getenv("SENTRAGATE_RATE_LIMIT", "30")),
        audit_log_path=os.getenv("SENTRAGATE_AUDIT_LOG", "audit_trail.jsonl"),
        policy_path=os.getenv("SENTRAGATE_POLICY_PATH", "config/policies.yaml"),
    )
