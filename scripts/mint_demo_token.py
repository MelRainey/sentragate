#!/usr/bin/env python3
"""
Mint a demo access token for local testing against SentraGate in offline
auth mode. This never touches a real Entra ID tenant; it signs a token with
a locally generated RSA keypair the gateway also trusts in offline mode.

Usage:
    python scripts/mint_demo_token.py --subject alice@example.com \
        --groups employees --risk-level low --device-compliant

    python scripts/mint_demo_token.py --subject intern@example.com \
        --groups interns --risk-level low --device-compliant
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sentragate.auth.entra_validator import EntraIDValidator
from sentragate.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Mint a SentraGate demo access token")
    parser.add_argument("--subject", required=True, help="Subject identifier, e.g. an email")
    parser.add_argument("--groups", nargs="*", default=["employees"], help="Group memberships")
    parser.add_argument(
        "--risk-level", default="low", choices=["low", "medium", "high"], help="Simulated risk signal"
    )
    parser.add_argument(
        "--device-compliant", action="store_true", help="Simulate a compliant managed device"
    )
    args = parser.parse_args()

    settings = load_settings()
    validator = EntraIDValidator(
        tenant_id=settings.tenant_id, client_id=settings.client_id, mode="offline"
    )
    token = validator.mint_demo_token(
        subject=args.subject,
        groups=args.groups,
        risk_level=args.risk_level,
        device_compliant=args.device_compliant,
    )
    print(token)


if __name__ == "__main__":
    main()
