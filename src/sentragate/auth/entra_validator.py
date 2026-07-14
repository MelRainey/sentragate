"""
Identity verification layer for SentraGate.

This is the front door of the gateway. Every single request is verified here
before it touches policy evaluation, guardrails, or the upstream model.
No session trust, no implicit trust from a previous successful call.
Every request proves who it is, every time. That is the Zero Trust contract.

Two modes:
  - "online":  validates real Microsoft Entra ID access tokens against the
               tenant's published JWKS (JSON Web Key Set) over OIDC.
  - "offline": generates and validates tokens against a locally held RSA
               keypair so the whole gateway can be demoed and tested without
               a live Entra ID tenant. Offline mode is clearly logged and
               should never be used in production.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEMO_KEY_DIR = Path(".sentragate_demo_keys")
DEMO_PRIVATE_KEY_PATH = DEMO_KEY_DIR / "demo_private_key.pem"
DEMO_PUBLIC_KEY_PATH = DEMO_KEY_DIR / "demo_public_key.pem"


class AuthError(Exception):
    """Raised whenever a token fails identity verification, for any reason."""


@dataclass
class Identity:
    """The verified claims we trust for the lifetime of a single request."""

    subject: str
    groups: list[str]
    risk_level: str
    device_compliant: bool
    raw_claims: dict[str, Any]


class EntraIDValidator:
    def __init__(self, tenant_id: str, client_id: str, mode: str = "offline") -> None:
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.mode = mode
        self._jwks_cache: dict[str, Any] | None = None
        self._jwks_cache_expiry: float = 0.0

        if mode == "offline":
            self._ensure_demo_keypair()

    # ---- offline demo mode -------------------------------------------------

    def _ensure_demo_keypair(self) -> None:
        DEMO_KEY_DIR.mkdir(exist_ok=True)
        if DEMO_PRIVATE_KEY_PATH.exists() and DEMO_PUBLIC_KEY_PATH.exists():
            return

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        DEMO_PRIVATE_KEY_PATH.write_bytes(private_pem)
        DEMO_PUBLIC_KEY_PATH.write_bytes(public_pem)

    def mint_demo_token(
        self,
        subject: str,
        groups: list[str],
        risk_level: str = "low",
        device_compliant: bool = True,
        ttl_seconds: int = 3600,
    ) -> str:
        """Mint a locally-signed demo access token. Offline mode only.

        This mirrors the claim shape an Entra ID access token would carry
        (sub, groups, custom risk/device signals from Conditional Access),
        so the rest of the pipeline never needs to know it isn't talking to
        a real tenant.
        """
        if self.mode != "offline":
            raise AuthError("mint_demo_token is only available in offline mode")

        private_key = DEMO_PRIVATE_KEY_PATH.read_bytes()
        now = int(time.time())
        payload = {
            "iss": f"https://sentragate.demo/{self.tenant_id}/v2.0",
            "aud": self.client_id,
            "sub": subject,
            "groups": groups,
            "risk_level": risk_level,
            "device_compliant": device_compliant,
            "iat": now,
            "exp": now + ttl_seconds,
        }
        return jwt.encode(payload, private_key, algorithm="RS256")

    def _validate_offline(self, token: str) -> dict[str, Any]:
        public_key = DEMO_PUBLIC_KEY_PATH.read_bytes()
        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"https://sentragate.demo/{self.tenant_id}/v2.0",
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("Token expired") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError(f"Token invalid: {exc}") from exc
        return claims

    # ---- online mode (real Microsoft Entra ID) ------------------------------

    def _jwks_uri(self) -> str:
        return (
            f"https://login.microsoftonline.com/{self.tenant_id}"
            "/discovery/v2.0/keys"
        )

    def _get_signing_key(self, token: str) -> Any:
        import httpx

        now = time.time()
        if self._jwks_cache is None or now > self._jwks_cache_expiry:
            resp = httpx.get(self._jwks_uri(), timeout=5.0)
            resp.raise_for_status()
            self._jwks_cache = resp.json()
            self._jwks_cache_expiry = now + 3600  # refresh JWKS hourly

        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        for key in self._jwks_cache.get("keys", []):
            if key.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key)
        raise AuthError("No matching signing key found in Entra ID JWKS")

    def _validate_online(self, token: str) -> dict[str, Any]:
        signing_key = self._get_signing_key(token)
        try:
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=f"https://login.microsoftonline.com/{self.tenant_id}/v2.0",
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("Token expired") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError(f"Token invalid: {exc}") from exc
        return claims

    # ---- public entrypoint --------------------------------------------------

    def validate(self, authorization_header: str | None) -> Identity:
        if not authorization_header or not authorization_header.startswith("Bearer "):
            raise AuthError("Missing or malformed Authorization header")

        token = authorization_header.removeprefix("Bearer ").strip()
        if not token:
            raise AuthError("Empty bearer token")

        claims = (
            self._validate_offline(token)
            if self.mode == "offline"
            else self._validate_online(token)
        )

        return Identity(
            subject=claims.get("sub", "unknown"),
            groups=claims.get("groups", []),
            risk_level=claims.get("risk_level", "unknown"),
            device_compliant=bool(claims.get("device_compliant", False)),
            raw_claims=claims,
        )
