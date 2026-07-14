import shutil
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import sentragate.auth.entra_validator as entra_validator_module
from sentragate.auth.entra_validator import AuthError, EntraIDValidator


@pytest.fixture(autouse=True)
def isolated_demo_keys(tmp_path, monkeypatch):
    """Point the demo keypair at a throwaway directory per test so tests
    never depend on or pollute a real .sentragate_demo_keys directory."""
    key_dir = tmp_path / ".sentragate_demo_keys"
    monkeypatch.setattr(entra_validator_module, "DEMO_KEY_DIR", key_dir)
    monkeypatch.setattr(
        entra_validator_module, "DEMO_PRIVATE_KEY_PATH", key_dir / "demo_private_key.pem"
    )
    monkeypatch.setattr(
        entra_validator_module, "DEMO_PUBLIC_KEY_PATH", key_dir / "demo_public_key.pem"
    )
    yield
    shutil.rmtree(key_dir, ignore_errors=True)


def make_validator():
    return EntraIDValidator(tenant_id="demo-tenant", client_id="demo-client", mode="offline")


def test_valid_token_round_trips():
    validator = make_validator()
    token = validator.mint_demo_token(
        subject="alice@example.com", groups=["employees"], risk_level="low", device_compliant=True
    )
    identity = validator.validate(f"Bearer {token}")
    assert identity.subject == "alice@example.com"
    assert identity.groups == ["employees"]
    assert identity.device_compliant is True


def test_missing_header_rejected():
    validator = make_validator()
    with pytest.raises(AuthError):
        validator.validate(None)


def test_malformed_header_rejected():
    validator = make_validator()
    with pytest.raises(AuthError):
        validator.validate("NotBearer sometoken")


def test_expired_token_rejected():
    validator = make_validator()
    token = validator.mint_demo_token(subject="bob@example.com", groups=[], ttl_seconds=-1)
    with pytest.raises(AuthError):
        validator.validate(f"Bearer {token}")


def test_tampered_token_rejected():
    validator = make_validator()
    token = validator.mint_demo_token(subject="carol@example.com", groups=["employees"])
    tampered = token[:-4] + ("A" if token[-4] != "A" else "B") + token[-3:]
    with pytest.raises(AuthError):
        validator.validate(f"Bearer {tampered}")
