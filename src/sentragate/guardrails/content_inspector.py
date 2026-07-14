"""
Content inspection guardrails for SentraGate.

Runs on every prompt before it is forwarded upstream. Catches three classes
of risk that are specific to AI workloads:

  1. Data exfiltration: PII and secrets accidentally pasted into a prompt
     (SSNs, credit card numbers, cloud credentials, private keys).
  2. Prompt injection / jailbreak attempts: known phrasing patterns used to
     override system instructions or extract the system prompt.
  3. System prompt probing: requests that explicitly ask the model to
     reveal its instructions or configuration.

This is a deliberately lightweight, explainable, regex-based first line of
defense. It is not a replacement for a dedicated LLM-based classifier in a
production deployment; see docs/THREAT_MODEL.md for that discussion.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

PII_PATTERNS: dict[str, re.Pattern] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[ -]){3}\d{4}\b|\b\d{16}\b"),
}

SECRET_PATTERNS: dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_api_key": re.compile(r"\b(?:api|secret)[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "bearer_token_leak": re.compile(r"\bBearer\s+[A-Za-z0-9\-_.]{20,}\b"),
}

INJECTION_PATTERNS: dict[str, re.Pattern] = {
    "ignore_instructions": re.compile(
        r"ignore (?:all )?(?:previous|prior|above) instructions", re.IGNORECASE
    ),
    "disregard_system_prompt": re.compile(
        r"disregard (?:the )?system prompt", re.IGNORECASE
    ),
    "reveal_system_prompt": re.compile(
        r"(reveal|show|print|repeat) (?:me )?(?:your |the )?"
        r"(system prompt|instructions|initial prompt)",
        re.IGNORECASE,
    ),
    "roleplay_override": re.compile(
        r"you are now (?:DAN|in developer mode|unrestricted|jailbroken)",
        re.IGNORECASE,
    ),
    "pretend_no_rules": re.compile(
        r"pretend (?:you have no|there are no) (?:rules|restrictions|guidelines)",
        re.IGNORECASE,
    ),
}


@dataclass
class InspectionResult:
    blocked: bool
    findings: list[str] = field(default_factory=list)
    risk_score: int = 0

    def add(self, label: str, weight: int) -> None:
        self.findings.append(label)
        self.risk_score += weight


def inspect(text: str, block_threshold: int = 5) -> InspectionResult:
    result = InspectionResult(blocked=False)

    for label, pattern in PII_PATTERNS.items():
        if pattern.search(text):
            result.add(f"pii:{label}", weight=5)

    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            result.add(f"secret:{label}", weight=5)

    for label, pattern in INJECTION_PATTERNS.items():
        if pattern.search(text):
            result.add(f"injection:{label}", weight=3)

    result.blocked = result.risk_score >= block_threshold
    return result
