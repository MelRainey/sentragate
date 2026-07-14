"""
Audit logging for SentraGate.

Every decision the gateway makes (allow, deny, guardrail block, rate limit)
is written as a structured JSON line. This is the evidence trail a Director
or auditor asks for after an incident: who asked for what, what identity
signals they presented, what policy fired, and what happened next.

Append-only by design. Nothing in this module ever reads back and rewrites
a prior entry, which keeps the log honest even if a bug elsewhere in the
gateway tries to get clever.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AuditEvent:
    request_id: str
    timestamp: float
    subject: str
    groups: list[str]
    risk_level: str
    device_compliant: bool
    model_requested: str | None
    decision: str  # "allow" | "deny" | "blocked_content" | "rate_limited" | "auth_failed"
    matched_policy: str | None
    guardrail_findings: list[str] = field(default_factory=list)
    guardrail_risk_score: int = 0
    reason: str = ""
    source_ip: str | None = None


class AuditLogger:
    def __init__(self, log_path: str) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: AuditEvent) -> None:
        line = json.dumps(asdict(event), separators=(",", ":"))
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()

    @staticmethod
    def new_request_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def now() -> float:
        return time.time()
