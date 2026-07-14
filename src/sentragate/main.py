"""
SentraGate: a Zero Trust gateway for AI workloads.

Request flow, every single time, no shortcuts:
  1. Verify identity (Microsoft Entra ID token, online or offline demo mode).
  2. Evaluate Conditional-Access-style policy against the verified claims.
  3. Enforce per-identity rate limits.
  4. Run content guardrails on the prompt (PII, secrets, prompt injection).
  5. Forward to the upstream model only if every prior gate passed.
  6. Write an audit event for the decision, regardless of outcome.

Never trust, always verify. Default deny. Least privilege. That is the
whole design in one sentence, the rest is implementation detail.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from sentragate.audit.logger import AuditEvent, AuditLogger
from sentragate.auth.entra_validator import AuthError, EntraIDValidator
from sentragate.config import load_policies, load_settings
from sentragate.guardrails.content_inspector import inspect
from sentragate.middleware.rate_limiter import RateLimiter
from sentragate.policy.engine import PolicyEngine, RequestContext
from sentragate.proxy.llm_client import UpstreamError, forward_to_llm

settings = load_settings()
policies = load_policies(settings.policy_path)

validator = EntraIDValidator(
    tenant_id=settings.tenant_id, client_id=settings.client_id, mode=settings.auth_mode
)
policy_engine = PolicyEngine(policies)
rate_limiter = RateLimiter(limit_per_minute=settings.rate_limit_per_minute)
audit_logger = AuditLogger(log_path=settings.audit_log_path)

app = FastAPI(
    title="SentraGate",
    description="Zero Trust gateway for AI workloads, built on Entra ID identity verification.",
    version="0.1.0",
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "auth_mode": settings.auth_mode}


@app.get("/v1/policies")
async def list_policies(request: Request) -> Any:
    """Admin introspection endpoint. Requires the 'security-admins' group."""
    try:
        identity = validator.validate(request.headers.get("authorization"))
    except AuthError as exc:
        return JSONResponse(status_code=401, content={"error": str(exc)})

    if "security-admins" not in identity.groups:
        return JSONResponse(status_code=403, content={"error": "Insufficient privilege"})

    return {"policies": policies}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Any:
    request_id = AuditLogger.new_request_id()
    body = await request.json()
    model = body.get("model", "unknown")
    messages = body.get("messages", [])
    prompt_text = "\n".join(m.get("content", "") for m in messages if isinstance(m, dict))
    source_ip = request.client.host if request.client else None

    # 1. Identity verification. No identity, no access, full stop.
    try:
        identity = validator.validate(request.headers.get("authorization"))
    except AuthError as exc:
        audit_logger.record(
            AuditEvent(
                request_id=request_id,
                timestamp=AuditLogger.now(),
                subject="unauthenticated",
                groups=[],
                risk_level="unknown",
                device_compliant=False,
                model_requested=model,
                decision="auth_failed",
                matched_policy=None,
                reason=str(exc),
                source_ip=source_ip,
            )
        )
        return JSONResponse(status_code=401, content={"error": f"Authentication failed: {exc}"})

    # 2. Policy evaluation against verified claims.
    context = RequestContext(
        subject=identity.subject,
        groups=identity.groups,
        risk_level=identity.risk_level,
        device_compliant=identity.device_compliant,
        model=model,
    )
    decision = policy_engine.evaluate(context)

    if not decision.allowed:
        audit_logger.record(
            AuditEvent(
                request_id=request_id,
                timestamp=AuditLogger.now(),
                subject=identity.subject,
                groups=identity.groups,
                risk_level=identity.risk_level,
                device_compliant=identity.device_compliant,
                model_requested=model,
                decision="deny",
                matched_policy=decision.matched_policy,
                reason=decision.reason,
                source_ip=source_ip,
            )
        )
        return JSONResponse(status_code=403, content={"error": decision.reason})

    # 3. Rate limiting, scoped to the verified identity.
    if not rate_limiter.allow(identity.subject):
        audit_logger.record(
            AuditEvent(
                request_id=request_id,
                timestamp=AuditLogger.now(),
                subject=identity.subject,
                groups=identity.groups,
                risk_level=identity.risk_level,
                device_compliant=identity.device_compliant,
                model_requested=model,
                decision="rate_limited",
                matched_policy=decision.matched_policy,
                reason="Rate limit exceeded for this identity",
                source_ip=source_ip,
            )
        )
        return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})

    # 4. Content guardrails on the prompt itself.
    inspection = inspect(prompt_text)
    if inspection.blocked:
        audit_logger.record(
            AuditEvent(
                request_id=request_id,
                timestamp=AuditLogger.now(),
                subject=identity.subject,
                groups=identity.groups,
                risk_level=identity.risk_level,
                device_compliant=identity.device_compliant,
                model_requested=model,
                decision="blocked_content",
                matched_policy=decision.matched_policy,
                guardrail_findings=inspection.findings,
                guardrail_risk_score=inspection.risk_score,
                reason="Prompt blocked by content guardrails",
                source_ip=source_ip,
            )
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": "Prompt blocked by content guardrails",
                "findings": inspection.findings,
            },
        )

    # 5. Forward to the upstream model.
    try:
        response = await forward_to_llm(
            payload=body,
            upstream_url=settings.upstream_url,
            api_key=settings.upstream_api_key,
        )
    except UpstreamError as exc:
        audit_logger.record(
            AuditEvent(
                request_id=request_id,
                timestamp=AuditLogger.now(),
                subject=identity.subject,
                groups=identity.groups,
                risk_level=identity.risk_level,
                device_compliant=identity.device_compliant,
                model_requested=model,
                decision="upstream_error",
                matched_policy=decision.matched_policy,
                reason=str(exc),
                source_ip=source_ip,
            )
        )
        return JSONResponse(status_code=502, content={"error": "Upstream service unavailable"})

    # 6. Success. Audit the allow, including guardrail telemetry.
    audit_logger.record(
        AuditEvent(
            request_id=request_id,
            timestamp=AuditLogger.now(),
            subject=identity.subject,
            groups=identity.groups,
            risk_level=identity.risk_level,
            device_compliant=identity.device_compliant,
            model_requested=model,
            decision="allow",
            matched_policy=decision.matched_policy,
            guardrail_findings=inspection.findings,
            guardrail_risk_score=inspection.risk_score,
            reason=decision.reason,
            source_ip=source_ip,
        )
    )
    return response
