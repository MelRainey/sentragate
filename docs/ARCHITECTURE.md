# Architecture

## Design principle

**Never trust, always verify.** Every request to `/v1/chat/completions` runs through the same five gates in the same order, regardless of who is calling or what they asked for last time. There is no cached trust and no fast path around any gate.

## Request lifecycle

```
Client request
     │
     ▼
┌─────────────────────────┐
│ 1. Identity verification │  EntraIDValidator.validate()
│    Bearer token → claims │  - offline: local RSA keypair, demo tokens
└─────────────────────────┘  - online: Entra ID JWKS, RS256, iss/aud/exp checked
     │ fail → 401, audit "auth_failed"
     ▼
┌─────────────────────────┐
│ 2. Policy evaluation      │  PolicyEngine.evaluate()
│    Conditional Access      │  - deny rules checked first, always win
│    style YAML rules          │  - allow rules checked second
└─────────────────────────┘  - default deny if nothing matches
     │ fail → 403, audit "deny"
     ▼
┌─────────────────────────┐
│ 3. Rate limiting          │  RateLimiter.allow()
│    scoped to verified sub  │  - in-memory sliding window, per identity
└─────────────────────────┘
     │ fail → 429, audit "rate_limited"
     ▼
┌─────────────────────────┐
│ 4. Content guardrails     │  content_inspector.inspect()
│    PII / secrets / injection │ - weighted regex findings
└─────────────────────────┘  - blocks above configurable threshold
     │ fail → 400, audit "blocked_content"
     ▼
┌─────────────────────────┐
│ 5. Upstream forward        │  llm_client.forward_to_llm()
│    OpenAI-compatible call   │  - real upstream, or canned demo response
└─────────────────────────┘
     │
     ▼
Audit "allow" event written regardless of outcome above (except the
request never reaches this point unless every gate passed)
```

## Why this ordering

Identity is verified before anything else because every later decision depends on knowing who is asking. Policy is evaluated before rate limiting and guardrails because there is no reason to spend CPU cycles inspecting the content of a request that should never have been allowed to reach the model in the first place. Rate limiting sits before content inspection for the same reason: cheap checks before expensive ones, once identity and authorization are settled.

## Component map

| Component | File | Responsibility |
|---|---|---|
| **Identity verification** | `src/sentragate/auth/entra_validator.py` | Validates Entra ID (or offline demo) bearer tokens, returns a verified `Identity` |
| **Policy engine** | `src/sentragate/policy/engine.py` | Evaluates request context against YAML Conditional Access-style rules |
| **Content guardrails** | `src/sentragate/guardrails/content_inspector.py` | Regex-based detection of PII, secrets, and prompt injection phrasing |
| **Rate limiter** | `src/sentragate/middleware/rate_limiter.py` | Per-identity sliding window request limiting |
| **Audit logger** | `src/sentragate/audit/logger.py` | Structured, append-only JSONL logging of every decision |
| **Upstream proxy** | `src/sentragate/proxy/llm_client.py` | Forwards allowed requests to the real model provider, or returns a demo response |
| **Application wiring** | `src/sentragate/main.py` | FastAPI routes, ties every component together in the fixed gate order |

## Deployment topology (production direction, not yet implemented)

The current build is a single-process reference implementation, intentionally. A production rollout would sit SentraGate behind a load balancer, front multiple stateless gateway instances, and move the rate limiter and any shared caches (JWKS cache, policy cache) to Redis so horizontal scaling does not break per-identity limits. This is called out explicitly rather than silently assumed, because pretending a demo project is production-hardened is how real incidents happen.

## Configuration surface

All runtime configuration is environment-variable driven (`src/sentragate/config.py`), with policy definitions kept separately in YAML (`config/policies.yaml`) so security policy can be reviewed, diffed, and approved independently of application code changes. That separation is deliberate: a policy change should never require a code deploy, and a code deploy should never silently change security policy.
