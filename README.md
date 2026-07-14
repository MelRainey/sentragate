# SentraGate

**Zero Trust gateway for AI workloads, built on Microsoft Entra ID identity verification.**

Every request to an LLM gets verified, scoped, inspected, and logged before it reaches the model. No implicit trust, no session carryover, no "it worked last time so it's probably fine." That is the entire pitch.

## The problem this solves

Most internal "AI gateways" are a reverse proxy with an API key bolted on. Anyone with the key gets the same access to the same models with the same prompt at the same risk. That is not a security control, that is a shared password with extra steps.

**SentraGate** treats every call to an LLM the way a **Zero Trust architecture** treats every call to any resource: verify the identity, evaluate the policy, inspect the payload, log the decision. Access to `gpt-4o` for a compliance-verified employee on a managed device looks nothing like access for an intern on an unmanaged laptop, and the gateway enforces that difference on every single request rather than trusting a static API key.

## Core capabilities

- **Identity-first authentication.** Every request presents a **Microsoft Entra ID** access token (or a locally signed demo token in offline mode). No token, no access. Full stop.
- **Conditional Access-style policy engine.** YAML-defined rules evaluate group membership, simulated device compliance, and risk signals against the model being requested. Deny rules always win over allow rules, and anything that matches no rule is denied by default.
- **Content guardrails.** Every prompt is scanned before it leaves the gateway for **PII** (SSNs, card numbers), leaked secrets (cloud access keys, private key blocks, bearer tokens), and known **prompt injection** and jailbreak phrasing.
- **Per-identity rate limiting.** Limits are scoped to the verified subject, not to a shared API key or a raw IP address.
- **Structured audit trail.** Every allow, deny, guardrail block, and rate-limit event is written as a JSON line: who, what model, what policy fired, what the guardrails found. This is the evidence trail an auditor or incident responder actually wants.
- **Runs with zero external dependencies.** Offline demo mode generates its own signing keypair and returns canned model responses, so the full pipeline is testable with no Entra ID tenant and no LLM API key.

## Architecture

```
Client
  │  Authorization: Bearer <Entra ID access token>
  ▼
┌─────────────────────────────────────────────────────────┐
│                        SentraGate                        │
│                                                            │
│  1. Identity verification  (Entra ID / offline validator) │
│  2. Policy evaluation      (Conditional Access engine)    │
│  3. Rate limiting          (per verified identity)         │
│  4. Content guardrails     (PII / secrets / injection)     │
│  5. Audit logging          (structured JSONL, every path)  │
│                                                            │
└─────────────────────────────────────────────────────────┘
  │  only if every gate passes
  ▼
Upstream LLM (OpenAI-compatible endpoint, or demo mode)
```

Full request-by-request breakdown lives in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). The threat model for the gateway itself, including what this demo build does not yet cover, lives in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Quickstart

```bash
git clone https://github.com/<your-username>/sentragate.git
cd sentragate
pip install -r requirements.txt

# Run the gateway in offline demo mode (no Entra ID tenant, no LLM API key needed)
uvicorn sentragate.main:app --app-dir src --reload

# In another terminal, mint a demo identity token
python scripts/mint_demo_token.py \
  --subject alice@example.com --groups employees --risk-level low --device-compliant

# Call the gateway
curl -X POST http://127.0.0.1:8000/v1/chat/completions \
  -H "Authorization: Bearer <token from above>" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'
```

Try denying yourself on purpose. Mint a token with `--risk-level high`, or drop `--device-compliant` and request `gpt-4o`, and watch the policy engine shut it down with a `403` and an audit entry explaining exactly why.

## Configuring policy

Policies live in [`config/policies.yaml`](config/policies.yaml) and read like **Entra ID Conditional Access** rules:

```yaml
- name: "block-noncompliant-device-for-frontier-models"
  effect: deny
  when:
    model: ["gpt-4", "gpt-4o", "claude-opus"]
    device_compliant: [false]
```

Deny rules are evaluated first and always win. Allow rules are evaluated second. Anything that matches nothing is denied. That ordering is not an accident, it is the whole security model.

## Connecting a real model provider

Set `SENTRAGATE_UPSTREAM_URL` and `SENTRAGATE_UPSTREAM_API_KEY` in your `.env` (see [`.env.example`](.env.example)) to forward allowed, inspected requests to a real OpenAI-compatible endpoint. Leave them unset and the gateway stays fully self-contained for demos and interviews.

## Connecting to a real Entra ID tenant

Set `SENTRAGATE_AUTH_MODE=online` along with your `SENTRAGATE_TENANT_ID` and `SENTRAGATE_CLIENT_ID`. The gateway will fetch and cache your tenant's **JWKS** (JSON Web Key Set) from the standard **OIDC** discovery endpoint and validate real Entra ID access tokens against it, including issuer, audience, and expiry.

## Running the tests

```bash
pip install -r requirements.txt
pytest -q
```

16 tests cover the policy engine's allow/deny/default-deny logic, the content guardrails against PII, secrets, and injection phrasing, and the identity validator's handling of expired and tampered tokens.

## Known limitations (read before treating this as production-ready)

This is a portfolio-grade reference implementation, not a hardened production gateway. Specifically:

- The rate limiter is in-memory and single-process. A real deployment behind more than one instance needs a shared store.
- The content guardrails are regex-based. They are fast and explainable but will miss obfuscated or multi-turn injection attempts that a dedicated classifier would catch.
- Offline auth mode is for local development and demos only. It must never be pointed at production traffic.

These are documented in detail, with the reasoning behind each tradeoff, in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Roadmap

- [ ] Redis-backed distributed rate limiting
- [ ] Pluggable LLM-based classifier for guardrails, behind the same interface as the regex inspector
- [ ] Streaming response support
- [ ] OpenTelemetry export for the audit trail
- [ ] Admin dashboard for live policy and audit visibility

## About this project

Built by **Mel Rainey**, AI Security Engineer & content creator. More architecture breakdowns and the "LinkedIn fantasy vs. cybersecurity reality" series at [melrainey.com](https://melrainey.com).

## License

[MIT](LICENSE)
