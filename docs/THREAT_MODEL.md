# Threat Model

SentraGate is a security control, which means SentraGate is also an attack surface. This document threat models the gateway itself, using a lightweight **STRIDE**-style pass, and is honest about what the current reference build does and does not defend against.

## Assets being protected

- The upstream LLM and its API credentials
- Prompt content that may contain sensitive business data
- Model responses, which may themselves leak system prompt content or internal context
- The audit trail, which is the evidence base for any post-incident investigation
- Identity claims, which every downstream decision depends on

## Trust boundaries

```
Untrusted            Verified                 Trusted
(raw request)  →   (post-identity-check)  →  (post-policy-and-guardrails)
```

Nothing on the left side of the first boundary is trusted for anything beyond "here is a bearer token, let's find out if it's real." Nothing on the right side of the second boundary reaches the upstream model unless it also cleared rate limiting and content guardrails.

## STRIDE pass

**Spoofing.** An attacker without a valid Entra ID token cannot authenticate. In offline demo mode, anyone with access to the local `.sentragate_demo_keys` directory can mint valid demo tokens, which is exactly why offline mode must never run against production traffic or be exposed on a network interface beyond localhost.

**Tampering.** Access tokens are RS256-signed and any modification to the payload invalidates the signature (verified in `test_tampered_token_rejected`). Policy files are plain YAML on disk; a production deployment should protect `config/policies.yaml` with the same change control as any other security-relevant configuration, ideally version-controlled with required review.

**Repudiation.** Every decision, allow or deny, is written to the audit log with a request ID, verified subject, matched policy, and guardrail findings. The current implementation is append-only at the application layer but does not yet provide cryptographic tamper-evidence (e.g., hash chaining) for the log file itself. That is a known gap for a high-assurance deployment and is on the roadmap.

**Information disclosure.** This is the guardrail layer's job. Prompts are scanned for PII, cloud credentials, and private key material before they ever leave the gateway. The regex-based approach is fast and fully explainable in an audit, but it is a first line of defense, not a complete one: it will not catch semantically obfuscated exfiltration attempts (base64-encoded secrets, PII split across multiple messages, homoglyph substitution). A production deployment should pair this layer with a model-based classifier for defense in depth.

**Denial of service.** Per-identity rate limiting bounds how hard any single identity can hammer the upstream model. It does not currently protect against a volumetric attack from many distinct compromised identities, which is an infrastructure-layer concern (WAF, network rate limiting) outside this application's scope.

**Elevation of privilege.** The policy engine's default-deny posture means a request with no matching allow rule is denied, not silently allowed. The `/v1/policies` introspection endpoint itself requires the `security-admins` group claim, so policy visibility is not open to every authenticated caller.

## Prompt injection and jailbreak coverage

The content inspector currently detects direct, literal injection phrasing: instruction override attempts, system prompt extraction requests, and known jailbreak framing ("DAN", "developer mode"). It does **not** currently catch:

- Multi-turn injection built up gradually across a conversation
- Indirect injection carried in retrieved documents or tool outputs (this gateway sits in front of the model call itself, not inside a **RAG** pipeline)
- Injection phrased in a language other than English, or through unicode obfuscation

These are explicitly out of scope for this reference build and are the natural next milestone for the project (see README roadmap).

## What "offline mode" actually means for security

Offline mode exists so this project can be cloned, run, and evaluated by anyone without a real Entra ID tenant or an LLM API key. It is a demo and testing convenience, not a lightweight production auth mode. The demo RSA keypair is generated and stored unencrypted on local disk specifically so it is easy to reason about and inspect. Running offline mode anywhere near real user traffic defeats the entire purpose of the identity layer, since anyone with filesystem access can mint a valid token for any subject and any group.

## Summary judgment

This build demonstrates the correct shape of a Zero Trust AI gateway: verified identity before anything else, explicit policy with default deny, content inspection before upstream forwarding, and an audit trail for every decision. It is not a substitute for a production security review, and it should not be represented as one. Treat it as a reference architecture and a base to harden, not a finished product.
