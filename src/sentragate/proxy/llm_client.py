"""
Upstream LLM proxy client.

Forwards an allowed, inspected request to the real model provider. If no
upstream is configured (SENTRAGATE_UPSTREAM_URL unset), the gateway runs in
fully self-contained demo mode and returns a canned response, so the whole
security pipeline can be exercised without an API key or network egress.
"""
from __future__ import annotations

from typing import Any

import httpx


class UpstreamError(Exception):
    pass


async def forward_to_llm(
    payload: dict[str, Any],
    upstream_url: str | None,
    api_key: str | None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    if not upstream_url:
        return {
            "id": "demo-completion",
            "model": payload.get("model", "demo-model"),
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": (
                            "[SentraGate demo mode] Request passed identity "
                            "verification, policy evaluation, and content "
                            "guardrails. No upstream LLM is configured, so "
                            "this is a canned response. Set "
                            "SENTRAGATE_UPSTREAM_URL to forward for real."
                        ),
                    },
                    "finish_reason": "stop",
                }
            ],
        }

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.post(upstream_url, json=payload, headers=headers)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise UpstreamError(str(exc)) from exc

    return resp.json()
