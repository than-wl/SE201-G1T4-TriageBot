"""Caller interface: complete(request: dict) -> dict.

The request carries: system, user, max_tokens, temperature.
Implementations add the model/endpoint/auth, send the request, parse
the model's JSON answer into a dict, and return that dict (decision:
parsing lives in the caller, so every role sees dicts).

Failure contract: on transport, auth, or billing problems, do NOT
raise and do NOT retry — return {"_error": "<reason>"} instead; roles
convert it into a safe human_review report.

Implementations: openrouter.OpenRouterCaller (live),
fixture.FixtureCaller (offline tests).
"""
