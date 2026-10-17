"""Baseline review path (proposal condition B): one LLM call.

ContextPayload in -> AgentReport out — same interface as the council,
so downstream validation and scoring are strategy-agnostic.
"""

from triagebot import config
from triagebot.nodes.review.report import assemble, failure
from triagebot.nodes.review.prompts import SINGLE_SYSTEM, to_prompt_block


def review(payload, caller):
    request = {
        "system": SINGLE_SYSTEM,
        "user": to_prompt_block(payload),
        "max_tokens": config.REVIEW_MAX_TOKENS,
        "temperature": config.REVIEW_TEMPERATURE,
    }
    result = caller.complete(request)
    case_id = payload["alert"]["case_id"]
    if "_error" in result:
        return failure("single", case_id, result["_error"])
    return assemble("single", case_id, result)
