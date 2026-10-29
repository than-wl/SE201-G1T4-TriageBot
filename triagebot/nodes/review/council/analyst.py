"""Parallel branch A — Analyst: trace user-controlled input toward the
dangerous operation and collect evidence that the finding is genuine.

Runs concurrently with the Skeptic on a byte-identical evidence block;
neither sees the other's report (blinded until the Chair joins).
"""

from triagebot import config
from triagebot.nodes.review.report import assemble, failure
from triagebot.nodes.review.prompts import ANALYST_SYSTEM, for_cwe, to_prompt_block


def review(payload, caller):
    request = {
        "system": for_cwe(ANALYST_SYSTEM, payload),
        "user": to_prompt_block(payload),
        "max_tokens": config.REVIEW_MAX_TOKENS,
        "temperature": config.REVIEW_TEMPERATURE,
    }
    result = caller.complete(request)
    case_id = payload["alert"]["case_id"]
    if "_error" in result:
        return failure("analyst", case_id, result["_error"])
    return assemble("analyst", case_id, result)
