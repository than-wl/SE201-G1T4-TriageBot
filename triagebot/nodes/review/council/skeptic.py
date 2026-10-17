"""Parallel branch B — Skeptic: search for constants, sanitisation,
guards, overwritten values, unreachable paths, and missing context that
would make the finding a false positive.

Runs concurrently with the Analyst on a byte-identical evidence block;
neither sees the other's report (blinded until the Chair joins).
"""

from triagebot import config
from triagebot.nodes.review.report import assemble, failure
from triagebot.nodes.review.prompts import SKEPTIC_SYSTEM, to_prompt_block


def review(payload, caller):
    request = {
        "system": SKEPTIC_SYSTEM,
        "user": to_prompt_block(payload),
        "max_tokens": config.REVIEW_MAX_TOKENS,
        "temperature": config.REVIEW_TEMPERATURE,
    }
    result = caller.complete(request)
    case_id = payload["alert"]["case_id"]
    if "_error" in result:
        return failure("skeptic", case_id, result["_error"])
    return assemble("skeptic", case_id, result)
