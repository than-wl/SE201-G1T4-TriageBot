"""Baseline review path (proposal condition B): one primary LLM call.

ContextPayload in -> AgentReport out — same interface as the council,
so downstream validation and scoring are strategy-agnostic.
"""

from triagebot import config
from triagebot.nodes.review.report import assemble, failure
import json

from triagebot.nodes.review.prompts import (REPAIR_SYSTEM, SINGLE_SYSTEM, for_cwe,
                                            to_prompt_block)


def review(payload, caller):
    request = {
        "system": for_cwe(SINGLE_SYSTEM, payload),
        "user": to_prompt_block(payload),
        "max_tokens": config.REVIEW_MAX_TOKENS,
        "temperature": config.REVIEW_TEMPERATURE,
    }
    result = caller.complete(request)
    case_id = payload["alert"]["case_id"]
    if "_error" in result:
        return failure("single", case_id, result["_error"])
    return assemble("single", case_id, result)


def repair(payload, report, issue, caller):
    user = "\n\n".join([
        to_prompt_block(payload),
        "--- Report to reconsider ---",
        json.dumps(report, indent=1),
        "--- Consistency problem ---",
        issue,
    ])
    result = caller.complete({
        "system": for_cwe(REPAIR_SYSTEM, payload),
        "user": user,
        "max_tokens": config.REVIEW_MAX_TOKENS,
        "temperature": config.REVIEW_TEMPERATURE,
    })
    case_id = payload["alert"]["case_id"]
    if "_error" in result:
        return failure("single", case_id, result["_error"])
    return assemble("single", case_id, result)
