"""Join node — Chair: receives both specialist reports and returns one
supported verdict with exact source citations.

The specialists' reports are appended as claims after the shared
evidence block; the Chair must re-verify their citations against the
numbered source lines before relying on them.
"""

import json

from triagebot import config
from triagebot.nodes.review.report import assemble, failure
from triagebot.nodes.review.prompts import (CHAIR_SYSTEM, REPAIR_SYSTEM, for_cwe,
                                            to_prompt_block)


def review(payload, analyst_report, skeptic_report, caller):
    user = "\n\n".join([
        to_prompt_block(payload),
        "--- Analyst report (claims to verify, not facts) ---",
        json.dumps(analyst_report, indent=1),
        "--- Skeptic report (claims to verify, not facts) ---",
        json.dumps(skeptic_report, indent=1),
    ])
    request = {
        "system": for_cwe(CHAIR_SYSTEM, payload),
        "user": user,
        "max_tokens": config.REVIEW_MAX_TOKENS,
        "temperature": config.REVIEW_TEMPERATURE,
    }
    result = caller.complete(request)
    case_id = payload["alert"]["case_id"]
    if "_error" in result:
        return failure("chair", case_id, result["_error"])
    return assemble("chair", case_id, result)


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
        return failure("chair", case_id, result["_error"])
    return assemble("chair", case_id, result)
