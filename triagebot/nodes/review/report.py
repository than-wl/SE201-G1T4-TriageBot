"""Shared report assembly for every review role.

Identity fields (role, case_id) are stamped by code, never trusted from
the model; defaults are always the safe verdict. The validator (PR #2)
remains the enforcer of evidence rules — this module only normalises
shape so all four roles emit the same AgentReport contract.
"""

_VERDICTS = ("true_positive", "false_positive", "human_review")


def assemble(role: str, case_id: str, result: dict) -> dict:
    """Normalise a parsed model dict into an AgentReport."""
    verdict = result.get("verdict")
    if verdict not in _VERDICTS:              # model never widens the enum
        verdict = "human_review"
    return {
        "role": role,
        "case_id": case_id,
        "verdict": verdict,
        "explanation": result.get("explanation", ""),
        "citations": _as_list(result.get("citations")),
        "guidance": _as_list(result.get("guidance")),
        "analysis": result.get("analysis") if isinstance(result.get("analysis"), dict) else {},
    }


def failure(role: str, case_id: str, error: str) -> dict:
    """Safe report for a failed model call (no retries per team rules)."""
    return {
        "role": role,
        "case_id": case_id,
        "verdict": "human_review",
        "explanation": f"Model call failed; no verdict can be trusted: {error}",
        "citations": [],
        "guidance": [],
        "analysis": {},
    }


def _as_list(value) -> list:
    return list(value) if isinstance(value, list) else []
