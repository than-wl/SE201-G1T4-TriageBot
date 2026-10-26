"""Serializable state for the council graph, not the single-agent baseline.

Each parallel specialist writes its own key (no shared-list reducer).
Callers, credentials, KB objects, paths and live timing handles belong in
runtime context, not this state. Persisted checkpointing is Phase 2.
"""

from typing import TypedDict

from triagebot.schemas import AgentReport, ContextPayload, NormalisedAlert


class CouncilState(TypedDict, total=False):
    # Initial input; subsequent keys are populated by their owning nodes.
    alert: NormalisedAlert
    payload: ContextPayload
    analyst_report: AgentReport
    skeptic_report: AgentReport
    # Reports include optional model/usage/latency fields, as before.
    review: dict
    role_reports: list[dict]
    validated: dict
