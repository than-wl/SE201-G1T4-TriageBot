"""Council-only LangGraph orchestration (Phase 1: no persistence or HITL).

The graph fans out to independent specialists and explicitly joins BOTH
before Chair. Dependencies live in per-invocation runtime context; the
state contains only JSON-compatible inputs and results. No retry policy
is configured: transport failures still follow the existing caller contract.
"""

from dataclasses import dataclass
import time
from typing import Any, Callable

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from triagebot import config
from triagebot.execution import summed_usage, validation_case, with_call_metadata
from triagebot.llm.openrouter import OpenRouterCaller
from triagebot.nodes.context.payload import build_payload
from triagebot.nodes.context.retrieval import KnowledgeBase
from triagebot.nodes.review.council import analyst, chair, skeptic
from triagebot.nodes.validate.validator import validate_results
from triagebot.state import CouncilState


@dataclass
class CouncilContext:
    """Run-scoped dependencies; never part of serialized CouncilState.

    The monotonic timer preserves Phase 1's pre-validation latency metric.
    Phase 2 must define timing for cross-process recovery; this marker
    cannot be restored from a checkpoint or reused across processes.
    """

    caller_factory: Callable[[], Any]
    kb: Any
    benchmark_root: Any
    review_started: float | None = None


def _build_context(state: CouncilState, runtime: Runtime[CouncilContext]):
    ctx = runtime.context
    payload = build_payload(state["alert"], ctx.kb, ctx.benchmark_root)
    ctx.review_started = time.perf_counter()
    return {"payload": payload}


def _analyst(state: CouncilState, runtime: Runtime[CouncilContext]):
    caller = runtime.context.caller_factory()
    report = analyst.review(state["payload"], caller)
    return {"analyst_report": with_call_metadata(report, caller)}


def _skeptic(state: CouncilState, runtime: Runtime[CouncilContext]):
    caller = runtime.context.caller_factory()
    report = skeptic.review(state["payload"], caller)
    return {"skeptic_report": with_call_metadata(report, caller)}


def _chair(state: CouncilState, runtime: Runtime[CouncilContext]):
    caller = runtime.context.caller_factory()
    report = chair.review(
        state["payload"], state["analyst_report"], state["skeptic_report"], caller
    )
    review = with_call_metadata(report, caller)
    review["usage"] = summed_usage(
        [state["analyst_report"], state["skeptic_report"], review]
    )
    return {"review": review}


def _validate(state: CouncilState, runtime: Runtime[CouncilContext]):
    ctx = runtime.context
    if ctx.review_started is None:
        raise RuntimeError("Council review timer was not initialized")
    # Copy rather than mutate the value produced by the Chair node.
    review = dict(state["review"])
    review["latency_seconds"] = round(time.perf_counter() - ctx.review_started, 3)
    cases = {
        state["alert"]["case_id"]: validation_case(state["payload"], ctx.benchmark_root)
    }
    validated = validate_results(review, cases)["results"][0]
    return {
        "review": review,
        "role_reports": [state["analyst_report"], state["skeptic_report"], review],
        "validated": validated,
    }


def build_council_graph():
    """Compile an ephemeral graph; SQLite/thread IDs are explicitly Phase 2."""
    graph = StateGraph(CouncilState, context_schema=CouncilContext)
    graph.add_node("build_context", _build_context)
    graph.add_node("analyst", _analyst)
    graph.add_node("skeptic", _skeptic)
    graph.add_node("chair", _chair)
    graph.add_node("validate", _validate)
    graph.add_edge(START, "build_context")
    graph.add_edge("build_context", "analyst")
    graph.add_edge("build_context", "skeptic")
    # A waiting edge, not two independent edges that might trigger two joins.
    graph.add_edge(["analyst", "skeptic"], "chair")
    graph.add_edge("chair", "validate")
    graph.add_edge("validate", END)
    return graph.compile()


def run_council(alert, caller_factory=OpenRouterCaller, kb=None, benchmark_root=None):
    """Return the existing triage() result contract without graph internals."""
    context = CouncilContext(
        caller_factory=caller_factory,
        kb=kb if kb is not None else KnowledgeBase(),
        benchmark_root=benchmark_root or config.BENCHMARK_ROOT,
    )
    state = build_council_graph().invoke({"alert": alert}, context=context)
    return {
        "case_id": alert["case_id"],
        "mode": "council",
        "payload": state["payload"],
        "role_reports": state["role_reports"],
        "review": state["review"],
        "validated": state["validated"],
    }
