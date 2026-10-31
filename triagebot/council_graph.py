"""Council-only LangGraph orchestration; persistence is opt-in, HITL deferred.

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

    Ephemeral runs retain the original monotonic wall-clock metric. Durable
    runs use saved active node durations instead; no process-local timer is
    required after recovery. Dependencies are reconstructed by the caller.
    """

    caller_factory: Callable[[], Any]
    kb: Any
    benchmark_root: Any
    review_started: float | None = None
    persistent: bool = False
    expected_source_sha256: str | None = None


def _build_context(state: CouncilState, runtime: Runtime[CouncilContext]):
    ctx = runtime.context
    if ctx.expected_source_sha256 is not None:
        validation_case({"alert": state["alert"], "guidance": {"chunks": []}},
                        ctx.benchmark_root, ctx.expected_source_sha256)
    payload = build_payload(state["alert"], ctx.kb, ctx.benchmark_root)
    ctx.review_started = time.perf_counter()
    return {"payload": payload}


def _analyst(state: CouncilState, runtime: Runtime[CouncilContext]):
    started = time.perf_counter()
    caller = runtime.context.caller_factory()
    report = analyst.review(state["payload"], caller)
    return {"analyst_report": with_call_metadata(report, caller),
            "analyst_elapsed_seconds": time.perf_counter() - started}


def _skeptic(state: CouncilState, runtime: Runtime[CouncilContext]):
    started = time.perf_counter()
    caller = runtime.context.caller_factory()
    report = skeptic.review(state["payload"], caller)
    return {"skeptic_report": with_call_metadata(report, caller),
            "skeptic_elapsed_seconds": time.perf_counter() - started}


def _chair(state: CouncilState, runtime: Runtime[CouncilContext]):
    started = time.perf_counter()
    caller = runtime.context.caller_factory()
    report = chair.review(
        state["payload"], state["analyst_report"], state["skeptic_report"], caller
    )
    review = with_call_metadata(report, caller)
    review["usage"] = summed_usage(
        [state["analyst_report"], state["skeptic_report"], review]
    )
    return {"review": review, "chair_elapsed_seconds": time.perf_counter() - started}


def _validate(state: CouncilState, runtime: Runtime[CouncilContext]):
    ctx = runtime.context
    if not ctx.persistent and ctx.review_started is None:
        raise RuntimeError("Council review timer was not initialized")
    # Copy rather than mutate the value produced by the Chair node.
    review = dict(state["review"])
    if ctx.persistent:
        # Critical path of completed model nodes, excluding offline/recovery wait.
        elapsed = max(state["analyst_elapsed_seconds"], state["skeptic_elapsed_seconds"])
        elapsed += state["chair_elapsed_seconds"]
    else:
        elapsed = time.perf_counter() - ctx.review_started
    review["latency_seconds"] = round(elapsed, 3)
    cases = {
        state["alert"]["case_id"]: validation_case(state["payload"], ctx.benchmark_root, ctx.expected_source_sha256)
    }
    validated = validate_results(review, cases)["results"][0]
    return {
        "review": review,
        "role_reports": [state["analyst_report"], state["skeptic_report"], review],
        "validated": validated,
    }


def build_council_graph(checkpointer=None, *, interrupt_after=None):
    """Compile with optional persistence. Static test stops are NOT human HITL."""
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
    return graph.compile(checkpointer=checkpointer, interrupt_after=interrupt_after)


def run_council(alert, caller_factory=OpenRouterCaller, kb=None, benchmark_root=None):
    """Return the existing triage() result contract without graph internals."""
    context = CouncilContext(
        caller_factory=caller_factory,
        kb=kb if kb is not None else KnowledgeBase(),
        benchmark_root=benchmark_root or config.BENCHMARK_ROOT,
    )
    state = build_council_graph().invoke({"alert": alert}, context=context)
    return council_result(state)


def council_result(state):
    """Project graph internals onto the existing public triage contract."""
    return {
        "case_id": state["alert"]["case_id"],
        "mode": "council",
        "payload": state["payload"],
        "role_reports": state["role_reports"],
        "review": state["review"],
        "validated": state["validated"],
    }
