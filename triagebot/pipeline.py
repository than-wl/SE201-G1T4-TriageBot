"""Public orchestration seam: plain-Python baseline or LangGraph council.

Keep triage() and run_sample() outputs stable for the CLI and evaluator.
Review functions remain framework-neutral; council wiring is isolated in
council_graph.py. Phase 1 does not persist state or interrupt for a human.
"""

import json
from pathlib import Path
import time

from triagebot import config
from triagebot.execution import validation_case, with_call_metadata
from triagebot.llm.openrouter import OpenRouterCaller
from triagebot.nodes.context.payload import build_payload
from triagebot.nodes.context.retrieval import KnowledgeBase
from triagebot.nodes.review.single_agent import baseline
from triagebot.nodes.validate.validator import validate_results


def triage(alert, mode="single", caller_factory=OpenRouterCaller, kb=None,
           benchmark_root=None):
    """Run one normalised alert through review and deterministic validation."""
    if mode not in ("single", "council"):
        raise ValueError(f"unsupported review mode: {mode}")
    if mode == "council":
        # Lazy import keeps the comparison baseline framework-independent.
        from triagebot.council_graph import run_council

        return run_council(alert, caller_factory, kb, benchmark_root)
    root = benchmark_root or config.BENCHMARK_ROOT
    kb = kb or KnowledgeBase()
    payload = build_payload(alert, kb, root)
    started = time.perf_counter()
    caller = caller_factory()
    review = with_call_metadata(baseline.review(payload, caller), caller)
    role_reports = [review]

    review["latency_seconds"] = round(time.perf_counter() - started, 3)
    cases = {alert["case_id"]: validation_case(payload, root)}
    validated = validate_results(review, cases)["results"][0]
    return {"case_id": alert["case_id"], "mode": mode, "payload": payload,
            "role_reports": role_reports, "review": review, "validated": validated}


def _configuration(results):
    model = next((result.get("model") for result in results if result.get("model")), None)
    return {"model": model, "results": results}


def run_sample(alerts, modes=("single", "council"), out_dir=config.CHECKPOINT_OUT,
               caller_factory=OpenRouterCaller, kb=None, benchmark_root=None):
    """Run the selected alerts and save configurations accepted by the evaluator."""
    unknown = set(modes) - {"single", "council"}
    if unknown:
        raise ValueError(f"unsupported review mode(s): {', '.join(sorted(unknown))}")
    kb = kb or KnowledgeBase()
    single, council, validated_council = [], [], []
    for alert in alerts:
        for mode in modes:
            run = triage(alert, mode, caller_factory, kb, benchmark_root)
            if mode == "single":
                single.append(run["review"])
            else:
                council.append(run["review"])
                validated_council.append(run["validated"])

    configurations = {}
    if "single" in modes:
        configurations["B-single-agent"] = _configuration(single)
    if "council" in modes:
        configurations["C-council"] = _configuration(council)
        configurations["D-validated-council"] = _configuration(validated_council)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, data in configurations.items():
        (out / f"{name}.json").write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return configurations
