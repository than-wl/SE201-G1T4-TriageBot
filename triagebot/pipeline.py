"""Main graph: wires ingest -> context payload -> review -> validate.

The only module that knows the orchestration style. Nodes themselves are
plain functions with no framework dependency, so the wiring can change
without touching any node.
"""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import time

from triagebot import config
from triagebot.llm.openrouter import OpenRouterCaller
from triagebot.nodes.context.payload import build_payload
from triagebot.nodes.context.retrieval import KnowledgeBase
from triagebot.nodes.review.council import analyst, chair, skeptic
from triagebot.nodes.review.consistency import problem as consistency_problem
from triagebot.nodes.review.single_agent import baseline
from triagebot.nodes.validate.validator import validate_results


def _with_call_metadata(report, caller):
    call = getattr(caller, "last_call", None) or {}
    enriched = dict(report)
    for key in ("model", "latency_seconds", "usage"):
        if key in call:
            enriched[key] = call[key]
    return enriched


def _validation_case(payload, benchmark_root):
    path = Path(benchmark_root) / payload["alert"]["file"]
    source_files = {payload["alert"]["file"]: path.read_text(
        encoding="utf-8", errors="replace")}
    for related in payload["source"].get("related", []):
        related_path = Path(benchmark_root) / related["file"]
        source_files[related["file"]] = related_path.read_text(
            encoding="utf-8", errors="replace")
    return {
        "file": payload["alert"]["file"],
        "source": source_files[payload["alert"]["file"]],
        "source_files": source_files,
        "guidance_chunks": payload["guidance"]["chunks"],
    }


def _summed_usage(reports):
    usage = {}
    for report in reports:
        for key, value in (report.get("usage") or {}).items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                usage[key] = usage.get(key, 0) + value
    return usage


def _repair_inconsistent(payload, review, role_reports, caller_factory, repair):
    issue = consistency_problem(review)
    if not issue:
        return review
    caller = caller_factory()
    repaired = _with_call_metadata(repair(payload, review, issue, caller), caller)
    role_reports.append(repaired)
    if consistency_problem(repaired):
        repaired = dict(repaired, verdict="human_review")
        role_reports[-1] = repaired
    return repaired


def triage(alert, mode="single", caller_factory=OpenRouterCaller, kb=None,
           benchmark_root=None):
    """Run one normalised alert through review and deterministic validation."""
    if mode not in ("single", "council"):
        raise ValueError(f"unsupported review mode: {mode}")
    root = benchmark_root or config.BENCHMARK_ROOT
    kb = kb or KnowledgeBase()
    payload = build_payload(alert, kb, root)
    started = time.perf_counter()
    if mode == "single":
        caller = caller_factory()
        review = _with_call_metadata(baseline.review(payload, caller), caller)
        role_reports = [review]
        review = _repair_inconsistent(
            payload, review, role_reports, caller_factory, baseline.repair)
    else:
        analyst_caller, skeptic_caller = caller_factory(), caller_factory()
        with ThreadPoolExecutor(max_workers=2) as pool:
            analyst_future = pool.submit(analyst.review, payload, analyst_caller)
            skeptic_future = pool.submit(skeptic.review, payload, skeptic_caller)
            analyst_report = _with_call_metadata(analyst_future.result(), analyst_caller)
            skeptic_report = _with_call_metadata(skeptic_future.result(), skeptic_caller)
        chair_caller = caller_factory()
        chair_report = _with_call_metadata(
            chair.review(payload, analyst_report, skeptic_report, chair_caller), chair_caller)
        role_reports = [analyst_report, skeptic_report, chair_report]
        review = _repair_inconsistent(
            payload, chair_report, role_reports, caller_factory, chair.repair)

    review = dict(review)
    review["usage"] = _summed_usage(role_reports)
    role_reports[-1] = review

    review["latency_seconds"] = round(time.perf_counter() - started, 3)
    cases = {alert["case_id"]: _validation_case(payload, root)}
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
