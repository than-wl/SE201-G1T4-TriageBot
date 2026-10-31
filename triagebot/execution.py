"""Framework-neutral execution helpers shared by both review strategies."""

import hashlib
from pathlib import Path

from triagebot.nodes.review.consistency import problem as consistency_problem


def with_call_metadata(report, caller):
    call = getattr(caller, "last_call", None) or {}
    enriched = dict(report)
    for key in ("model", "latency_seconds", "usage"):
        if key in call:
            enriched[key] = call[key]
    return enriched


def validation_case(payload, benchmark_root, expected_source_sha256=None):
    root = Path(benchmark_root)
    main_file = payload["alert"]["file"]
    path = root / main_file
    if expected_source_sha256 is None:
        source = path.read_text(encoding="utf-8", errors="replace")
    else:
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_source_sha256:
            raise ValueError("Source changed since this council run was created")
        source = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    # The alert's own file plus any related project files the payload quoted, so a
    # citation into a helper is checked against that helper's real text.
    source_files = {main_file: source}
    for related in payload.get("source", {}).get("related", []):
        source_files[related["file"]] = (root / related["file"]).read_text(
            encoding="utf-8", errors="replace")
    return {
        "file": main_file,
        "source": source,
        "source_files": source_files,
        "guidance_chunks": payload["guidance"]["chunks"],
        # False means no grounded guidance: the validator routes the case to human review.
        "guidance_matched": payload.get("guidance", {}).get("cwe_matched"),
    }


def summed_usage(reports):
    usage = {}
    for report in reports:
        for key, value in (report.get("usage") or {}).items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                usage[key] = usage.get(key, 0) + value
    return usage


def repair_if_inconsistent(payload, review, role_reports, caller_factory, repair):
    """One repair call when the verdict contradicts the structured analysis.

    A repaired report that is still inconsistent is escalated to human_review. The
    repaired report is appended to ``role_reports`` (the caller's list). No automatic
    retry beyond this single repair call.
    """
    issue = consistency_problem(review)
    if not issue:
        return review
    caller = caller_factory()
    repaired = with_call_metadata(repair(payload, review, issue, caller), caller)
    role_reports.append(repaired)
    if consistency_problem(repaired):
        repaired = dict(repaired, verdict="human_review")
        role_reports[-1] = repaired
    return repaired
