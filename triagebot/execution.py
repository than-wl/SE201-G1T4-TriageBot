"""Framework-neutral execution helpers shared by both review strategies."""

from pathlib import Path


def with_call_metadata(report, caller):
    call = getattr(caller, "last_call", None) or {}
    enriched = dict(report)
    for key in ("model", "latency_seconds", "usage"):
        if key in call:
            enriched[key] = call[key]
    return enriched


def validation_case(payload, benchmark_root):
    path = Path(benchmark_root) / payload["alert"]["file"]
    return {
        "file": payload["alert"]["file"],
        "source": path.read_text(encoding="utf-8", errors="replace"),
        "guidance_chunks": payload["guidance"]["chunks"],
    }


def summed_usage(reports):
    usage = {}
    for report in reports:
        for key, value in (report.get("usage") or {}).items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                usage[key] = usage.get(key, 0) + value
    return usage
