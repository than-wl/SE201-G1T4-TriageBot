"""Framework-neutral execution helpers shared by both review strategies."""

import hashlib
from pathlib import Path


def with_call_metadata(report, caller):
    call = getattr(caller, "last_call", None) or {}
    enriched = dict(report)
    for key in ("model", "latency_seconds", "usage"):
        if key in call:
            enriched[key] = call[key]
    return enriched


def validation_case(payload, benchmark_root, expected_source_sha256=None):
    path = Path(benchmark_root) / payload["alert"]["file"]
    if expected_source_sha256 is None:
        source = path.read_text(encoding="utf-8", errors="replace")
    else:
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_source_sha256:
            raise ValueError("Source changed since this council run was created")
        source = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    return {
        "file": payload["alert"]["file"],
        "source": source,
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
