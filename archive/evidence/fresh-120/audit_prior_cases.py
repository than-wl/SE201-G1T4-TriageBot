"""Reproduce the fresh-120 post-selection audit against 287 prior cases."""

import hashlib
import json
from pathlib import Path


EVIDENCE = Path(__file__).resolve().parents[1]
FRESH = Path(__file__).with_name("selected_alerts.json")
SOURCES = {
    "checkpoint_sample": EVIDENCE / "prior-samples" / "checkpoint-100-selected_alerts.json",
    "original_final_sample": EVIDENCE / "prior-samples" / "original-final-120-selected_alerts.json",
    "comparison_sample": EVIDENCE / "comparison-66" / "selected_alerts.json",
}
SMOKE_CASES = {"BenchmarkTest00105"}


def case_ids(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {alert["case_id"] for alert in payload["alerts"]}


source_ids = {name: case_ids(path) for name, path in SOURCES.items()}
construction_exclusions = source_ids["original_final_sample"] | source_ids["comparison_sample"]
prior = set().union(*source_ids.values(), SMOKE_CASES)
fresh = case_ids(FRESH)
overlap = sorted(fresh & prior)

assert len(construction_exclusions) == 186
assert len(prior) == 287
assert len(fresh) == 120
assert not overlap

report = {
    "construction_exclusions": {
        "count": len(construction_exclusions),
        "sources": ["original_final_sample", "comparison_sample"],
    },
    "post_selection_audit": {
        "prior_case_count": len(prior),
        "source_counts": {name: len(ids) for name, ids in source_ids.items()},
        "additional_smoke_cases": sorted(SMOKE_CASES),
        "fresh_case_count": len(fresh),
        "overlap_count": len(overlap),
        "overlap": overlap,
    },
    "fresh_selected_alerts_sha256": hashlib.sha256(FRESH.read_bytes()).hexdigest(),
    "prior_case_ids": sorted(prior),
}

output = Path(__file__).with_name("prior_case_audit.json")
output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(f"Verified {len(fresh)} fresh cases against {len(prior)} prior cases: zero overlap")
