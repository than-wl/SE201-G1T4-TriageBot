"""Measure bounded source-relationship retrieval on a selected alert sample."""

import argparse
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagebot import config
from triagebot.nodes.context.payload import build_payload
from triagebot.nodes.context.retrieval import KnowledgeBase
from triagebot.nodes.review.prompts import to_prompt_block


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path,
                        default=config.CHECKPOINT_OUT / "selected_alerts.json")
    parser.add_argument("--benchmark-root", type=Path,
                        default=Path(config.BENCHMARK_ROOT) if config.BENCHMARK_ROOT else None)
    args = parser.parse_args(argv)
    if args.benchmark_root is None:
        raise SystemExit("Set BENCHMARK_ROOT or pass --benchmark-root")

    alerts = json.loads(args.sample.read_text(encoding="utf-8"))["alerts"]
    kb = KnowledgeBase()
    rows = []
    for alert in alerts:
        payload = build_payload(alert, kb, args.benchmark_root)
        related = payload["source"].get("related", [])
        rows.append({
            "case_id": alert["case_id"],
            "primary_lines": len(payload["source"]["lines"]),
            "related_files": len(related),
            "related_lines": sum(len(item["lines"]) for item in related),
            "evidence_chars": len(to_prompt_block(payload)),
        })

    with_related = [row for row in rows if row["related_files"]]
    largest = sorted(rows, key=lambda row: row["evidence_chars"], reverse=True)[:5]
    print(json.dumps({
        "cases": len(rows),
        "cases_with_related_source": len(with_related),
        "related_files_max": max(row["related_files"] for row in rows),
        "related_lines_max": max(row["related_lines"] for row in rows),
        "evidence_chars_mean": round(statistics.mean(row["evidence_chars"] for row in rows)),
        "evidence_chars_max": max(row["evidence_chars"] for row in rows),
        "rough_tokens_max_at_4_chars": round(max(row["evidence_chars"] for row in rows) / 4),
        "largest_evidence_cases": largest,
    }, indent=2))


if __name__ == "__main__":
    main()
