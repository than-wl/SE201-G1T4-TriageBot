"""Produce overall and per-CWE final-test metrics from saved run files."""

import argparse
import json
from pathlib import Path

from triagebot.nodes.ingest.answer_key import load_answer_key
from triagebot.nodes.score.evaluate import evaluate, load_cases, load_results


def build(cases, answer_key, configs):
    labels = {case_id: entry["vulnerable"] for case_id, entry in answer_key.items()}
    by_cwe = {}
    for cwe in sorted({answer_key[case_id]["cwe"] for case_id in cases}):
        category_cases = [case_id for case_id in cases if answer_key[case_id]["cwe"] == cwe]
        by_cwe[cwe] = evaluate(category_cases, labels, configs)
    return {
        "protocol": "frozen 50/50 stratified test split; human_review is retained for precision/recall/F1",
        "overall": evaluate(cases, labels, configs),
        "by_cwe": by_cwe,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--config", action="append", default=[], metavar="NAME=PATH")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    configs = {}
    for item in args.config:
        name, separator, path = item.partition("=")
        if not separator or not name or name in configs:
            parser.error(f"bad or repeated --config {item!r}; use NAME=PATH")
        configs[name] = load_results(path)
    report = build(load_cases(args.cases), load_answer_key(args.labels), configs)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Final evaluation report: {out}")


if __name__ == "__main__":
    main()
