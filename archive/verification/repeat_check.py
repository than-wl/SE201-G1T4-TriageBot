"""Repeat the pre-declared five-case council subset and measure agreement."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagebot import config, pipeline


CASES = (
    "BenchmarkTest00011",
    "BenchmarkTest00015",
    "BenchmarkTest00030",
    "BenchmarkTest00024",
    "BenchmarkTest00021",
)
CONFIGS = ("C-council", "D-validated-council")


def _by_case(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return {result["case_id"]: result for result in data["results"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path,
                        default=config.FINAL_OUT / "selected_alerts.json")
    parser.add_argument("--original", type=Path,
                        default=config.FINAL_OUT / "results")
    parser.add_argument("--out", type=Path,
                        default=config.FINAL_OUT / "repeat")
    args = parser.parse_args(argv)
    sample = json.loads(args.sample.read_text(encoding="utf-8"))["alerts"]
    wanted = set(CASES)
    alerts = [alert for alert in sample if alert["case_id"] in wanted]
    if {alert["case_id"] for alert in alerts} != wanted:
        raise ValueError("repeat subset is not fully present in the frozen sample")
    pipeline.run_sample(alerts, modes=("council",), out_dir=args.out)
    summary = {"cases": list(CASES), "configurations": {}}
    for name in CONFIGS:
        first = _by_case(args.original / f"{name}.json")
        repeat = _by_case(args.out / f"{name}.json")
        pairs = [{
            "case_id": case_id,
            "first": first[case_id]["verdict"],
            "repeat": repeat[case_id]["verdict"],
            "agree": first[case_id]["verdict"] == repeat[case_id]["verdict"],
        } for case_id in CASES]
        summary["configurations"][name] = {
            "agreement": sum(pair["agree"] for pair in pairs) / len(pairs),
            "pairs": pairs,
        }
    path = args.out / "repeat_summary.json"
    path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"Repeat summary: {path}")


if __name__ == "__main__":
    main()
