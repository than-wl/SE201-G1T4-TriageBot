"""Run pre-declared development source-mutation pairs through TriageBot."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagebot import config, pipeline


CASES = (
    "BenchmarkTest00104",
    "BenchmarkTest00329",
    "BenchmarkTest00333",
    "BenchmarkTest00517",
    "BenchmarkTest01095",
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path,
                        default=config.CHECKPOINT_OUT / "selected_alerts.json")
    parser.add_argument("--mode", choices=("single", "council"), default="single")
    parser.add_argument("--case", action="append", choices=CASES, dest="cases",
                        help="run one declared case (repeatable; defaults to all five)")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    cases = tuple(args.cases or CASES)
    out = args.out or config.FINAL_OUT / f"mutation_results_{args.mode}.json"
    alerts = {item["case_id"]: item for item in
              json.loads(args.sample.read_text(encoding="utf-8"))["alerts"]}
    records = []
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        for case_id in cases:
            alert = alerts[case_id]
            original_path = Path(config.BENCHMARK_ROOT) / alert["file"]
            source = original_path.read_text(encoding="utf-8")
            if source.count("> 200") != 1:
                raise ValueError(f"{case_id}: expected exactly one safe branch condition")
            target = root / alert["file"]
            target.parent.mkdir(parents=True, exist_ok=True)

            target.write_text(source, encoding="utf-8")
            original = pipeline.triage(alert, mode=args.mode, benchmark_root=root)
            target.write_text(source.replace("> 200", "< 200"), encoding="utf-8")
            mutated = pipeline.triage(alert, mode=args.mode, benchmark_root=root)
            records.append({
                "case_id": case_id,
                "mutation": "invert the constant branch comparison from > 200 to < 200",
                "expected": {"original": "false_positive", "mutated": "true_positive"},
                "original_review": original["review"],
                "original": original["validated"],
                "mutated_review": mutated["review"],
                "mutated": mutated["validated"],
            })
            print(f"{case_id}: {original['validated']['verdict']} -> "
                  f"{mutated['validated']['verdict']}", flush=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"mode": args.mode, "pairs": records}, indent=2) + "\n",
                   encoding="utf-8")
    print(f"Mutation results: {out}")


if __name__ == "__main__":
    main()
