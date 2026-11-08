"""Freeze an unused held-out sample, excluding the completed final evaluation."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagebot import config
from triagebot.nodes.ingest.final_sample import build


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", type=Path,
                        default=config.FINAL_OUT / "semgrep-owasp-combined.json")
    parser.add_argument("--answer-key", type=Path, default=config.ANSWER_KEY)
    parser.add_argument("--prior-sample", type=Path,
                        default=config.FINAL_OUT / "selected_alerts.json")
    parser.add_argument("--out", type=Path,
                        default=config.FINAL_OUT.parent / "comparison")
    args = parser.parse_args(argv)
    for name, path in (("Semgrep scan", args.semgrep), ("answer key", args.answer_key),
                       ("prior sample", args.prior_sample)):
        if path is None or not path.is_file():
            parser.error(f"{name} not found: {path}")

    prior = json.loads(args.prior_sample.read_text(encoding="utf-8"))["alerts"]
    excluded = {alert["case_id"] for alert in prior}
    outputs = build(args.semgrep, args.answer_key, exclude_case_ids=excluded,
                    sample_sizes=config.COMPARISON_SAMPLE_SIZES)
    current = {alert["case_id"]
               for alert in outputs["selected_alerts.json"]["alerts"]}
    overlap = sorted(excluded & current)
    if overlap:
        raise ValueError(f"comparison sample overlaps prior sample: {overlap[:5]}")

    args.out.mkdir(parents=True, exist_ok=True)
    for name, value in outputs.items():
        (args.out / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    print(f"Frozen comparison sample: {len(current)} unused cases -> {args.out}")


if __name__ == "__main__":
    main()
