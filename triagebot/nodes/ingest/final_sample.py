"""Build the frozen, held-out multi-category final sample.

The model-side file contains only NormalisedAlert fields. Labels are used only
to balance selection and are written only as aggregate evaluation metadata.
"""

import argparse
import json
from pathlib import Path

from triagebot import config
from triagebot.nodes.ingest.answer_key import load_answer_key
from triagebot.nodes.ingest.normalise import load_semgrep, normalise
from triagebot.nodes.ingest.run import assert_llm_safe
from triagebot.nodes.ingest.split import assign_split, select_categories


def build(semgrep_path, answer_key_path) -> dict[str, dict]:
    raw, scan_date = load_semgrep(semgrep_path)
    alerts, report = normalise(raw, config.recorded_scan_date(semgrep_path) or scan_date)
    key = load_answer_key(answer_key_path)
    assignment = assign_split(key, config.SPLIT_SEED, config.TEST_FRACTION)
    sample, composition = select_categories(
        alerts, key, assignment, config.FINAL_SAMPLE_SIZES,
        config.SPLIT_SEED, partition=config.FINAL_PARTITION)
    assert_llm_safe(sample)
    if len(sample) != sum(config.FINAL_SAMPLE_SIZES.values()):
        raise ValueError(f"final sample is short: selected {len(sample)}")
    selection = {
        "status": "frozen",
        "partition": config.FINAL_PARTITION,
        "split_seed": config.SPLIT_SEED,
        "test_fraction": config.TEST_FRACTION,
        "sample_seed": config.SPLIT_SEED,
        "categories": config.FINAL_SAMPLE_SIZES,
        "selected": len(sample),
        "rule": "one CWE-matching Semgrep alert per case, balanced by label on the evaluation side",
    }
    return {
        "selected_alerts.json": {"selection": selection, "alerts": sample},
        "final_sample_manifest.json": {
            "selection": selection,
            "composition": composition,
            "semgrep_version": report["semgrep_version"],
            "scan_date": report["scan_date"],
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semgrep", type=Path, default=config.RECORDED_SCAN)
    parser.add_argument("--answer-key", type=Path, default=config.ANSWER_KEY)
    parser.add_argument("--out", type=Path, default=config.FINAL_OUT)
    args = parser.parse_args(argv)
    if args.answer_key is None or not args.answer_key.is_file():
        parser.error("answer key not found; set BENCHMARK_ROOT or pass --answer-key")
    outputs = build(args.semgrep, args.answer_key)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, value in outputs.items():
        (args.out / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    print(f"Frozen final sample: {len(outputs['selected_alerts.json']['alerts'])} cases -> {args.out}")


if __name__ == "__main__":
    main()
