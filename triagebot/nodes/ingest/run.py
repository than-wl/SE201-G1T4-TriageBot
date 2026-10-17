"""Ingest + scanner baseline command (engine for menu option 1).

Usage, from the repository root:
    py -m triagebot.nodes.ingest.run [--semgrep PATH] [--answer-key PATH] [--out DIR]

Writes to --out:
  LLM side (NormalisedAlert fields only, no answer-key data):
    alerts.json               every normalised alert
    selected_alerts.json      {"selection": {...}, "alerts": [...]}: the checkpoint sample
    ingest_report.json        counts from normalisation
  EVALUATION SIDE (derived from the answer key; never sent to a model):
    split.json                seed, fraction, per-stratum counts, sample composition, assignment
    scanner_predictions.json  {"file": {case: bool}, "cwe": {case: bool}}
    baseline.json             per-category metrics for both modes, CWE mismatch report
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from triagebot import config
from triagebot.nodes.ingest.answer_key import load_answer_key
from triagebot.nodes.ingest.mapping import (ACCEPTED_CWE_EQUIVALENTS, MODES,
                                            mismatch_report, scanner_predictions)
from triagebot.nodes.ingest.normalise import load_semgrep, normalise
from triagebot.nodes.ingest.split import assign_split, select_sample, stratum_counts
from triagebot.nodes.score.metrics import by_category
from triagebot.schemas import NormalisedAlert

MODE_DESCRIPTIONS = {
    "file": "case flagged if it has any alert",
    "cwe": "case flagged only if an alert's CWE matches the benchmark CWE (or an accepted equivalent)",
}
SAMPLE_RULE = ("dev-split cases whose benchmark CWE is {cwe} and that have a CWE-matching alert; "
               "one alert per case (lowest start_line, then rule_id); cases drawn with the sample "
               "seed, balanced on the evaluation side (composition recorded in split.json)")


def assert_llm_safe(alerts):
    """Raise unless every alert has exactly the NormalisedAlert fields."""
    fields = set(NormalisedAlert.__annotations__)
    for alert in alerts:
        if set(alert) != fields:
            raise ValueError(f"non-NormalisedAlert fields in LLM-side output: {sorted(set(alert) ^ fields)}")


def build(semgrep_path, answer_key_path, seed=config.SPLIT_SEED,
          test_fraction=config.TEST_FRACTION, sample_cwe=config.SAMPLE_CWE,
          sample_size=config.SAMPLE_SIZE) -> dict:
    """Run ingest, mapping, split and sample; return {filename: JSON-ready data}."""
    data, scan_date = load_semgrep(semgrep_path)
    alerts, report = normalise(data, scan_date)
    key = load_answer_key(answer_key_path)

    predictions = {mode: scanner_predictions(alerts, key, mode) for mode in MODES}
    split = assign_split(key, seed, test_fraction)
    sample, composition = select_sample(alerts, key, split, sample_cwe, sample_size, seed)
    assert_llm_safe(alerts)
    assert_llm_safe(sample)

    vulnerable = sum(entry["vulnerable"] for entry in key.values())
    flagged = {a["case_id"] for a in alerts}
    selection = {"rule": SAMPLE_RULE.format(cwe=sample_cwe), "cwe": sample_cwe,
                 "split_seed": seed, "test_fraction": test_fraction, "sample_seed": seed,
                 "requested": sample_size, "selected": len(sample),
                 "shortfall": composition["shortfall"]}
    return {
        "alerts.json": alerts,
        "selected_alerts.json": {"selection": selection, "alerts": sample},
        "ingest_report.json": report,
        "split.json": {
            "seed": seed, "test_fraction": test_fraction,
            "totals": {part: sum(v == part for v in split.values()) for part in ("dev", "test")},
            "strata": stratum_counts(key, split),
            "sample": composition,
            "assignment": split,
        },
        "scanner_predictions.json": predictions,
        "baseline.json": {
            "semgrep_version": report["semgrep_version"],
            "scan_date": report["scan_date"],
            "run_timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "answer_key": {"cases": len(key), "vulnerable": vulnerable, "safe": len(key) - vulnerable},
            "cases_without_alerts": len(set(key) - flagged),
            "category_cwe": dict(sorted({e["category"]: e["cwe"] for e in key.values()}.items())),
            "accepted_cwe_equivalents": {k: sorted(v) for k, v in sorted(ACCEPTED_CWE_EQUIVALENTS.items())},
            "modes": {mode: {"description": MODE_DESCRIPTIONS[mode],
                             "by_category": by_category(predictions[mode], key)} for mode in MODES},
            "cwe_mismatches": mismatch_report(alerts, key),
        },
    }


def write_outputs(outputs: dict, out_dir) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        (out / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return out


def _pct(value):
    return "n/a" if value is None else f"{value:.1%}"


def metrics_table(rows: dict, category_cwe: dict) -> str:
    lines = ["| Category | CWE | Cases | TP | FP | FN | TN | Precision | Recall | F1 |",
             "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name, r in rows.items():
        label = "**overall**" if name == "overall" else name
        lines.append(f"| {label} | {category_cwe.get(name, '')} | {r['cases']} | {r['tp']} | {r['fp']} "
                     f"| {r['fn']} | {r['tn']} | {_pct(r['precision'])} | {_pct(r['recall'])} | {_pct(r['f1'])} |")
    return "\n".join(lines)


def mismatch_table(rows: list, limit=10) -> str:
    lines = ["| Category | Benchmark CWE | Semgrep CWE | Alerts | Cases | Cases w/o match | Rule ids |",
             "| --- | --- | --- | ---: | ---: | ---: | --- |"]
    for r in rows[:limit]:
        rules = ", ".join(f"{rule} ({n})" for rule, n in r["rule_ids"].items())
        lines.append(f"| {r['category']} | {r['benchmark_cwe']} | {r['semgrep_cwe'] or '(none)'} "
                     f"| {r['alerts']} | {r['cases']} | {r['cases_without_matching_alert']} | {rules} |")
    return "\n".join(lines)


def summary(outputs: dict) -> str:
    rep, base = outputs["ingest_report.json"], outputs["baseline.json"]
    sample = outputs["split.json"]["sample"]
    key = base["answer_key"]
    parts = [
        f"Ingest: Semgrep {rep['semgrep_version']}, scan date {rep['scan_date']} (file mtime)",
        f"  findings: {rep['total_findings']} total, {rep['test_file_findings']} in test files, "
        f"{rep['helper_file_findings_dropped']['count']} helper-file dropped, "
        f"{rep['unmapped_paths']['count']} unmapped",
        f"  alerts: {rep['alerts']} after collapsing {rep['exact_duplicates_collapsed']} exact duplicates; "
        f"{rep['cases_with_alerts']} cases with >= 1 alert",
        f"  no CWE: {rep['alerts_without_cwe']}; multiple CWEs: {rep['alerts_with_multiple_cwes']['count']}; "
        f"Semgrep errors: {rep['semgrep_errors']}",
        f"Answer key: {key['cases']} cases ({key['vulnerable']} vulnerable / {key['safe']} safe); "
        f"{base['cases_without_alerts']} cases with no alert",
    ]
    for mode in MODES:
        parts += ["", f"Scanner baseline, mode \"{mode}\" ({base['modes'][mode]['description']})", "",
                  metrics_table(base["modes"][mode]["by_category"], base["category_cwe"])]
    parts += ["", f"Top 10 CWE mismatch pairs ({len(base['cwe_mismatches'])} pairs in total)", "",
              mismatch_table(base["cwe_mismatches"]),
              "",
              f"Checkpoint sample: {sample['selected']} of {sample['requested']} requested {sample['cwe']} "
              f"dev cases ({sample['selected_vulnerable']} vulnerable / {sample['selected_safe']} safe; "
              f"eligible {sample['eligible_vulnerable']} / {sample['eligible_safe']}); "
              f"shortfall {sample['shortfall']}"]
    return "\n".join(parts)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Normalise Semgrep output and score the scanner baseline.")
    parser.add_argument("--semgrep", default=str(config.SEMGREP_JSON), help="Semgrep JSON output")
    parser.add_argument("--answer-key", default=str(config.ANSWER_KEY) if config.ANSWER_KEY else None,
                        help="expectedresults-1.2.csv (default: under BENCHMARK_ROOT)")
    parser.add_argument("--out", default=str(config.CHECKPOINT_OUT), help="output directory")
    args = parser.parse_args(argv)
    if not args.answer_key:
        parser.error("answer key unknown: pass --answer-key or set BENCHMARK_ROOT")

    outputs = build(args.semgrep, args.answer_key)
    out = write_outputs(outputs, args.out)
    print(summary(outputs))
    print(f"\nWrote {', '.join(outputs)} to {out}")
    return outputs


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        sys.exit(f"Ingest failed: {error}")
