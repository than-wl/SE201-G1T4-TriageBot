"""Evaluation harness (owner: Bradley).

Joins saved run results with the hidden answer key and computes the
checkpoint metrics (retained / removed / wrongly dismissed / human-review
rate, latency, cost). Runs outside the LLM-facing pipeline: the answer
key enters only here and never appears in any payload or prompt.
Offline and deterministic: the same saved inputs give byte-identical output.

Usage, from the repository root:
    py -m triagebot.nodes.score.evaluate --labels L --cases C --config NAME=PATH [--config ...]

  --labels  official expectedresults-1.2.csv, or a list of {"case_id", "vulnerable": bool}
  --cases   the selected sample: a list of case IDs, or Darren's normalised alerts (duplicates collapse)
  --config  NAME=PATH, repeatable. PATH holds a list of triage results, or {"model": ..., "results": [...]}
            (Lisa's validator output has this shape). Each result needs "case_id" and "verdict"; optional
            "validation_errors" (list), "validated" (bool), "latency_seconds", and
            "usage" {"prompt_tokens", "completion_tokens", "cost"}. Council results should carry the
            summed usage of all three roles.

The scanner-only baseline (A) is added automatically: every finding in the sample is kept.
"""
import argparse
import csv
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = ROOT / "Context/tmp/checkpoint/evaluation.json"
VERDICTS = ("true_positive", "false_positive", "human_review")
SCANNER = "A-scanner-only"
OUTCOMES = {  # (label is vulnerable, verdict) -> outcome
    (True, "true_positive"): "genuine_retained",
    (True, "false_positive"): "genuine_dismissed",
    (True, "human_review"): "genuine_human_review",
    (False, "false_positive"): "fp_removed",
    (False, "true_positive"): "fp_retained",
    (False, "human_review"): "fp_human_review",
}
CORRECT = {"genuine_retained", "fp_removed"}


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_labels(path):
    """Return {case_id: is_vulnerable}."""
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8", newline="") as stream:
            rows = [row for row in csv.reader(stream) if row and not row[0].startswith("#")]
        pairs = [(row[0].strip(), row[2].strip().lower()) for row in rows]
        if any(value not in ("true", "false") for _, value in pairs):
            raise ValueError(f"{path}: 'real vulnerability' column must be true or false")
        pairs = [(case_id, value == "true") for case_id, value in pairs]
    else:
        pairs = [(row["case_id"], row["vulnerable"]) for row in load_json(path)]
        if any(type(vulnerable) is not bool for _, vulnerable in pairs):
            raise ValueError(f"{path}: 'vulnerable' must be true or false")
    labels = dict(pairs)
    if len(labels) != len(pairs):
        raise ValueError(f"{path}: duplicate case_id in answer key")
    return labels


def load_cases(path):
    data = load_json(path)
    if isinstance(data, dict):
        data = data.get("cases", data.get("alerts"))
    return sorted({item["case_id"] if isinstance(item, dict) else item for item in data})


def load_results(path):
    data = load_json(path)
    if isinstance(data, list):
        return data, None
    return data["results"], data.get("model")


def scanner_only(cases):
    return [{"case_id": case_id, "verdict": "true_positive"} for case_id in cases]


def problems(result):
    if result is None:
        return ["missing result"]
    reasons = []
    if result.get("verdict") not in VERDICTS:
        reasons.append(f"unsupported verdict: {result.get('verdict')!r}")
    errors = [str(error) for error in result.get("validation_errors") or []]
    if result.get("validated") is False and not errors:
        errors = ["failed validation (no reason given)"]
    return reasons + errors


def rate(part, whole):
    return round(part / whole, 4) if whole else None


def numbers(values):
    return [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]


def usage_summary(results):
    latencies = numbers(r.get("latency_seconds") for r in results)
    usage = [r.get("usage") or {} for r in results]
    summary = {"latency_reported": len(latencies),
               "latency_mean_seconds": round(sum(latencies) / len(latencies), 3) if latencies else None,
               "latency_max_seconds": max(latencies) if latencies else None}
    for key in ("prompt_tokens", "completion_tokens", "cost"):
        values = numbers(u.get(key) for u in usage)
        summary[key + "_reported"] = len(values)
        summary[key + "_total"] = round(sum(values), 6) if values else None
    return summary


def score(name, cases, labels, results, model=None):
    unlabelled = [case_id for case_id in cases if case_id not in labels]
    if unlabelled:
        raise ValueError(f"No answer-key label for: {', '.join(unlabelled)}")
    by_case, malformed = {}, 0
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("case_id"), str):
            malformed += 1
        elif result["case_id"] in by_case:
            raise ValueError(f"{name}: duplicate result for {result['case_id']}")
        else:
            by_case[result["case_id"]] = result

    counts = dict.fromkeys(OUTCOMES.values(), 0)
    invalid, missing, failures = 0, 0, []
    for case_id in cases:
        result = by_case.get(case_id)
        reasons = problems(result)
        missing += result is None
        invalid += bool(reasons)
        # Missing or unreadable verdicts fall back to human review, never to a removal.
        verdict = result["verdict"] if result and result.get("verdict") in VERDICTS else "human_review"
        outcome = OUTCOMES[labels[case_id], verdict]
        counts[outcome] += 1
        if outcome not in CORRECT or reasons:
            failures.append({"case_id": case_id, "outcome": outcome, "verdict": verdict,
                             "expected": "true_positive" if labels[case_id] else "false_positive",
                             "reasons": reasons, "explanation": (result or {}).get("explanation")})

    total = len(cases)
    genuine = sum(labels[case_id] for case_id in cases)
    human = counts["genuine_human_review"] + counts["fp_human_review"]
    scored = [by_case[case_id] for case_id in cases if case_id in by_case]
    return {
        "configuration": name, "model": model,
        "evaluated_findings": total, "genuine_in_sample": genuine, "fp_in_sample": total - genuine,
        **counts,
        "human_review": human, "invalid_outputs": invalid, "missing_results": missing,
        "genuine_retained_rate": rate(counts["genuine_retained"], genuine),
        "genuine_dismissed_rate": rate(counts["genuine_dismissed"], genuine),
        "fp_removed_rate": rate(counts["fp_removed"], total - genuine),
        "human_review_rate": rate(human, total),
        "invalid_output_rate": rate(invalid, total),
        "malformed_results": malformed,
        "results_outside_sample": sorted(set(by_case) - set(cases)),
        "usage": usage_summary(scored),
        "failures": failures,
    }


def evaluate(cases, labels, configs, include_scanner=True):
    """configs: {name: (results, model)}. Returns the full report as plain JSON-ready data."""
    cases = sorted(set(cases))
    runs = ({SCANNER: (scanner_only(cases), None)} if include_scanner else {}) | configs
    coverage = {name: sorted({r.get("case_id") for r in results if isinstance(r, dict)} & set(cases))
                for name, (results, _) in configs.items()}
    return {
        "note": "Initial checkpoint sample, not a general accuracy estimate.",
        "sample_size": len(cases),
        "same_case_coverage": len({tuple(ids) for ids in coverage.values()}) <= 1,
        "configurations": [score(name, cases, labels, *runs[name]) for name in sorted(runs)],
    }


def percent(value):
    return "n/a" if value is None else f"{value:.1%}"


def markdown_table(report):
    rows = [
        ("Evaluated findings", "evaluated_findings", str),
        ("Genuine findings retained", "genuine_retained", str),
        ("Genuine wrongly dismissed", "genuine_dismissed", str),
        ("Genuine sent to human review", "genuine_human_review", str),
        ("False positives removed", "fp_removed", str),
        ("False positives retained", "fp_retained", str),
        ("False positives sent to human review", "fp_human_review", str),
        ("Genuine retained rate", "genuine_retained_rate", percent),
        ("False-positive removal rate", "fp_removed_rate", percent),
        ("Human-review rate", "human_review_rate", percent),
        ("Invalid-output rate", "invalid_output_rate", percent),
        ("Missing results", "missing_results", str),
    ]
    configs = report["configurations"]
    lines = ["| Metric | " + " | ".join(c["configuration"] for c in configs) + " |",
             "| --- |" + " --- |" * len(configs)]
    lines += [f"| {label} | " + " | ".join(fmt(c[key]) for c in configs) + " |" for label, key, fmt in rows]
    for label, key in (("Mean latency (s)", "latency_mean_seconds"), ("Total cost (USD)", "cost_total")):
        lines.append(f"| {label} | " + " | ".join(
            "n/a" if c["usage"][key] is None else str(c["usage"][key]) for c in configs) + " |")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Score saved TriageBot results against the answer key.")
    parser.add_argument("--labels", required=True, help="expectedresults CSV or labels JSON")
    parser.add_argument("--cases", required=True, help="selected sample: case IDs or normalised alerts")
    parser.add_argument("--config", action="append", default=[], metavar="NAME=PATH",
                        help="saved results for one configuration, e.g. C-council=council.json")
    parser.add_argument("--no-scanner", action="store_true", help="omit the scanner-only baseline")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="where to write the JSON report")
    args = parser.parse_args(argv)

    configs = {}
    for item in args.config:
        name, sep, path = item.partition("=")
        if not sep or not name or name in configs or name == SCANNER:
            parser.error(f"bad or repeated --config {item!r}; use NAME=PATH")
        configs[name] = load_results(path)
    report = evaluate(load_cases(args.cases), load_labels(args.labels), configs, not args.no_scanner)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(markdown_table(report))
    if not report["same_case_coverage"]:
        print("\nWarning: configurations do not cover the same cases; see missing_results.")
    print(f"\nReport: {out}")
    return report


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        sys.exit(f"Evaluation failed: {error}")
