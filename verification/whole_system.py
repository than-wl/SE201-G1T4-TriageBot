"""Whole system vs Semgrep alone, over the full benchmark for the 4 types (free, no model calls).

Semgrep alone: every OWASP Benchmark case whose benchmark CWE is one of the four
measured types (CWE-22, 78, 79, 89), scored with the existing CWE-matched rule
(mapping.cwe_matches, design decision 17):

  TP  real vulnerabilities with a matching alert
  FP  safe cases with a matching alert
  FN  real vulnerabilities with no matching alert

Whole system, projected: Semgrep followed by TriageBot. For each CWE, the finished
step 7 run (the final test; runs 6-before and 6-after) gives two rates:

  keep rate     share of real cases kept (a case sent to a human counts as kept)
  removal rate  share of safe cases removed

They are applied to that CWE's Semgrep counts and summed over the four CWEs:

  kept real = TP x keep rate
  kept safe = FP x (1 - removal rate)
  missed    = FN + TP x (1 - keep rate)

Recall can only fall: TriageBot never sees what Semgrep missed (FN), so its
ceiling is Semgrep's recall. That ceiling is the point of the comparison.

Reads only the recorded scan (config.RECORDED_SCAN), the answer key and the run's
evaluation_by_cwe.json. The answer key is used on the evaluation side only. Writes
evidence/whole_system/<run>.json and .md. Before step 7 has been run it prints
Semgrep alone and says to run step 7 first (nothing is written).

    python verification/whole_system.py --mode council     # run 6-after, D (validated council)
    python verification/whole_system.py --mode single      # run 6-before, B (single agent)
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagebot import config, experiments  # noqa: E402
from triagebot.nodes.ingest.mapping import cwe_matches  # noqa: E402

CWES = config.EVAL_SET_CWES
STEP = "7"                 # the final test's display number (internal step 6)
OUT_DIR = ROOT / "evidence" / "whole_system"
# --mode -> (run of step 7, the configuration that is the whole system's output)
MODES = {
    "council": ("6-after", "D-validated-council"),
    "single": ("6-before", "B-single-agent"),
}
CONFIG_LABELS = {"D-validated-council": "council after deterministic validation (D)",
                 "B-single-agent": "single agent (B)"}
LABEL = "projection: final-test rates applied to the full benchmark for the 4 types"
CEILING = "Recall can only fall: TriageBot never sees what Semgrep missed (FN)."
FORMULA = (
    "For each of the four types, the final-test run gives the share of real vulnerabilities "
    "TriageBot keeps (a case sent to a human counts as kept) and the share of safe cases it "
    "removes. Those rates are applied to Semgrep's results for that type over the whole "
    "benchmark: kept real vulnerabilities are Semgrep's true positives times the keep rate; "
    "kept safe cases are Semgrep's false positives times one minus the removal rate; missed "
    "real vulnerabilities are Semgrep's false negatives plus Semgrep's true positives times "
    "one minus the keep rate. The four types are summed, and precision, recall and F1 are "
    "computed from the sums.")
RERUN = "python verification/whole_system.py --mode {mode}"


class WholeSystemError(RuntimeError):
    """The run is missing, unfinished or not on the final test (the message says what to do)."""


# --- arithmetic (pure) ------------------------------------------------------------------

def prf(tp, fp, fn) -> dict:
    """Precision, recall and F1 from (possibly fractional) counts; None for a zero denominator."""
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if precision is not None and recall is not None else None
    return {"precision": precision, "recall": recall, "f1": f1}


def semgrep_counts(alerts, answer_key, cwes=CWES) -> dict[str, dict]:
    """{cwe: {"tp", "fp", "fn"}} over every benchmark case of each CWE (CWE-matched alerts)."""
    matched = {a["case_id"] for a in alerts
               if a["case_id"] in answer_key and cwe_matches(a["cwe"], answer_key[a["case_id"]]["cwe"])}
    counts = {cwe: {"tp": 0, "fp": 0, "fn": 0} for cwe in cwes}
    for case_id, entry in answer_key.items():
        if entry["cwe"] not in counts:
            continue
        row = counts[entry["cwe"]]
        if case_id in matched:
            row["tp" if entry["vulnerable"] else "fp"] += 1
        elif entry["vulnerable"]:
            row["fn"] += 1
    return counts


def rates_from_evaluation(by_cwe: dict, configuration: str, cwes=CWES) -> dict[str, dict]:
    """{cwe: {"keep_rate", "removal_rate", "real", "safe"}} from evaluation_by_cwe.json's by_cwe.

    Keep rate = 1 - dismissed / real cases (a case sent to a human is kept);
    removal rate = removed / safe cases.
    """
    rates = {}
    for cwe in cwes:
        if cwe not in by_cwe:
            raise WholeSystemError(f"the run's evaluation has no results for {cwe}")
        row = next((r for r in by_cwe[cwe]["configurations"] if r["configuration"] == configuration),
                   None)
        if row is None:
            raise WholeSystemError(f"the run's evaluation has no {configuration} results for {cwe}")
        real, safe = row["genuine_in_sample"], row["fp_in_sample"]
        if not real or not safe:
            raise WholeSystemError(f"{cwe}: the run has {real} real and {safe} safe cases; "
                                   "both rates need at least one of each")
        rates[cwe] = {"keep_rate": 1 - row["genuine_dismissed"] / real,
                      "removal_rate": row["fp_removed"] / safe,
                      "real": real, "safe": safe,
                      "dismissed": row["genuine_dismissed"], "removed": row["fp_removed"]}
    return rates


def project(counts: dict, rates: dict) -> dict:
    """Semgrep alone and the projected whole system, per CWE and summed over the CWEs."""
    per_cwe, alone, whole = {}, {"tp": 0, "fp": 0, "fn": 0}, {"tp": 0.0, "fp": 0.0, "fn": 0.0}
    for cwe, c in counts.items():
        keep, removal = rates[cwe]["keep_rate"], rates[cwe]["removal_rate"]
        kept_real = c["tp"] * keep
        kept_safe = c["fp"] * (1 - removal)
        missed = c["fn"] + c["tp"] * (1 - keep)
        per_cwe[cwe] = {"semgrep": dict(c, **prf(c["tp"], c["fp"], c["fn"])),
                        "rates": rates[cwe],
                        "whole_system": {"kept_real": kept_real, "kept_safe": kept_safe,
                                         "missed": missed, **prf(kept_real, kept_safe, missed)}}
        for key in alone:
            alone[key] += c[key]
        whole["tp"] += kept_real
        whole["fp"] += kept_safe
        whole["fn"] += missed
    return {
        "per_cwe": per_cwe,
        "semgrep_alone": {**alone, **prf(alone["tp"], alone["fp"], alone["fn"])},
        "whole_system": {"kept_real": whole["tp"], "kept_safe": whole["fp"], "missed": whole["fn"],
                         **prf(whole["tp"], whole["fp"], whole["fn"])},
    }


# --- inputs -------------------------------------------------------------------------------

def load_semgrep_alone(scan=None, answer_key_path=None) -> tuple[dict, dict]:
    """(counts per CWE, provenance) from the recorded scan and the answer key."""
    from triagebot.nodes.ingest.answer_key import load_answer_key
    from triagebot.nodes.ingest.normalise import load_semgrep, normalise

    scan = Path(scan or config.RECORDED_SCAN)
    answer_key_path = Path(answer_key_path or config.ANSWER_KEY or "")
    if not answer_key_path.is_file():
        raise WholeSystemError(f"answer key not found: {answer_key_path} (python -m triagebot check "
                               "shows how to get the Benchmark)")
    data, _ = load_semgrep(scan)
    alerts, _ = normalise(data)
    key = load_answer_key(answer_key_path)
    return semgrep_counts(alerts, key), {"scan": _repo_path(scan), "scan_sha256": _sha256(scan),
                                         "answer_key_sha256": _sha256(answer_key_path)}


def load_run(run, out_root=None) -> tuple[dict, dict]:
    """(evaluation_by_cwe["by_cwe"], manifest) for a finished final-test run over the whole set."""
    out_root = Path(out_root or config.EXPERIMENTS_OUT)
    status = experiments.run_status(run, out_root)
    if status["state"] == "none":
        raise WholeSystemError(f"run {run} does not exist yet; run step 7 first: "
                               f"python -m triagebot experiment run {STEP}")
    if status["state"] != "complete" or status["cases_total"] != status["cases_in_set"]:
        raise WholeSystemError(f"run {run} is not finished ({status['cases_saved']} of "
                               f"{status['cases_in_set']} cases); finish step 7 first: "
                               f"python -m triagebot experiment run {STEP}")
    folder = out_root / run
    manifest = json.loads((folder / experiments.MANIFEST).read_text(encoding="utf-8"))
    if manifest["case_set"]["name"] != experiments.FINAL_TEST:
        raise WholeSystemError(f"run {run} is on {manifest['case_set']['name']}, not the final test")
    by_cwe = json.loads((folder / experiments.EVALUATION_BY_CWE).read_text(encoding="utf-8"))["by_cwe"]
    return by_cwe, manifest


def _sha256(path) -> str | None:
    path = Path(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _repo_path(path) -> str:
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


# --- output -------------------------------------------------------------------------------

def _pct(value):
    return "–" if value is None else f"{value:.1%}"


def _n(value):
    return f"{value:,.1f}" if isinstance(value, float) and not value.is_integer() else f"{value:,.0f}"


def semgrep_markdown(counts) -> str:
    total = {k: sum(c[k] for c in counts.values()) for k in ("tp", "fp", "fn")}
    scores = prf(total["tp"], total["fp"], total["fn"])
    lines = ["Semgrep alone, every benchmark case of the 4 types (CWE-matched alerts):", "",
             "| CWE | Real, alert (TP) | Safe, alert (FP) | Real, no alert (FN) | Precision | Recall | F1 |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for cwe, c in counts.items():
        s = prf(c["tp"], c["fp"], c["fn"])
        lines.append(f"| {cwe} | {c['tp']} | {c['fp']} | {c['fn']} | {_pct(s['precision'])} | "
                     f"{_pct(s['recall'])} | {_pct(s['f1'])} |")
    lines.append(f"| **All 4** | **{total['tp']}** | **{total['fp']}** | **{total['fn']}** | "
                 f"**{_pct(scores['precision'])}** | **{_pct(scores['recall'])}** | "
                 f"**{_pct(scores['f1'])}** |")
    return "\n".join(lines)


def render_markdown(report) -> str:
    result, prov = report["result"], report["provenance"]
    alone, whole = result["semgrep_alone"], result["whole_system"]
    lines = [
        f"# Whole system vs Semgrep alone: run `{report['run']}`, {CONFIG_LABELS[report['configuration']]}",
        "",
        f"**{LABEL}.**",
        "",
        "| | Semgrep alone | Whole system (Semgrep, then TriageBot) |",
        "| --- | ---: | ---: |",
        f"| Real vulnerabilities kept | {_n(alone['tp'])} | {_n(whole['kept_real'])} |",
        f"| Safe cases kept (false alarms) | {_n(alone['fp'])} | {_n(whole['kept_safe'])} |",
        f"| Real vulnerabilities missed | {_n(alone['fn'])} | {_n(whole['missed'])} |",
        f"| Precision | {_pct(alone['precision'])} | {_pct(whole['precision'])} |",
        f"| Recall | {_pct(alone['recall'])} | {_pct(whole['recall'])} |",
        f"| F1 | {_pct(alone['f1'])} | {_pct(whole['f1'])} |",
        "",
        CEILING,
        "",
        "## The formula",
        "",
        FORMULA,
        "",
        "## Per type",
        "",
        "| CWE | Semgrep TP | Semgrep FP | Semgrep FN | Keep rate (final test) | Removal rate (final test) "
        "| Kept real | Kept safe | Missed | Precision | Recall |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for cwe, row in result["per_cwe"].items():
        s, r, w = row["semgrep"], row["rates"], row["whole_system"]
        lines.append(
            f"| {cwe} | {s['tp']} | {s['fp']} | {s['fn']} | {_pct(r['keep_rate'])} "
            f"({r['real'] - r['dismissed']} of {r['real']}) | {_pct(r['removal_rate'])} "
            f"({r['removed']} of {r['safe']}) | {_n(w['kept_real'])} | {_n(w['kept_safe'])} | "
            f"{_n(w['missed'])} | {_pct(w['precision'])} | {_pct(w['recall'])} |")
    git = prov["git"]
    first = next(iter(result["per_cwe"].values()))["rates"]
    lines += [
        "",
        "## Caveats",
        "",
        "- A projection, not a measurement: TriageBot reviewed the final test's cases only; "
        "its rates there are assumed to hold for every alert of the same type.",
        f"- Each rate rests on the final test's {first['real']} real and {first['safe']} safe "
        "cases per type, so one case moves a rate by several points.",
        "- Semgrep is scored per case: a case counts once however many matching alerts it has.",
        "",
        "## Provenance",
        "",
        f"- Scan: `{prov['scan']}` (SHA-256 `{(prov['scan_sha256'] or '')[:12]}`); answer key SHA-256 "
        f"`{(prov['answer_key_sha256'] or '')[:12]}` (evaluation side only).",
        f"- Run: `{report['run']}` on case set `{prov['case_set']}` (SHA-256 "
        f"`{prov['case_set_sha256'][:12]}`), commit `{(prov['run_commit'] or 'unknown')[:12]}`.",
        f"- Generated {prov['date']} by `{RERUN.format(mode=report['mode'])}` at commit "
        f"`{(git.get('commit') or 'unknown')[:12]}`" + (" with uncommitted changes." if git.get("dirty") else "."),
        "",
    ]
    return "\n".join(lines)


def build(mode, out_root=None, scan=None, answer_key=None) -> dict:
    run, configuration = MODES[mode]
    counts, prov = load_semgrep_alone(scan, answer_key)
    by_cwe, manifest = load_run(run, out_root)
    result = project(counts, rates_from_evaluation(by_cwe, configuration))
    return {
        "run": run, "mode": mode, "configuration": configuration, "label": LABEL,
        "ceiling": CEILING, "formula": FORMULA, "result": result,
        "provenance": {**prov, "case_set": manifest["case_set"]["name"],
                       "case_set_sha256": manifest["case_set"]["sha256"],
                       "run_commit": (manifest.get("git") or {}).get("commit"),
                       "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       "git": experiments.git_state()},
    }


def write(report, out_dir=None) -> tuple[Path, Path]:
    out_dir = Path(out_dir or OUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path, md_path = out_dir / f"{report['run']}.json", out_dir / f"{report['run']}.md"
    with json_path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    with md_path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(render_markdown(report))
    return json_path, md_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--mode", choices=tuple(MODES), default="council",
                        help="council: run 6-after, D (validated council); single: run 6-before, B")
    parser.add_argument("--answer-key", help="expectedresults-1.2.csv (default: under BENCHMARK_ROOT)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    try:
        counts, _ = load_semgrep_alone(answer_key_path=args.answer_key)
    except (WholeSystemError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        report = build(args.mode, answer_key=args.answer_key)
    except WholeSystemError as exc:
        print(semgrep_markdown(counts))
        print()
        print(f"Whole system: not available yet. {exc}")
        return 0
    print(render_markdown(report))
    json_path, md_path = write(report)
    print(f"Wrote {_repo_path(json_path)} and {_repo_path(md_path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
