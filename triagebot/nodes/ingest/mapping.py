"""Scanner-only predictions per benchmark case. EVALUATION SIDE ONLY.

Joins normalised alerts with the answer key, so nothing here may reach a
payload or prompt.

Two prediction modes for every benchmark case:
- "file": vulnerable if the case has ANY alert (the proposal's
  preliminary method).
- "cwe":  vulnerable only if some alert's CWE equals the case's benchmark
  CWE or one of its ACCEPTED_CWE_EQUIVALENTS.
"""

from collections import Counter, defaultdict

from triagebot.schemas import AnswerKeyEntry, NormalisedAlert

MODES = ("file", "cwe")

# Benchmark CWE -> extra Semgrep CWEs counted as the same weakness.
# Entries are added only by a team decision taken from the mismatch report
# (docs/DESIGN_DECISIONS.md, decision 17), never by code.
#
# Accepted:
#   CWE-327 <- CWE-326: Semgrep's DES/DESede rules tag CWE-326 (inadequate
#     encryption strength) for the same code pattern the Benchmark labels
#     CWE-327 (broken/risky algorithm).
# Rejected:
#   CWE-501 <- CWE-79: different weakness; the XSS response-writer rule fires
#     on trust-boundary tests because they also write to the response.
#   CWE-89 / CWE-643 <- CWE-79: different weakness; every such case also has
#     a matching alert, so accepting it would not change any prediction.
ACCEPTED_CWE_EQUIVALENTS: dict[str, set[str]] = {"CWE-327": {"CWE-326"}}


def cwe_matches(alert_cwe: str, benchmark_cwe: str) -> bool:
    return bool(alert_cwe) and (
        alert_cwe == benchmark_cwe
        or alert_cwe in ACCEPTED_CWE_EQUIVALENTS.get(benchmark_cwe, set()))


def _check_known(alerts, answer_key):
    unknown = sorted({a["case_id"] for a in alerts} - set(answer_key))
    if unknown:
        raise ValueError(f"alerts for cases missing from the answer key: {', '.join(unknown[:10])}")


def scanner_predictions(alerts: list[NormalisedAlert],
                        answer_key: dict[str, AnswerKeyEntry],
                        mode: str) -> dict[str, bool]:
    """{case_id: predicted vulnerable} for every case in the answer key."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    _check_known(alerts, answer_key)
    flagged = set()
    for alert in alerts:
        if mode == "file" or cwe_matches(alert["cwe"], answer_key[alert["case_id"]]["cwe"]):
            flagged.add(alert["case_id"])
    return {case_id: case_id in flagged for case_id in sorted(answer_key)}


def mismatch_report(alerts: list[NormalisedAlert],
                    answer_key: dict[str, AnswerKeyEntry]) -> list[dict]:
    """Alerts whose CWE does not match their case, grouped by CWE pair.

    One row per (benchmark category, benchmark CWE, Semgrep CWE), sorted
    by alert count. "cases_without_matching_alert" counts cases where no
    other alert matches either: only those would change "cwe"-mode
    predictions if the pair were accepted as equivalent.
    """
    _check_known(alerts, answer_key)
    matched_cases = {a["case_id"] for a in alerts
                     if cwe_matches(a["cwe"], answer_key[a["case_id"]]["cwe"])}
    groups = defaultdict(lambda: {"alerts": 0, "cases": set(), "rule_ids": Counter()})
    for alert in alerts:
        entry = answer_key[alert["case_id"]]
        if cwe_matches(alert["cwe"], entry["cwe"]):
            continue
        group = groups[entry["category"], entry["cwe"], alert["cwe"]]
        group["alerts"] += 1
        group["cases"].add(alert["case_id"])
        group["rule_ids"][alert["rule_id"]] += 1

    rows = []
    for (category, benchmark_cwe, semgrep_cwe), group in groups.items():
        cases = group["cases"]
        unmatched = cases - matched_cases
        rows.append({
            "category": category,
            "benchmark_cwe": benchmark_cwe,
            "semgrep_cwe": semgrep_cwe,
            "alerts": group["alerts"],
            "cases": len(cases),
            "cases_without_matching_alert": len(unmatched),
            "vulnerable_cases_without_matching_alert":
                sum(answer_key[c]["vulnerable"] for c in unmatched),
            "rule_ids": dict(sorted(group["rule_ids"].items(), key=lambda kv: (-kv[1], kv[0]))),
        })
    return sorted(rows, key=lambda r: (-r["alerts"], r["category"], r["semgrep_cwe"]))
