"""Normalise Semgrep JSON into the shared NormalisedAlert shape (LLM side).

This module never reads the OWASP answer key: everything it produces may
flow into payloads and prompts. Answer-key work lives in answer_key.py,
mapping.py and split.py (evaluation side only).

- case_id_from_path() / to_relative(): locate a finding in the benchmark.
- extract_cwe(): first CWE id from a rule's metadata, or "".
- normalise(): one alert per distinct test-file finding, plus a report
  that counts everything dropped or collapsed (nothing is lost silently).
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import re

from triagebot.schemas import NormalisedAlert

_CASE_RE = re.compile(r"(?:^|/)testcode/(BenchmarkTest\d{5})\.java$")
_RELATIVE_RE = re.compile(r"(?:^|/)(src/main/java/.+)$")
_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_MAX_EXAMPLES = 10


def _slashes(path: str) -> str:
    return path.replace("\\", "/")


def case_id_from_path(path: str) -> str | None:
    """"BenchmarkTestNNNNN" for a file in .../testcode/, else None."""
    match = _CASE_RE.search(_slashes(path))
    return match.group(1) if match else None


def to_relative(path: str) -> str | None:
    """Path from "src/main/java/" onward with forward slashes, else None.

    payload.py joins this onto BENCHMARK_ROOT, so it must be relative to
    the benchmark root whatever directory the scan was run from.
    """
    match = _RELATIVE_RE.search(_slashes(path))
    return match.group(1) if match else None


def _cwe_list(metadata) -> list[str]:
    """Every CWE id in metadata["cwe"] (list, single string, or missing)."""
    raw = (metadata or {}).get("cwe")
    if raw is None:
        return []
    items = [raw] if isinstance(raw, str) else list(raw)
    found = []
    for item in items:
        match = _CWE_RE.search(str(item))
        if match:
            cwe = f"CWE-{int(match.group(1))}"
            if cwe not in found:
                found.append(cwe)
    return found


def extract_cwe(metadata) -> str:
    """First CWE id as "CWE-89", or "" when the rule declares none."""
    cwes = _cwe_list(metadata)
    return cwes[0] if cwes else ""


def load_semgrep(path) -> tuple[dict, str]:
    """Read Semgrep JSON; return (data, file modification time as ISO UTC)."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    mtime = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    return data, mtime.isoformat(timespec="seconds")


def normalise(semgrep_json: dict, scan_date: str | None = None
              ) -> tuple[list[NormalisedAlert], dict]:
    """Return (alerts sorted by case/line/rule, ingest report).

    Duplicate policy: findings with the same (case_id, rule_id, start_line)
    are one alert (the first is kept). Different rules or lines on the
    same case stay separate alerts. Helper-file and unrecognised paths are
    dropped and counted.
    """
    results = semgrep_json.get("results", [])
    alerts: dict[tuple, NormalisedAlert] = {}
    helper, unmapped, multi = [], [], []
    test_findings = duplicates = 0

    for finding in results:
        path = finding.get("path", "")
        relative, case_id = to_relative(path), case_id_from_path(path)
        if relative is None:
            unmapped.append(_slashes(path))
            continue
        if case_id is None:
            helper.append(relative)
            continue
        test_findings += 1
        extra = finding.get("extra", {})
        cwes = _cwe_list(extra.get("metadata"))
        alert: NormalisedAlert = {
            "case_id": case_id,
            "file": relative,
            "rule_id": finding.get("check_id", ""),
            "cwe": cwes[0] if cwes else "",
            "start_line": int(finding["start"]["line"]),
            "end_line": int(finding["end"]["line"]),
            "message": str(extra.get("message", "")).strip(),
        }
        key = (case_id, alert["rule_id"], alert["start_line"])
        if key in alerts:
            duplicates += 1
            continue
        alerts[key] = alert
        if len(cwes) > 1:
            multi.append({"case_id": case_id, "rule_id": alert["rule_id"],
                          "kept": cwes[0], "dropped": cwes[1:]})

    ordered = sorted(alerts.values(),
                     key=lambda a: (a["case_id"], a["start_line"], a["rule_id"]))
    report = {
        "semgrep_version": semgrep_json.get("version"),
        "scan_date": scan_date,
        "scan_date_source": "Semgrep JSON file modification time",
        "total_findings": len(results),
        "test_file_findings": test_findings,
        "helper_file_findings_dropped": {"count": len(helper),
                                         "examples": sorted(set(helper))[:_MAX_EXAMPLES]},
        "unmapped_paths": {"count": len(unmapped),
                           "examples": sorted(set(unmapped))[:_MAX_EXAMPLES]},
        "exact_duplicates_collapsed": duplicates,
        "alerts": len(ordered),
        "alerts_without_cwe": sum(1 for a in ordered if not a["cwe"]),
        "alerts_with_multiple_cwes": {"count": len(multi), "details": multi},
        "cases_with_alerts": len({a["case_id"] for a in ordered}),
        "semgrep_errors": len(semgrep_json.get("errors", [])),
    }
    return ordered, report
