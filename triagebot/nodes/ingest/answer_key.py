"""OWASP Benchmark answer-key loader. EVALUATION SIDE ONLY.

The answer key (expectedresults-1.2.csv) is ground truth. Nothing loaded
here may reach a payload, prompt or LLM-side output file (alerts.json,
selected_alerts.json); see docs/DESIGN_DECISIONS.md, decision 7.

CSV rows: test name, category, real vulnerability (true/false), CWE number.
Lines whose first cell starts with "#" are comments.
"""

import csv
from pathlib import Path
import re

from triagebot.schemas import AnswerKeyEntry

_CASE_RE = re.compile(r"BenchmarkTest\d{5}")


def load_answer_key(csv_path) -> dict[str, AnswerKeyEntry]:
    """Return {case_id: {"category", "cwe": "CWE-NN", "vulnerable"}}.

    Raises ValueError on a malformed row or a repeated case id.
    """
    path = Path(csv_path)
    key: dict[str, AnswerKeyEntry] = {}
    with path.open(encoding="utf-8", newline="") as stream:
        for number, row in enumerate(csv.reader(stream), start=1):
            if not row or not "".join(row).strip() or row[0].lstrip().startswith("#"):
                continue
            cells = [cell.strip() for cell in row]
            where = f"{path}:{number}"
            if len(cells) != 4:
                raise ValueError(f"{where}: expected 4 columns, got {len(cells)}")
            case_id, category, real, cwe = cells
            if not _CASE_RE.fullmatch(case_id):
                raise ValueError(f"{where}: bad test name {case_id!r}")
            if not category:
                raise ValueError(f"{where}: empty category")
            if real.lower() not in ("true", "false"):
                raise ValueError(f"{where}: real vulnerability must be true or false")
            if not cwe.isdigit():
                raise ValueError(f"{where}: CWE must be a number, got {cwe!r}")
            if case_id in key:
                raise ValueError(f"{where}: duplicate case id {case_id}")
            key[case_id] = {"category": category, "cwe": f"CWE-{int(cwe)}",
                            "vulnerable": real.lower() == "true"}
    return key
