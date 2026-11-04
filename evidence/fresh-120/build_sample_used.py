"""Exact one-off builder used for the 2 November fresh 120-case sample.

This archival script records the original local paths and construction logic.
The generated evidence files are already committed beside it.
"""

import json
from pathlib import Path

from triagebot import config
from triagebot.nodes.ingest.final_sample import build


ROOT = Path("Context/tmp")
OUT = ROOT / "fresh-120-latest"
PRIOR_SAMPLES = (
    ROOT / "final" / "selected_alerts.json",
    ROOT / "comparison" / "selected_alerts.json",
)
SIZES = {
    "CWE-22": 24,
    "CWE-78": 24,
    "CWE-79": 24,
    "CWE-89": 24,
    "CWE-501": 12,
    "CWE-643": 12,
}


used = set()
for sample_path in PRIOR_SAMPLES:
    payload = json.loads(sample_path.read_text(encoding="utf-8"))
    used.update(alert["case_id"] for alert in payload["alerts"])

outputs = build(
    config.RECORDED_SCAN,
    ROOT / "BenchmarkJava" / "expectedresults-1.2.csv",
    exclude_case_ids=used,
    sample_sizes=SIZES,
)
OUT.mkdir(parents=True, exist_ok=True)
for name, value in outputs.items():
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

print(f"Frozen {len(outputs['selected_alerts.json']['alerts'])} cases in {OUT}")
