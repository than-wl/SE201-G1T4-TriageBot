"""verification/whole_system.py: Semgrep alone vs the projected whole system (offline).

A tiny hand-made benchmark and run evaluation; no model calls, no real scan or
answer key, and no catalogue or embedder.
"""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from triagebot import config, experiments

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verification"))
import whole_system as ws  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "ingest"


def key_entry(cwe, vulnerable):
    return {"cwe": cwe, "vulnerable": vulnerable, "category": "x"}


def cwe_row(configuration, real, dismissed, safe, removed):
    return {"configuration": configuration, "genuine_in_sample": real, "genuine_dismissed": dismissed,
            "fp_in_sample": safe, "fp_removed": removed}


class Arithmetic(unittest.TestCase):
    def test_semgrep_counts_use_cwe_matched_alerts_per_case(self):
        key = {"T1": key_entry("CWE-89", True), "T2": key_entry("CWE-89", True),
               "T3": key_entry("CWE-89", False), "T4": key_entry("CWE-89", False),
               "T5": key_entry("CWE-79", True), "T6": key_entry("CWE-327", True)}
        alerts = [{"case_id": "T1", "cwe": "CWE-89"}, {"case_id": "T1", "cwe": "CWE-89"},  # one case, once
                  {"case_id": "T2", "cwe": "CWE-79"},          # wrong CWE: no matching alert
                  {"case_id": "T3", "cwe": "CWE-89"},          # safe case with a matching alert
                  {"case_id": "T6", "cwe": "CWE-326"}]         # another type: not counted
        counts = ws.semgrep_counts(alerts, key, ("CWE-79", "CWE-89"))
        self.assertEqual(counts, {"CWE-79": {"tp": 0, "fp": 0, "fn": 1},
                                  "CWE-89": {"tp": 1, "fp": 1, "fn": 1}})

    def test_projection_on_a_hand_made_example(self):
        # CWE-89: Semgrep 10 TP, 10 FP, 5 FN; the run kept 3 of 4 real and removed 3 of 4 safe.
        # CWE-79: Semgrep 20 TP, 0 FP, 0 FN; the run kept every real case.
        counts = {"CWE-79": {"tp": 20, "fp": 0, "fn": 0}, "CWE-89": {"tp": 10, "fp": 10, "fn": 5}}
        by_cwe = {"CWE-79": {"configurations": [cwe_row("D-validated-council", 4, 0, 4, 2)]},
                  "CWE-89": {"configurations": [cwe_row("D-validated-council", 4, 1, 4, 3)]}}
        rates = ws.rates_from_evaluation(by_cwe, "D-validated-council", ("CWE-79", "CWE-89"))
        self.assertEqual((rates["CWE-89"]["keep_rate"], rates["CWE-89"]["removal_rate"]), (0.75, 0.75))
        result = ws.project(counts, rates)
        cwe89 = result["per_cwe"]["CWE-89"]["whole_system"]
        self.assertEqual((cwe89["kept_real"], cwe89["kept_safe"], cwe89["missed"]), (7.5, 2.5, 7.5))
        whole = result["whole_system"]
        self.assertEqual((whole["kept_real"], whole["kept_safe"], whole["missed"]), (27.5, 2.5, 7.5))
        self.assertAlmostEqual(whole["precision"], 27.5 / 30)
        self.assertAlmostEqual(whole["recall"], 27.5 / 35)
        self.assertAlmostEqual(whole["f1"], 55 / 65)
        alone = result["semgrep_alone"]
        self.assertEqual((alone["tp"], alone["fp"], alone["fn"]), (30, 10, 5))
        self.assertAlmostEqual(alone["precision"], 0.75)
        self.assertAlmostEqual(alone["recall"], 30 / 35)
        # Every real vulnerability is either kept or missed.
        self.assertAlmostEqual(whole["kept_real"] + whole["missed"], alone["tp"] + alone["fn"])

    def test_recall_never_exceeds_semgrep_recall(self):
        counts = {"CWE-22": {"tp": 7, "fp": 3, "fn": 2}, "CWE-78": {"tp": 0, "fp": 4, "fn": 1}}
        for dismissed in range(0, 5):
            for removed in range(0, 5):
                by_cwe = {cwe: {"configurations": [cwe_row("B-single-agent", 4, dismissed, 4, removed)]}
                          for cwe in counts}
                result = ws.project(counts, ws.rates_from_evaluation(by_cwe, "B-single-agent", tuple(counts)))
                self.assertLessEqual(result["whole_system"]["recall"],
                                     result["semgrep_alone"]["recall"] + 1e-12)
                for cwe in counts:
                    whole, alone = result["per_cwe"][cwe]["whole_system"], result["per_cwe"][cwe]["semgrep"]
                    if alone["recall"] is not None:
                        self.assertLessEqual(whole["recall"], alone["recall"] + 1e-12)
        # Keeping every real case reaches the ceiling exactly.
        by_cwe = {cwe: {"configurations": [cwe_row("B-single-agent", 4, 0, 4, 4)]} for cwe in counts}
        result = ws.project(counts, ws.rates_from_evaluation(by_cwe, "B-single-agent", tuple(counts)))
        self.assertAlmostEqual(result["whole_system"]["recall"], result["semgrep_alone"]["recall"])
        self.assertEqual(result["whole_system"]["kept_safe"], 0)

    def test_a_missing_cwe_or_configuration_is_refused(self):
        by_cwe = {"CWE-89": {"configurations": [cwe_row("B-single-agent", 4, 0, 4, 4)]}}
        with self.assertRaisesRegex(ws.WholeSystemError, "no results for CWE-79"):
            ws.rates_from_evaluation(by_cwe, "B-single-agent", ("CWE-79",))
        with self.assertRaisesRegex(ws.WholeSystemError, "no D-validated-council results"):
            ws.rates_from_evaluation(by_cwe, "D-validated-council", ("CWE-89",))


class Command(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.runs = self.tmp / "experiments"
        patcher = mock.patch.multiple(config, RECORDED_SCAN=FIXTURES / "semgrep.json",
                                      ANSWER_KEY=FIXTURES / "expectedresults.csv",
                                      EXPERIMENTS_OUT=self.runs)
        patcher.start()
        self.addCleanup(patcher.stop)
        out = mock.patch.object(ws, "OUT_DIR", self.tmp / "whole_system")
        out.start()
        self.addCleanup(out.stop)

    def main(self, *argv):
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = ws.main(list(argv))
        return code, stream.getvalue()

    def write_run(self, name, configuration, case_set="final-test", status="complete"):
        folder = self.runs / name
        folder.mkdir(parents=True)
        cases = ["BenchmarkTest00001"]
        manifest = {"run": name, "modes": ["council"], "status": status,
                    "case_set": {"name": case_set, "sha256": "f" * 64, "cases": cases, "cases_in_set": 1,
                                 "limit": None},
                    "git": {"commit": "e" * 40}}
        (folder / experiments.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
        (folder / experiments.EVALUATION).write_text("{}", encoding="utf-8")
        (folder / experiments.RESULTS_LOG).write_text(
            json.dumps({"case_id": cases[0], "council": {}}) + "\n", encoding="utf-8")
        by_cwe = {cwe: {"configurations": [cwe_row(configuration, 15, 1, 15, 12)]} for cwe in config.EVAL_SET_CWES}
        (folder / experiments.EVALUATION_BY_CWE).write_text(json.dumps({"by_cwe": by_cwe}), encoding="utf-8")

    def test_before_step_6_it_prints_semgrep_alone_and_says_to_run_step_6(self):
        code, printed = self.main("--mode", "council")
        self.assertEqual(code, 0)
        self.assertIn("Semgrep alone", printed)
        self.assertIn("| **All 4** |", printed)
        self.assertIn("run step 6 first", printed)
        self.assertIn("python -m triagebot experiment run 6", printed)
        self.assertFalse((self.tmp / "whole_system").exists())

    def test_an_unfinished_or_wrong_run_is_not_used(self):
        self.write_run("6-before", "B-single-agent", status="running")
        code, printed = self.main("--mode", "single")
        self.assertEqual(code, 0)
        self.assertIn("is not finished", printed)
        self.write_run("6-after", "D-validated-council", case_set="comparison")
        code, printed = self.main("--mode", "council")
        self.assertIn("not the final test", printed)
        self.assertFalse((self.tmp / "whole_system").exists())

    def test_after_step_6_it_writes_json_and_markdown(self):
        self.write_run("6-after", "D-validated-council")
        code, printed = self.main("--mode", "council")
        self.assertEqual(code, 0, printed)
        for text in (ws.LABEL, ws.CEILING, "kept safe cases are Semgrep's false positives times one minus",
                     "| Recall |", "council after deterministic validation (D)"):
            self.assertIn(text, printed)
        report = json.loads((self.tmp / "whole_system" / "6-after.json").read_text(encoding="utf-8"))
        markdown = (self.tmp / "whole_system" / "6-after.md").read_bytes()
        self.assertNotIn(b"\r\n", markdown)
        self.assertIn(ws.CEILING.encode("utf-8"), markdown)
        self.assertEqual((report["run"], report["configuration"], report["label"]),
                         ("6-after", "D-validated-council", ws.LABEL))
        rates = report["result"]["per_cwe"]["CWE-89"]["rates"]
        self.assertAlmostEqual(rates["keep_rate"], 14 / 15)
        self.assertAlmostEqual(rates["removal_rate"], 12 / 15)
        self.assertLessEqual(report["result"]["whole_system"]["recall"],
                             report["result"]["semgrep_alone"]["recall"])
        self.assertEqual(report["provenance"]["run_commit"], "e" * 40)


if __name__ == "__main__":
    unittest.main()
