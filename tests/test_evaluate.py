"""Offline tests for the evaluation harness. Run from the repo root: python -m unittest discover -s tests"""
from contextlib import redirect_stdout
import io
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from triagebot.nodes.score import evaluate  # noqa: E402

FIXTURES = ROOT / "tests/fixtures/evaluation"


def run_cli(out):
    with redirect_stdout(io.StringIO()):
        return evaluate.main(["--labels", str(FIXTURES / "labels.json"),
                              "--cases", str(FIXTURES / "cases.json"),
                              "--config", "C-council=" + str(FIXTURES / "council_results.json"),
                              "--out", str(out)])


class HandWrittenDataset(unittest.TestCase):
    """One case of each outcome the brief asks for, with exact expected counts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        report = run_cli(Path(self.tmp.name) / "report.json")
        self.scanner, self.council = report["configurations"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_council_counts_match_exactly(self):
        c = self.council
        self.assertEqual((c["evaluated_findings"], c["genuine_in_sample"], c["fp_in_sample"]), (5, 2, 3))
        self.assertEqual(c["genuine_retained"], 1)
        self.assertEqual(c["genuine_dismissed"], 1)
        self.assertEqual(c["fp_removed"], 1)
        self.assertEqual(c["fp_retained"], 1)
        self.assertEqual(c["fp_human_review"], 1)
        self.assertEqual(c["human_review_rate"], 0.2)
        self.assertEqual(c["invalid_output_rate"], 0.2)
        self.assertEqual(c["model"], "fixture")

    def test_human_review_is_not_counted_as_a_removed_false_positive(self):
        self.assertEqual(self.council["fp_removed"], 1)
        self.assertEqual(self.council["fp_removed_rate"], round(1 / 3, 4))

    def test_failures_list_every_wrong_or_invalid_case(self):
        failures = {f["case_id"]: f["outcome"] for f in self.council["failures"]}
        self.assertEqual(failures, {"FixtureCase02": "genuine_dismissed",
                                    "FixtureCase04": "fp_retained",
                                    "FixtureCase05": "fp_human_review"})

    def test_usage_is_totalled(self):
        usage = self.council["usage"]
        self.assertEqual(usage["latency_mean_seconds"], 10.0)
        self.assertEqual(usage["prompt_tokens_total"], 5000)
        self.assertEqual(usage["cost_total"], 0.01)

    def test_scanner_only_baseline_keeps_every_finding(self):
        s = self.scanner
        self.assertEqual(s["configuration"], "A-scanner-only")
        self.assertEqual((s["genuine_retained"], s["fp_retained"], s["fp_removed"]), (2, 3, 0))

    def test_same_inputs_give_identical_output(self):
        first, second = Path(self.tmp.name) / "first.json", Path(self.tmp.name) / "second.json"
        run_cli(first)
        run_cli(second)
        self.assertEqual(first.read_bytes(), second.read_bytes())


class UnsafeInputs(unittest.TestCase):
    labels = {"Case1": True, "Case2": False, "Case3": False}

    def score(self, results):
        return evaluate.score("X", sorted(self.labels), self.labels, results)

    def test_missing_and_unsupported_results_become_human_review(self):
        result = self.score([{"case_id": "Case2", "verdict": "safe"}])
        self.assertEqual(result["missing_results"], 2)
        self.assertEqual(result["invalid_outputs"], 3)
        self.assertEqual(result["human_review"], 3)
        self.assertEqual(result["fp_removed"], 0)

    def test_validator_records_are_scored_with_their_reasons(self):
        # Same record shape as triagebot/nodes/validate/validator.py produces.
        record = {"case_id": "Case2", "verdict": "human_review", "original_verdict": "false_positive",
                  "validated": False, "explanation": "Validation failed; human review required.",
                  "citations": [], "validation_errors": ["Citation 1: wrong file"]}
        unexplained = {"case_id": "Case3", "verdict": "human_review", "validated": False}
        result = self.score([record, unexplained, {"case_id": "Case1", "verdict": "true_positive",
                                                   "validated": True, "validation_errors": []}])
        self.assertEqual(result["genuine_retained"], 1)
        self.assertEqual((result["fp_human_review"], result["invalid_outputs"]), (2, 2))
        reasons = {f["case_id"]: f["reasons"] for f in result["failures"]}
        self.assertEqual(reasons, {"Case2": ["Citation 1: wrong file"],
                                   "Case3": ["failed validation (no reason given)"]})

    def test_valid_human_review_is_still_listed_for_the_report(self):
        result = self.score([{"case_id": "Case1", "verdict": "true_positive"},
                             {"case_id": "Case2", "verdict": "false_positive"},
                             {"case_id": "Case3", "verdict": "human_review"}])
        self.assertEqual(result["invalid_outputs"], 0)
        self.assertEqual([(f["case_id"], f["outcome"]) for f in result["failures"]],
                         [("Case3", "fp_human_review")])

    def test_duplicate_result_is_rejected(self):
        with self.assertRaises(ValueError):
            self.score([{"case_id": "Case1", "verdict": "true_positive"}] * 2)

    def test_case_without_answer_key_label_is_rejected(self):
        with self.assertRaises(ValueError):
            evaluate.score("X", ["Unknown"], self.labels, [])

    def test_results_outside_sample_are_reported_not_scored(self):
        result = self.score([{"case_id": "Other", "verdict": "true_positive"}])
        self.assertEqual(result["results_outside_sample"], ["Other"])
        self.assertEqual(result["evaluated_findings"], 3)

    def test_uneven_coverage_is_flagged(self):
        report = evaluate.evaluate(sorted(self.labels), self.labels, {
            "B": ([{"case_id": "Case1", "verdict": "true_positive"}], None),
            "C": ([], None)})
        self.assertFalse(report["same_case_coverage"])

    def test_official_answer_key_csv_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "expectedresults-1.2.csv"
            path.write_text("# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n"
                            "BenchmarkTest00001,pathtraver,true,22\n"
                            "BenchmarkTest00002,sqli,false,89\n", encoding="utf-8")
            self.assertEqual(evaluate.load_labels(path),
                             {"BenchmarkTest00001": True, "BenchmarkTest00002": False})


if __name__ == "__main__":
    unittest.main()
