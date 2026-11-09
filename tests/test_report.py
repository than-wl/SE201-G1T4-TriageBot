"""Offline tests for the full PDF report (triagebot/report.py, `python -m triagebot report`, menu option 6).

Builds a small saved run and case set in a temporary directory. No model calls,
no answer key, and the real evidence folder is never read.

Run from the repo root: python -m unittest discover -s tests
"""
import isolated_store  # noqa: F401  (first: keeps every test off the real vector store)
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from triagebot import __main__ as cli, report  # noqa: E402

FILE = "src/main/java/org/owasp/benchmark/testcode/{}.java"


def _record(case_id, verdict, original=None, errors=()):
    chair = {"case_id": case_id, "role": "chair", "verdict": original or verdict,
             "explanation": f"Explanation for {case_id} → safe…",
             "citations": [{"file": FILE.format(case_id), "line": 50, "quote": 'String sql = "x" + bar;'}],
             "guidance": [{"doc": "MITRE_CWE", "section": "CWE-89"}],
             "latency_seconds": 20.0, "usage": {"cost": 0.015}}
    validated = {**chair, "verdict": verdict, "original_verdict": original or verdict,
                 "validation_errors": list(errors)}
    return {"case_id": case_id, "council": {"review": chair, "validated": validated}}


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        run = self.tmp / "runs" / "r1"
        run.mkdir(parents=True)
        ids = [f"BenchmarkTest{n:05d}" for n in (1, 2, 3, 4)]
        alerts = [{"case_id": c, "cwe": "CWE-89", "file": FILE.format(c), "start_line": 50,
                   "end_line": 50, "rule_id": "sqli", "message": "m"} for c in ids]
        (self.tmp / "set.json").write_text(json.dumps({"alerts": alerts}), encoding="utf-8")
        (run / "run_manifest.json").write_text(json.dumps({
            "case_set": {"file": str(self.tmp / "set.json"), "name": "t"},
            "finished_at": "2026-11-08T00:00:00", "model": {"reported": ["m"]}}), encoding="utf-8")
        records = [_record(ids[0], "true_positive"), _record(ids[1], "false_positive"),
                   _record(ids[2], "human_review", "human_review"),
                   _record(ids[3], "human_review", "false_positive", ["citation 1 not found"])]
        (run / "results.jsonl").write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
        self.root = self.tmp / "runs"

    def test_groups_and_escalation_reasons(self):
        data = report.load_report("r1", out_root=self.root)
        verdicts = [f["verdict"] for f in data["findings"]]
        self.assertEqual(verdicts, ["true_positive", "false_positive", "human_review", "human_review"])
        self.assertIn("could not decide", data["findings"][2]["escalation"])
        self.assertIn("citation 1 not found", data["findings"][3]["escalation"])

    def test_never_reads_answer_key(self):
        with mock.patch("triagebot.nodes.ingest.answer_key.load_answer_key", side_effect=AssertionError):
            data = report.load_report("r1", out_root=self.root)
        self.assertNotIn("real", data["findings"][0])

    def test_builds_pdf_with_non_latin_text(self):
        out = report.build_pdf(report.load_report("r1", out_root=self.root), self.tmp / "out" / "r.pdf")
        self.assertTrue(out.read_bytes().startswith(b"%PDF"))

    def test_council_confidence(self):
        votes = lambda a, s: {"role_reports": [{"role": "analyst", "verdict": a},
                                               {"role": "skeptic", "verdict": s}]}
        self.assertIn("unanimous", report._council(votes("true_positive", "true_positive"), "true_positive"))
        self.assertIn("split", report._council(votes("true_positive", "false_positive"), "true_positive"))
        self.assertIn("overruled both", report._council(votes("false_positive", "false_positive"),
                                                        "true_positive"))
        self.assertIn("sent to a person", report._council(votes("human_review", "human_review"),
                                                          "human_review"))
        self.assertEqual(report._council({}, "true_positive"), "")

    def test_cited_line_roles(self):
        self.assertEqual(report._role('String p = request.getParameter("a");', "true_positive"), "SOURCE")
        self.assertEqual(report._role('String sql = "SELECT " + bar;', "true_positive"), "BUILDS")
        self.assertEqual(report._role("statement.executeQuery(sql);", "true_positive"), "SINK")
        self.assertEqual(report._role('bar = "safe";', "false_positive"), "GUARD")

    def test_fix_falls_back_to_link_without_catalogue(self):
        with mock.patch.object(report, "_catalogue", False):
            self.assertEqual(report._recommended_fix("CWE-89"), [])
        self.assertEqual(report._mitre_url("CWE-89"), "https://cwe.mitre.org/data/definitions/89.html")

    def test_missing_run(self):
        with self.assertRaises(report.ReportUnavailable):
            report.load_report("nope", out_root=self.root)

    def test_cli_subcommand(self):
        out = self.tmp / "cli.pdf"
        real = report.load_report
        with mock.patch.object(report, "load_report", lambda run: real(run, out_root=self.root)):
            self.assertEqual(cli.main(["report", "--run", "r1", "--out", str(out)]), 0)
        self.assertTrue(out.is_file())


if __name__ == "__main__":
    unittest.main()
