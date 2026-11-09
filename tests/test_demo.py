"""Offline tests for the product demo (triagebot/demo.py, `python -m triagebot demo`, menu option 5).

Builds a small saved run, case set, scan, whole-system projection and answer key
in a temporary directory. No model calls; the real evidence folder is never read.

Run from the repo root: python -m unittest discover -s tests
"""
import isolated_store  # noqa: F401  (first: keeps every test off the real vector store)
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from rich.console import Console

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from triagebot import __main__ as cli, config, demo  # noqa: E402

FILE = "src/main/java/org/owasp/benchmark/testcode/{}.java"
CWES = ("CWE-89", "CWE-78", "CWE-79", "CWE-22")


def _case_id(number):
    return f"BenchmarkTest{number:05d}"


def _council(case_id, verdict, explanation, citations):
    chair = {"case_id": case_id, "role": "chair", "verdict": verdict, "explanation": explanation,
             "citations": [{"file": FILE.format(case_id), "line": line, "quote": quote}
                           for line, quote in citations],
             "latency_seconds": 20.0, "usage": {"cost": 0.015}}
    return {"role_reports": [chair], "review": chair,
            "validated": {**chair, "validated": verdict != "human_review", "validation_errors": []}}


class DemoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # 8 real and 6 safe cases; the council is right on all but one safe case (sent to a person).
        self.real = [_case_id(n) for n in range(1, 9)]
        self.safe = [_case_id(n) for n in range(101, 107)]
        key_rows = ["# test name, category, real vulnerability, cwe"]
        alerts, records = [], []
        for index, case_id in enumerate(self.real + self.safe):
            cwe = CWES[index % 4]
            real = case_id in self.real
            key_rows.append(f"{case_id},sqli,{'true' if real else 'false'},{cwe[4:]}")
            alerts.append({"case_id": case_id, "file": FILE.format(case_id), "rule_id": "rule", "cwe": cwe,
                           "start_line": 40 + index, "end_line": 40 + index, "message": "m"})
            if real:
                council = _council(case_id, "true_positive", "User input reaches the sink. It is not escaped.",
                                   [(10, 'param = request.getParameter("x");'),
                                    (12, 'String sql = "SELECT * FROM t WHERE a=\'" + bar + "\'";'),
                                    (14, "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.execute(sql);")])
            elif case_id == self.safe[0]:
                council = _council(case_id, "human_review", "Could not decide. Evidence unclear.", [])
            else:
                council = _council(case_id, "false_positive",
                                   "The parameter is read first. The value is replaced by a hardcoded "
                                   "constant before org.owasp.benchmark.helpers.Thing.use(bar) runs.",
                                   [(20, 'bar = "safe";')])
            records.append({"case_id": case_id, "council": council})
        self.key = self.tmp / "expectedresults.csv"
        self.key.write_text("\n".join(key_rows) + "\n", encoding="utf-8")
        sample = self.tmp / "final-test.json"
        sample.write_text(json.dumps({"selection": {}, "alerts": alerts}), encoding="utf-8")
        self.out = self.tmp / "experiments"
        run = self.out / "6-after"
        run.mkdir(parents=True)
        (run / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
        (run / "run_manifest.json").write_text(json.dumps({
            "run": "6-after", "finished_at": "2026-11-08T20:16:29+00:00",
            "case_set": {"file": str(sample), "name": "final-test"}}), encoding="utf-8")
        self.scan = self.tmp / "scan.json"
        self.scan.write_text(json.dumps({"results": [{}] * 25}), encoding="utf-8")
        whole = self.tmp / "evidence" / "whole_system"
        whole.mkdir(parents=True)
        (whole / "6-after.json").write_text(json.dumps({"result": {
            "per_cwe": {c: {} for c in CWES},
            "semgrep_alone": {"tp": 668, "fp": 453},
            "whole_system": {"kept_safe": 19.87}}}), encoding="utf-8")
        patcher = mock.patch.object(config, "EVIDENCE_DIR", self.tmp / "evidence")
        patcher.start()
        self.addCleanup(patcher.stop)

    def load(self, seed=demo.SEED):
        return demo.load_demo(out_root=self.out, answer_key=self.key, scan=self.scan, seed=seed)

    def text(self, show):
        console = Console(width=110, record=True, color_system=None, file=io.StringIO())
        show(console)
        return console.export_text()

    def test_pick_is_fixed_and_has_the_requested_mix(self):
        from triagebot.nodes.ingest.answer_key import load_answer_key
        key = load_answer_key(self.key)
        ids = self.real + self.safe
        first, again = demo.pick_cases(ids, key, seed=7), demo.pick_cases(ids, key, seed=7)
        self.assertEqual(first, again)
        self.assertEqual(sum(key[c]["vulnerable"] for c in first), demo.REAL_CASES)
        self.assertEqual(len(first), demo.REAL_CASES + demo.SAFE_CASES)
        with self.assertRaises(demo.DemoUnavailable):
            demo.pick_cases(ids, key, real=9)

    def test_loads_cases_in_case_order_with_proof_and_reason(self):
        shown = self.load()
        ids = [c["case_id"] for c in shown["cases"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual((shown["scan_alerts"], shown["test_cases"]), (25, 14))
        self.assertEqual(shown["projection"], {"flagged": 1121, "false_alarms": 453, "left": 19.87, "types": 4})
        real = next(c for c in shown["cases"] if c["verdict"] == "true_positive")
        self.assertIn("+ bar +", real["proof"]["quote"])                 # the glued-in input, not the call
        closed = [c for c in shown["cases"] if c["verdict"] == "false_positive"]
        for case in closed:
            self.assertTrue(case["reason"].startswith("The value is replaced"))   # the sentence with the why
            self.assertIn("Thing.use(bar)", case["reason"])                       # package prefix dropped

    def test_screen_shows_every_scene_and_marks_answers(self):
        shown = self.load()
        text = self.text(lambda console: demo.render(shown, console))
        for expected in ("1  The code and the scanner", "25 alerts raised", "1,121 flagged, 453",
                         "about 4 in 10", "2  10 alerts to investigate", "3  TriageBot reviewing 10 alerts",
                         "[10/10]", "4  The developer's new list", "TO FIX:", "CLOSED:",
                         "453 false alarms → about 20", "recorded run 6-after"):
            self.assertIn(expected, text)
        self.assertNotIn("random", text.lower())           # the sample was chosen knowing the outcome
        self.assertNotIn("sped up", text)                  # no pace, nothing sped up
        person = sum(c["verdict"] == "human_review" for c in shown["cases"])
        self.assertIn(f"{person} need a person", text)
        if person:
            self.assertIn("FOR A PERSON", text)

    def test_a_sample_with_a_person_case_says_so(self):
        for seed in range(50):                             # find a draw that includes the escalated case
            shown = self.load(seed)
            if any(c["verdict"] == "human_review" for c in shown["cases"]):
                break
        else:
            self.fail("no seed drew the escalated case")
        text = self.text(lambda console: demo.show_result(shown, console))
        self.assertIn("1 need a person", text)
        self.assertIn("FOR A PERSON: 1", text)
        self.assertIn("9 decided automatically", text)

    def test_missing_answer_key_or_run(self):
        with self.assertRaises(demo.DemoUnavailable):
            demo.load_demo(out_root=self.out, answer_key=self.tmp / "missing.csv", scan=self.scan)
        with self.assertRaises(demo.DemoUnavailable):
            demo.load_demo(run="9-after", out_root=self.out, answer_key=self.key, scan=self.scan)

    def test_cli_demo_and_svg_export(self):
        real_load = demo.load_demo
        stdout = Console(width=110, record=True, color_system=None, file=io.StringIO())
        svg = self.tmp / "slide.svg"
        with mock.patch.object(cli, "console", stdout), \
                mock.patch.object(demo, "load_demo", lambda answer_key=None: real_load(
                    out_root=self.out, answer_key=self.key, scan=self.scan)):
            self.assertEqual(cli.main(["demo"]), 0)
            self.assertEqual(cli.main(["demo", "--export-svg", str(svg)]), 0)
        printed = stdout.export_text()
        self.assertIn("The developer's new list", printed)
        self.assertIn("Saved the result screen", printed)
        image = svg.read_text(encoding="utf-8")
        self.assertIn("<svg", image)
        self.assertNotIn("The code and the scanner", image.replace("&#160;", " "))   # result only

    def test_menu_option_5_runs_the_demo(self):
        self.assertIn("5", [key for key, *_ in cli.OPTIONS])
        with mock.patch.object(cli, "run_demo", return_value=0) as run, \
                mock.patch("builtins.input", side_effect=[""]):
            cli._menu_demo(None)
        run.assert_called_once_with(pace=cli.DEMO_MENU_PACE, step=True, answer_key=None)


if __name__ == "__main__":
    unittest.main()
