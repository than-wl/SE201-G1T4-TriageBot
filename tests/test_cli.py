"""Offline tests for the terminal menu and subcommands (triagebot/__main__.py).

Output is rendered through fixed-width, colourless rich consoles, and
Semgrep is never run: re-scans use a mocked subprocess.

Run from the repo root: python -m unittest discover -s tests
"""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from rich.console import Console

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from triagebot import __main__ as cli  # noqa: E402

FIXTURES = ROOT / "tests/fixtures/ingest"
SEMGREP = FIXTURES / "semgrep.json"
ANSWER_KEY = FIXTURES / "expectedresults.csv"
OUTPUT_FILES = ("alerts.json", "selected_alerts.json", "ingest_report.json", "split.json",
                "scanner_predictions.json", "baseline.json")


def plain_console(stream):
    return Console(file=stream, width=120, color_system=None, highlight=False)


def capture(func, *args, **kwargs):
    """Call func with cli output captured; return (result, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.multiple(cli, console=plain_console(out), err_console=plain_console(err)), \
            redirect_stdout(out), redirect_stderr(err):
        result = func(*args, **kwargs)
    return result, out.getvalue(), err.getvalue()


class TempDir(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.out = self.tmp / "out"
        self.semgrep = self.tmp / "semgrep-owasp.json"     # a copy, so re-scans may replace it
        shutil.copy2(SEMGREP, self.semgrep)

    def baseline_argv(self, *extra):
        return ["baseline", "--semgrep", str(self.semgrep), "--answer-key", str(ANSWER_KEY),
                "--out", str(self.out), *extra]

    def fake_benchmark(self):
        root = self.tmp / "BenchmarkJava"
        (root / "src/main/java").mkdir(parents=True)
        return mock.patch.multiple(cli.config, BENCHMARK_ROOT=str(root))

    def fake_semgrep(self, returncode=0, write=True, stderr=""):
        """Patch the venv Semgrep lookup and subprocess.run; return the run mock."""
        def run(command, **kwargs):
            if write:
                Path(command[command.index("--output") + 1]).write_text(
                    json.dumps({"version": "9.9.9", "results": [], "errors": []}), encoding="utf-8")
            return subprocess.CompletedProcess(command, returncode, "", stderr)
        self.enterContext(mock.patch.object(cli, "_semgrep_exe", return_value=self.tmp / "semgrep.exe"))
        self.enterContext(self.fake_benchmark())
        return self.enterContext(mock.patch.object(cli.subprocess, "run", side_effect=run))


class Menu(TempDir):
    def run_menu(self, *answers):
        with mock.patch("builtins.input", side_effect=list(answers)) as fake:
            code, printed, errors = capture(cli.menu, str(self.semgrep), str(ANSWER_KEY), str(self.out))
        return code, printed, fake.call_count

    def test_shows_menu(self):
        _, printed, _ = self.run_menu("q")
        self.assertIn("TriageBot", printed)
        for title, description in ((title, description) for _, title, description, _ in cli.OPTIONS):
            self.assertIn(title, printed)
            self.assertIn(description, printed)
        self.assertIn("Quit", printed)
        self.assertEqual(printed.count("(coming soon)"), 2)
        self.assertNotIn("not yet available", printed)

    def test_quit_and_end_of_input(self):
        self.assertEqual(self.run_menu("q")[::2], (0, 1))
        self.assertEqual(self.run_menu(EOFError())[0], 0)

    def test_option_1_uses_saved_scan(self):
        code, printed, prompts = self.run_menu("1", "", "", "q")
        self.assertEqual((code, prompts), (0, 4))
        self.assertIn("use saved scan from", printed)
        self.assertIn("r = re-run Semgrep now (takes a few minutes, needs internet)", printed)
        self.assertIn("Semgrep raised alerts on 6 test cases", printed)
        self.assertIn("d = show technical details", printed)
        self.assertNotIn("Technical details", printed)
        for name in OUTPUT_FILES:
            self.assertTrue((self.out / name).is_file(), name)

    def test_option_1_details(self):
        code, printed, prompts = self.run_menu("1", "", "d", "", "q")
        self.assertEqual((code, prompts), (0, 5))
        self.assertIn("Technical details", printed)
        self.assertIn("file-matched", printed)

    def test_option_1_rescan(self):
        run = self.fake_semgrep()
        old = self.semgrep.read_bytes()
        code, printed, prompts = self.run_menu("1", "r", "", "q")
        self.assertEqual((code, prompts), (0, 4))
        command, env = run.call_args.args[0], run.call_args.kwargs["env"]
        self.assertEqual(command[1:5], ["scan", "--config", "p/java", "--json"])
        self.assertTrue(command[-1].replace("\\", "/").endswith("BenchmarkJava/src/main/java"))
        self.assertEqual(env["PYTHONUTF8"], "1")
        self.assertEqual((self.tmp / "semgrep-owasp.previous.json").read_bytes(), old)
        self.assertIn("Scan complete", printed)
        self.assertIn("Semgrep 9.9.9", printed)                # the screen uses the new scan

    def test_options_2_and_3_wait_for_enter(self):
        for choice in ("2", "3"):
            with self.subTest(choice=choice):
                code, printed, prompts = self.run_menu(choice, "", "q")
                self.assertEqual((code, prompts), (0, 3))
                self.assertIn(cli.NOT_YET, printed)
                self.assertIn("Press Enter to return to the menu", printed)
        self.assertFalse(self.out.exists())

    def test_invalid_input_reprompts(self):
        code, printed, prompts = self.run_menu("x", "", "4", "q")
        self.assertEqual((code, prompts), (0, 4))
        self.assertIn("Unknown option 'x'", printed)
        self.assertNotIn(cli.NOT_YET, printed)

    def test_menu_and_subcommand_call_the_same_functions(self):
        ctx = object()
        with mock.patch.object(cli, "prepare_baseline", return_value=ctx) as prepare, \
                mock.patch.object(cli, "show_baseline") as show:
            with mock.patch("builtins.input", side_effect=["1", "", "", "q"]):
                capture(cli.menu, str(self.semgrep), str(ANSWER_KEY), str(self.out))
            capture(cli.main, self.baseline_argv())
        self.assertEqual(prepare.call_count, 2)
        self.assertEqual(prepare.call_args_list[0], prepare.call_args_list[1])
        self.assertEqual(show.call_args_list, [mock.call(ctx)] * 2)

    def test_no_arguments_opens_menu(self):
        with mock.patch.object(cli, "menu", return_value=0) as fake:
            self.assertEqual(cli.main([]), 0)
        fake.assert_called_once_with()


class BaselineScreen(TempDir):
    def setUp(self):
        super().setUp()
        self.code, self.printed, self.errors = capture(cli.main, self.baseline_argv())
        self.flat = " ".join(self.printed.split())          # phrases may wrap at 120 columns

    def test_succeeds_and_writes_ingest_outputs(self):
        self.assertEqual((self.code, self.errors), (0, ""))
        for name in OUTPUT_FILES:
            self.assertTrue((self.out / name).is_file(), name)

    def test_title_and_provenance(self):
        self.assertIn("TriageBot · Scanner baseline", self.printed)
        self.assertIn("How good is the security scanner on its own, before TriageBot?", self.printed)
        self.assertIn("Semgrep 1.178.0, ruleset p/java, saved ", self.printed)
        self.assertIn(cli.saved_scan_time(self.semgrep), self.printed)
        self.assertIn("(local time), 9 alerts", self.printed)
        self.assertIn("OWASP Benchmark v1.2 answer key, 10 test cases", self.printed)

    def test_headline_numbers(self):
        for phrase in ("Semgrep raised alerts on 6 test cases",
                       "3 were real vulnerabilities and 3 were false alarms: precision 50.0%",
                       "It caught 3 of 6 real vulnerabilities: recall 50.0%",
                       "F1 50.0% (balance of the two)"):
            self.assertIn(phrase, self.flat)

    def test_table_uses_readable_names_in_order(self):
        names = ["Command injection", "Cross-site scripting", "Path traversal", "SQL injection",
                 "Weak encryption", "Weak hashing", "All types"]
        positions = [self.printed.index(name) for name in names]
        self.assertEqual(positions, sorted(positions))
        for raw in ("sqli", "pathtraver", "cmdi", "xss"):
            self.assertIsNone(re.search(rf"\b{raw}\b", self.printed), raw)
        self.assertRegex(self.printed, r"SQL injection\s+3\s+1\s+2\s+1\s+50\.0%\s+33\.3%\s+40\.0%")
        self.assertRegex(self.printed, r"All types\s+6\s+3\s+3\s+3\s+50\.0%\s+50\.0%\s+50\.0%")
        self.assertRegex(self.printed, r"Weak hashing\s+0\s+0\s+0\s+1\s+0\.0%\s+–\s+–")

    def test_what_it_means_and_test_set(self):
        self.assertIn("3 of 6 flagged test cases (50.0%) are false alarms", self.flat)
        self.assertIn("TriageBot can only filter alerts, never add them, so the system can catch at most "
                      "50.0% of real vulnerabilities with this scan", self.flat)
        self.assertIn("Blind spots (nothing caught): Path traversal (0 of 1).", self.flat)
        self.assertIn("2 SQL injection (CWE-89) test cases from the development split", self.flat)
        self.assertIn("1 real vulnerability, 1 false alarm.", self.flat)

    def test_footer(self):
        self.assertIn("(CWE match)", self.printed)
        self.assertIn(str(self.out / "baseline.json"), self.printed)

    def test_no_technical_wording_on_default_screen(self):
        self.assertIsNone(re.search(r"\bmodes?\b", self.printed, re.IGNORECASE))
        for phrase in ("file-matched", "proposal's method", "mismatch", "alerts.json", "split.json"):
            self.assertNotIn(phrase, self.printed)

    def test_sections_in_order(self):
        marks = ["Scanner baseline", "Scored against", "Semgrep raised alerts", "By vulnerability type",
                 "What this means for TriageBot", "Checkpoint test set", "Precision: of the"]
        positions = [self.printed.index(mark) for mark in marks]
        self.assertEqual(positions, sorted(positions))


class Details(TempDir):
    def test_details_show_technical_extras(self):
        code, printed, _ = capture(cli.main, self.baseline_argv("--details"))
        self.assertEqual(code, 0)
        self.assertRegex(printed, r'file-matched \(mode "file"\)\s+8\s+5\s+3\s+1\s+1\s+62\.5%\s+83\.3%\s+71\.4%')
        self.assertIn("proposal's method", printed)
        self.assertIn("CWE mismatch pairs", printed)
        self.assertIn("no-direct-response-writer", printed)
        self.assertIn("Ingest counts", printed)
        for name in OUTPUT_FILES:
            self.assertIn(str(self.out / name), printed)


class Rescan(TempDir):
    def test_missing_semgrep_falls_back_to_saved_scan(self):
        old = self.semgrep.read_bytes()
        with mock.patch.object(cli, "_semgrep_exe", return_value=None), \
                mock.patch.object(cli.subprocess, "run") as run:
            code, printed, errors = capture(cli.main, self.baseline_argv("--rescan"))
        self.assertEqual((code, errors), (0, ""))
        run.assert_not_called()
        self.assertIn("Semgrep is not installed", printed)
        self.assertIn('"Semgrep scan"', printed)
        self.assertIn("Using the saved scan from", printed)
        self.assertIn("Semgrep raised alerts on 6 test cases", printed)
        self.assertEqual(self.semgrep.read_bytes(), old)
        self.assertNotIn("Traceback", printed + errors)

    def test_failed_scan_keeps_old_file(self):
        self.fake_semgrep(returncode=2, write=False, stderr="downloading rules\nnetwork unreachable\n")
        old = self.semgrep.read_bytes()
        code, printed, _ = capture(cli.main, self.baseline_argv("--rescan"))
        self.assertEqual(code, 0)
        self.assertIn("The Semgrep scan did not complete: network unreachable", printed)
        self.assertIn("Using the saved scan from", printed)
        self.assertEqual(self.semgrep.read_bytes(), old)
        self.assertFalse((self.tmp / "semgrep-owasp.previous.json").exists())
        self.assertEqual(sorted(p.name for p in self.tmp.glob("semgrep-owasp*")), ["semgrep-owasp.json"])

    def test_successful_scan_replaces_file_and_keeps_previous(self):
        self.fake_semgrep()
        old = self.semgrep.read_bytes()
        code, printed, _ = capture(cli.main, self.baseline_argv("--rescan"))
        self.assertEqual(code, 0)
        self.assertEqual((self.tmp / "semgrep-owasp.previous.json").read_bytes(), old)
        self.assertEqual(json.loads(self.semgrep.read_text(encoding="utf-8"))["version"], "9.9.9")
        self.assertIn("Semgrep 9.9.9", printed)

    def test_no_saved_scan_and_no_semgrep_is_friendly(self):
        self.semgrep.unlink()
        with mock.patch.object(cli, "_semgrep_exe", return_value=None):
            code, printed, errors = capture(cli.main, self.baseline_argv("--rescan"))
        self.assertEqual(code, 1)
        self.assertIn("Semgrep JSON not found", errors)
        self.assertNotIn("Traceback", printed + errors)


class MissingInputs(TempDir):
    def run_baseline(self, *argv):
        return capture(cli.main, ["baseline", "--out", str(self.out), *argv])

    def assert_friendly(self, code, errors, *phrases):
        self.assertEqual(code, 1)
        self.assertNotIn("Traceback", errors)
        for phrase in phrases:
            self.assertIn(phrase, errors)
        self.assertFalse(self.out.exists())

    def test_missing_semgrep_json(self):
        code, _, errors = self.run_baseline("--semgrep", str(self.tmp / "none.json"),
                                            "--answer-key", str(ANSWER_KEY))
        self.assert_friendly(code, errors, "Semgrep JSON not found", '"Semgrep scan"')

    def test_missing_answer_key(self):
        code, _, errors = self.run_baseline("--semgrep", str(SEMGREP),
                                            "--answer-key", str(self.tmp / "none.csv"))
        self.assert_friendly(code, errors, "answer key not found", '"OWASP Benchmark"')

    def test_answer_key_unknown(self):
        with mock.patch.object(cli.config, "ANSWER_KEY", None):
            code, _, errors = self.run_baseline("--semgrep", str(SEMGREP))
        self.assert_friendly(code, errors, "answer key not found", "BENCHMARK_ROOT")

    def test_malformed_semgrep_json(self):
        self.semgrep.write_text("{not json", encoding="utf-8")
        code, _, errors = self.run_baseline("--semgrep", str(self.semgrep), "--answer-key", str(ANSWER_KEY))
        self.assert_friendly(code, errors, "not valid JSON", '"Semgrep scan"')


class MissingRich(unittest.TestCase):
    def test_friendly_exit_without_rich(self):
        script = ("import sys, runpy; sys.modules['rich'] = None; "
                  "runpy.run_module('triagebot', run_name='__main__')")
        done = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True,
                              text=True, timeout=60)
        self.assertEqual(done.returncode, 1)
        self.assertIn("TriageBot needs its Python environment", done.stderr)
        self.assertIn(r".\.verification-venv\Scripts\python.exe -m triagebot", done.stderr)
        self.assertNotIn("Traceback", done.stderr)


class Placeholders(unittest.TestCase):
    def test_triage_subcommand(self):
        code, printed, _ = capture(cli.main, ["triage", "--case", "BenchmarkTest00001", "--mode", "council"])
        self.assertEqual((code, printed.strip()), (2, cli.NOT_YET))

    def test_evaluate_subcommand(self):
        code, printed, _ = capture(cli.main, ["evaluate", "--mode", "single,council"])
        self.assertEqual((code, printed.strip()), (2, cli.NOT_YET))

    def test_evaluate_rejects_unknown_mode(self):
        with self.assertRaises(SystemExit) as raised:
            capture(cli.main, ["evaluate", "--mode", "single,bogus"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
