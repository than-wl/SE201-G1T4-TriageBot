"""Offline tests for the terminal menu and subcommands (triagebot/__main__.py).

Output is rendered through fixed-width, colourless rich consoles, and
Semgrep and git are never run: re-scans, clones and the commit check use a
mocked subprocess. config.LOCAL_SCAN and config.RECORDED_SCAN point into a
temporary directory, and the menu's setup check is mocked unless a test
is about it.

Run from the repo root: python -m unittest discover -s tests
"""
import ast
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ElementTree

from rich.console import Console

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from triagebot import __main__ as cli  # noqa: E402
from triagebot import check  # noqa: E402

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
        self.semgrep = self.tmp / "semgrep-owasp.json"     # the local re-scan, so re-scans may replace it
        shutil.copy2(SEMGREP, self.semgrep)
        self.recorded = self.tmp / "data" / "recorded.json"
        self.enter(mock.patch.multiple(cli.config, LOCAL_SCAN=self.semgrep, RECORDED_SCAN=self.recorded))

    def enter(self, manager):
        """Enter a context manager until the test ends (TestCase.enterContext is Python 3.11+)."""
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

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
        self.enter(mock.patch.object(cli, "_semgrep_exe", return_value=self.tmp / "semgrep.exe"))
        self.enter(self.fake_benchmark())
        return self.enter(mock.patch.object(cli.subprocess, "run", side_effect=run))


def checks(**status):
    """A setup-check result: every check OK unless overridden, e.g. checks(bench=check.MISSING)."""
    names = {"python": "Python version", "rich": "rich installed", "bench": "OWASP Benchmark folder",
             "scan": "Semgrep scan available", "semgrep": "Semgrep installed"}
    return [check.Check(name, status.get(key, check.OK), "detail", "fix command", key != "semgrep")
            for key, name in names.items()]


class Menu(TempDir):
    def setUp(self):
        super().setUp()
        self.enter(mock.patch.object(cli.check, "run_checks", return_value=checks()))
        self.enter(mock.patch.object(cli, "_semgrep_exe", return_value=self.tmp / "semgrep.exe"))

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
        self.assertIn("use the local re-scan from", printed)
        self.assertIn("Setup check", printed)
        self.assertIn("r = re-run Semgrep now (takes a few minutes, needs internet)", printed)
        self.assertNotIn("re-scan unavailable", printed)
        self.assertIn("Semgrep raised alerts on 6 test cases", printed)
        self.assertIn("d = show technical details", printed)
        self.assertNotIn("Technical details", printed)
        for name in OUTPUT_FILES:
            self.assertTrue((self.out / name).is_file(), name)

    def test_option_1_without_semgrep_offers_no_rescan(self):
        old = self.semgrep.read_bytes()
        with mock.patch.object(cli, "_semgrep_exe", return_value=None), \
                mock.patch.object(cli.subprocess, "run") as run:
            code, printed, prompts = self.run_menu("1", "r", "", "q")     # "r" is ignored
        self.assertEqual((code, prompts), (0, 4))
        self.assertIn("use the local re-scan from", printed)
        self.assertIn("(re-scan unavailable: Semgrep not installed)", printed)
        self.assertNotIn("r = re-run Semgrep now", printed)
        self.assertNotIn("Semgrep is not installed", printed)                 # no re-scan attempted
        self.assertIn("Semgrep raised alerts on 6 test cases", printed)
        run.assert_not_called()
        self.assertEqual(self.semgrep.read_bytes(), old)

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
        self.assertEqual(command[-1], "src/main/java")         # relative, like the recorded scan
        self.assertTrue(str(run.call_args.kwargs["cwd"]).endswith("BenchmarkJava"))
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
        self.assertIn("Semgrep 1.178.0, ruleset p/java, local re-scan from ", self.printed)
        self.assertIn(cli.scan_time(self.semgrep), self.printed)
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
        self.assertIn("pip install -r requirements.txt", printed)
        self.assertIn("Using the local re-scan from", printed)
        self.assertIn("Semgrep raised alerts on 6 test cases", printed)
        self.assertEqual(self.semgrep.read_bytes(), old)
        self.assertNotIn("Traceback", printed + errors)

    def test_failed_scan_keeps_old_file(self):
        self.fake_semgrep(returncode=2, write=False, stderr="downloading rules\nnetwork unreachable\n")
        old = self.semgrep.read_bytes()
        code, printed, _ = capture(cli.main, self.baseline_argv("--rescan"))
        self.assertEqual(code, 0)
        self.assertIn("The Semgrep scan did not complete: network unreachable", printed)
        self.assertIn("Using the local re-scan from", printed)
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
        self.assertIn("This re-scan is now used instead of the recorded scan. To go back, delete or rename "
                      f"{check.rel_path(self.semgrep)}.", " ".join(printed.split()))

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
        self.assert_friendly(code, errors, "Semgrep JSON not found", "python -m triagebot check")

    def test_missing_answer_key(self):
        code, _, errors = self.run_baseline("--semgrep", str(SEMGREP),
                                            "--answer-key", str(self.tmp / "none.csv"))
        self.assert_friendly(code, errors, "answer key not found", "Clone the OWASP Benchmark")

    def test_answer_key_unknown(self):
        with mock.patch.object(cli.config, "ANSWER_KEY", None):
            code, _, errors = self.run_baseline("--semgrep", str(SEMGREP))
        self.assert_friendly(code, errors, "answer key not found", "BENCHMARK_ROOT")

    def test_malformed_semgrep_json(self):
        self.semgrep.write_text("{not json", encoding="utf-8")
        code, _, errors = self.run_baseline("--semgrep", str(self.semgrep), "--answer-key", str(ANSWER_KEY))
        self.assert_friendly(code, errors, "not valid JSON", "Re-run the scan")


def run_triagebot(*argv, setup="", platform=None):
    """python -m triagebot ARGV in a child process, after SETUP code (and a pretend platform)."""
    pretend = f"import triagebot.check as c; c.platform = lambda: {platform!r}" if platform else ""
    script = "; ".join(part for part in (
        "import sys, runpy", setup, pretend, f"sys.argv = ['triagebot', *{list(argv)!r}]",
        "runpy.run_module('triagebot', run_name='__main__')") if part)
    return subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=60)


class MissingRich(unittest.TestCase):
    NO_RICH = "sys.modules['rich'] = None"

    def test_friendly_exit_without_rich_shows_this_os_command(self):
        for platform, command, other in (("win32", r".\.venv\Scripts\Activate.ps1", "source .venv/bin/activate"),
                                         ("darwin", "source .venv/bin/activate", "Activate.ps1"),
                                         ("linux", "source .venv/bin/activate", "Activate.ps1")):
            with self.subTest(platform=platform):
                done = run_triagebot(setup=self.NO_RICH, platform=platform)
                self.assertEqual(done.returncode, 1)
                self.assertIn("TriageBot needs its Python environment", done.stderr)
                self.assertIn(f"Activate .venv ({command};", done.stderr)
                self.assertNotIn(other, done.stderr)
                self.assertIn("pip install -r requirements.txt", done.stderr)
                self.assertNotIn("Traceback", done.stderr)

    def test_check_without_rich_prints_plain_report(self):
        done = run_triagebot("check", setup=self.NO_RICH, platform="darwin")
        self.assertEqual(done.returncode, 1)
        self.assertIn("MISSING  rich installed", done.stdout)
        self.assertIn("To fix: source .venv/bin/activate", done.stdout)
        self.assertEqual(run_triagebot("check", "--no-fail", setup=self.NO_RICH).returncode, 0)


class PythonVersionGuard(unittest.TestCase):
    def test_old_python_gets_one_plain_message(self):
        done = run_triagebot(setup="sys.version_info = (3, 9, 18, 'final', 0)")
        self.assertEqual(done.returncode, 1)
        self.assertEqual(done.stderr.strip(),
                         "TriageBot needs Python 3.10 or newer (you have 3.9). Install it from python.org or "
                         "with `brew install python@3.12` on macOS, then recreate .venv.")
        self.assertEqual(done.stdout, "")

    def test_main_module_parses_on_python_3_8(self):
        source = (ROOT / "triagebot/__main__.py").read_text(encoding="utf-8")
        ast.parse(source, feature_version=(3, 8))          # raises SyntaxError if not


class ScanResolution(TempDir):
    def test_local_rescan_preferred_over_recorded(self):
        self.recorded.parent.mkdir(parents=True)
        shutil.copy2(SEMGREP, self.recorded)
        self.assertEqual(cli.config.effective_scan(), (self.semgrep, "local re-scan"))

    def test_recorded_used_without_local_file(self):
        self.semgrep.unlink()
        self.assertEqual(cli.config.effective_scan(), (self.recorded, "recorded scan"))

    def test_provenance_names_the_recorded_scan_and_its_fixed_date(self):
        self.recorded.parent.mkdir(parents=True)
        self.semgrep.replace(self.recorded)
        code, printed, _ = capture(cli.main, ["baseline", "--answer-key", str(ANSWER_KEY), "--out", str(self.out)])
        self.assertEqual(code, 0)
        self.assertIn("ruleset p/java, recorded scan from ", printed)
        self.assertIn(cli.scan_time(self.recorded), printed)
        report = json.loads((self.out / "ingest_report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["scan_date"], cli.config.RECORDED_SCAN_DATE)    # not the checkout mtime

    def test_provenance_names_the_local_rescan(self):
        code, printed, _ = capture(cli.main, ["baseline", "--answer-key", str(ANSWER_KEY), "--out", str(self.out)])
        self.assertEqual(code, 0)
        self.assertIn("ruleset p/java, local re-scan from ", printed)


class RescanTarget(TempDir):
    def test_rescan_writes_only_the_local_scan(self):
        self.recorded.parent.mkdir(parents=True)
        shutil.copy2(SEMGREP, self.recorded)
        self.semgrep.unlink()
        recorded = self.recorded.read_bytes()
        run = self.fake_semgrep()
        code, printed, _ = capture(cli.main, ["baseline", "--semgrep", str(self.recorded), "--answer-key",
                                              str(ANSWER_KEY), "--out", str(self.out), "--rescan"])
        self.assertEqual(code, 0)
        command = run.call_args.args[0]
        self.assertEqual(Path(command[command.index("--output") + 1]), self.semgrep.resolve().with_name(
            "semgrep-owasp.json.partial"))
        self.assertEqual(self.recorded.read_bytes(), recorded)
        self.assertEqual(json.loads(self.semgrep.read_text(encoding="utf-8"))["version"], "9.9.9")
        self.assertIn("local re-scan", printed)

    def semgrep_exe_with(self, layout):
        """semgrep_exe() for a fake Python in a folder with no venv-like name."""
        python = self.tmp / f"any-python-folder-{layout}" / "python.exe"
        name = "semgrep.exe" if os.name == "nt" else "semgrep"
        target = {"beside": python.with_name(name),
                  "subdir": python.parent / ("Scripts" if os.name == "nt" else "bin") / name}.get(layout)
        if target:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("", encoding="utf-8")
        with mock.patch.object(check.sys, "executable", str(python)), \
                mock.patch.object(check.shutil, "which", return_value=None):
            return check.semgrep_exe(), target

    def test_semgrep_found_next_to_python(self):
        for layout in ("beside", "subdir"):
            with self.subTest(layout=layout):
                found, target = self.semgrep_exe_with(layout)
                self.assertEqual(found, target)

    def test_semgrep_found_on_path_or_not_at_all(self):
        self.assertEqual(self.semgrep_exe_with(None)[0], None)
        with mock.patch.object(check.sys, "executable", str(self.tmp / "python.exe")), \
                mock.patch.object(check.shutil, "which", return_value="/usr/bin/semgrep"):
            self.assertEqual(check.semgrep_exe(), Path("/usr/bin/semgrep"))


class SetupChecks(TempDir):
    def bench(self, testcode=True, key=True):
        root = self.tmp / "BenchmarkJava"
        if testcode:
            (root / check.TESTCODE).mkdir(parents=True, exist_ok=True)
        if key:
            root.mkdir(exist_ok=True)
            (root / check.ANSWER_KEY_NAME).write_text("# test name\n", encoding="utf-8")
        return root

    def git(self, head="", returncode=0):
        return mock.Mock(return_value=subprocess.CompletedProcess([], returncode, head + "\n", ""))

    def test_python_version(self):
        self.assertEqual(check.check_python((3, 10, 0)).status, check.OK)
        old = check.check_python((3, 9, 18))
        self.assertEqual((old.status, old.required), (check.MISSING, True))
        self.assertIn("python.org", old.fix)

    def test_rich(self):
        self.assertEqual(check.check_rich(lambda name: object()).status, check.OK)
        missing = check.check_rich(lambda name: None)
        self.assertEqual(missing.status, check.MISSING)
        self.assertIn("pip install -r requirements.txt", missing.fix)

    def test_fix_commands_follow_the_os(self):
        cases = {"win32": (r".\.venv\Scripts\Activate.ps1", "py -m venv .venv", "python.org", "source "),
                 "darwin": ("source .venv/bin/activate", "python3 -m venv .venv", "brew install python@3.12",
                            "Activate.ps1"),
                 "linux": ("source .venv/bin/activate", "python3 -m venv .venv", "package manager",
                           "Activate.ps1")}
        for platform, (activate, create, install, other) in cases.items():
            with self.subTest(platform=platform), mock.patch.object(check, "platform", return_value=platform):
                rich = check.check_rich(lambda name: None).fix
                venv = check.check_venv("/same", "/same").fix
                python = check.check_python((3, 9, 18)).fix
                self.assertEqual(rich.splitlines(), [activate, "pip install -r requirements.txt"])
                self.assertEqual(venv.splitlines(), [f"{create}   (first time only)", activate])
                self.assertIn(install, python)
                self.assertIn(create, python)
                for fix in (rich, venv, python):
                    self.assertNotIn(other, fix)

    def test_virtual_environment_is_only_a_warning(self):
        active = check.check_venv(str(self.tmp / ".venv"), str(self.tmp / "base"))
        self.assertEqual((active.status, active.detail), (check.OK, "active (.venv)"))
        inactive = check.check_venv(str(self.tmp), str(self.tmp))
        self.assertEqual((inactive.status, inactive.required), (check.WARNING, False))
        self.assertEqual(check.blocking([inactive]), [])

    def test_no_fail_exits_zero_while_missing(self):
        with mock.patch.object(cli.check, "run_checks", return_value=checks(bench=check.MISSING)):
            self.assertEqual(capture(cli.main, ["check"])[0], 1)
            code, printed, _ = capture(cli.main, ["check", "--no-fail"])
        self.assertEqual(code, 0)
        self.assertIn("MISSING", printed)
        self.assertIn("To fix: OWASP Benchmark folder", printed)

    def test_benchmark_folder(self):
        self.assertEqual(check.check_benchmark(self.bench()).status, check.OK)

    def test_benchmark_folder_missing_shows_clone_and_checkout(self):
        missing = check.check_benchmark(self.tmp / "nowhere")
        self.assertEqual(missing.status, check.MISSING)
        self.assertIn(f"git clone {cli.config.BENCHMARK_URL}", missing.fix)
        self.assertIn(f"checkout {cli.config.BENCHMARK_COMMIT}", missing.fix)

    def test_benchmark_folder_without_answer_key(self):
        missing = check.check_benchmark(self.bench(key=False))
        self.assertEqual(missing.status, check.MISSING)
        self.assertIn(check.ANSWER_KEY_NAME, missing.detail)

    def test_commit_check(self):
        root = self.bench()
        same = check.check_commit(root, run=self.git(cli.config.BENCHMARK_COMMIT))
        self.assertEqual(same.status, check.OK)
        other = check.check_commit(root, run=self.git("0" * 40))
        self.assertEqual((other.status, other.required), (check.WARNING, False))
        self.assertIn(f"checkout {cli.config.BENCHMARK_COMMIT}", other.fix)

    def test_commit_check_skipped_without_git(self):
        self.assertIsNone(check.check_commit(self.bench(), run=mock.Mock(side_effect=FileNotFoundError)))
        self.assertIsNone(check.check_commit(self.tmp, run=self.git(returncode=128)))   # not a git checkout
        with mock.patch.multiple(cli.config, BENCHMARK_ROOT=str(self.bench())):
            names = [c.name for c in check.run_checks(run=mock.Mock(side_effect=FileNotFoundError))]
        self.assertNotIn("Benchmark at pinned commit", names)
        self.assertIn("OWASP Benchmark folder", names)

    def test_scan(self):
        self.assertIn("local re-scan", check.check_scan().detail)
        self.semgrep.unlink()
        self.assertEqual(check.check_scan().status, check.MISSING)
        self.recorded.parent.mkdir(parents=True)
        shutil.copy2(SEMGREP, self.recorded)
        self.assertIn("recorded scan", check.check_scan().detail)

    def test_semgrep_is_only_a_warning(self):
        warning = check.check_semgrep(lambda: None)
        self.assertEqual((warning.status, warning.required), (check.WARNING, False))
        self.assertIn("needed for re-scans", warning.detail)
        self.assertIn("pip install -r requirements.txt", warning.fix)
        self.assertEqual(check.check_semgrep(lambda: self.tmp / "semgrep.exe").status, check.OK)
        self.assertEqual(check.blocking([warning]), [])

    def test_subcommand_prints_words_and_fixes(self):
        with mock.patch.object(cli.check, "run_checks", return_value=checks(bench=check.MISSING,
                                                                             semgrep=check.WARNING)):
            code, printed, _ = capture(cli.main, ["check"])
        self.assertEqual(code, 1)
        for word in ("Setup check", "OK", "MISSING", "WARNING", "To fix: OWASP Benchmark folder",
                     "Optional: Semgrep installed", "fix command"):
            self.assertIn(word, printed)
        self.assertNotIn("To fix: Semgrep installed", printed)
        self.assertNotIn("Optional: OWASP Benchmark folder", printed)
        with mock.patch.object(cli.check, "run_checks", return_value=checks(semgrep=check.WARNING)):
            self.assertEqual(capture(cli.main, ["check"])[0], 0)

    def test_plain_report_without_rich(self):
        out = io.StringIO()
        self.assertEqual(check.print_plain(checks(rich=check.MISSING), out=out), 1)
        self.assertIn("MISSING  rich installed", out.getvalue())
        self.assertIn("To fix: fix command", out.getvalue())
        out = io.StringIO()
        check.print_plain(checks(semgrep=check.WARNING), out=out)
        self.assertIn("Optional: fix command", out.getvalue())
        self.assertNotIn("To fix:", out.getvalue())


class MenuSetup(TempDir):
    def setUp(self):
        super().setUp()
        self.enter(mock.patch.object(cli, "_semgrep_exe", return_value=self.tmp / "semgrep.exe"))

    def run_menu(self, results, *answers):
        with mock.patch.object(cli.check, "run_checks", side_effect=results) as checked, \
                mock.patch.object(cli.subprocess, "run",
                                  return_value=subprocess.CompletedProcess([], 0, "", "")) as run, \
                mock.patch("builtins.input", side_effect=list(answers)):
            code, printed, _ = capture(cli.menu, str(self.semgrep), str(ANSWER_KEY), str(self.out))
        return code, printed, run, checked

    def test_no_clone_offer_when_benchmark_present(self):
        code, printed, run, _ = self.run_menu([checks()], "q")
        self.assertEqual(code, 0)
        self.assertNotIn("Clone the OWASP Benchmark now?", printed)
        run.assert_not_called()

    def test_clone_offer_declined_does_nothing(self):
        for answer in ("", "n"):
            with self.subTest(answer=answer):
                code, printed, run, _ = self.run_menu([checks(bench=check.MISSING)], answer, "q")
                self.assertEqual(code, 0)
                self.assertIn("Clone the OWASP Benchmark now? (about 100 MB) [y/N]", printed)
                run.assert_not_called()

    def test_clone_offer_accepted_clones_and_checks_out(self):
        target = self.tmp / "BenchmarkJava"
        with mock.patch.multiple(cli.config, BENCHMARK_ROOT=None, BENCHMARK_CLONE_DIR=target,
                                 ANSWER_KEY=None):
            code, printed, run, checked = self.run_menu([checks(bench=check.MISSING), checks()], "y", "q")
            self.assertEqual(cli.config.BENCHMARK_ROOT, str(target))
        self.assertEqual(code, 0)
        commands = [c.args[0] for c in run.call_args_list]
        self.assertEqual(commands, [["git", "clone", cli.config.BENCHMARK_URL, str(target)],
                                    ["git", "-C", str(target), "checkout", cli.config.BENCHMARK_COMMIT]])
        self.assertEqual(checked.call_count, 2)                # re-checked after the clone
        self.assertIn("Cloned", printed)

    def test_option_1_refuses_while_required_check_missing(self):
        with mock.patch.object(cli, "prepare_baseline") as prepare:
            code, printed, _, _ = self.run_menu([checks(), checks(scan=check.MISSING)], "1", "", "q")
        self.assertEqual(code, 0)
        prepare.assert_not_called()
        self.assertIn("Option 1 needs the items marked MISSING above", printed)

    def test_option_1_runs_when_only_warnings(self):
        code, printed, _, _ = self.run_menu([checks(), checks(semgrep=check.WARNING)], "1", "", "", "q")
        self.assertEqual(code, 0)
        self.assertIn("Semgrep raised alerts on 6 test cases", printed)


class ExportSvg(TempDir):
    def test_export_svg_writes_valid_svg(self):
        target = self.tmp / "shots" / "baseline.svg"
        code, printed, _ = capture(cli.main, self.baseline_argv("--export-svg", str(target)))
        self.assertEqual(code, 0)
        root = ElementTree.parse(target).getroot()
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        self.assertIn("Scanner", target.read_text(encoding="utf-8"))
        self.assertIn("Saved the screen to", printed)


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
