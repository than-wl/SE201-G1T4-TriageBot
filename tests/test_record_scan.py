"""Offline tests for the recorded-scan normaliser (triagebot/nodes/ingest/record_scan.py).

Run from the repo root: python -m unittest discover -s tests
"""
import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from triagebot.nodes.ingest import record_scan  # noqa: E402
from triagebot.nodes.ingest.normalise import load_semgrep, normalise  # noqa: E402

WINDOWS = r"C:\Users\someone\GitHub\TriageBot\Context\tmp\BenchmarkJava"
TEST_FILE = r"\src\main\java\org\owasp\benchmark\testcode\BenchmarkTest00001.java"
HELPER = "/home/someone/BenchmarkJava/src/main/java/org/owasp/benchmark/helpers/DatabaseHelper.java"
RELATIVE = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"

# The shape of a real Semgrep --json scan run from an absolute path.
FIXTURE = {
    "version": "1.178.0",
    "results": [{
        "check_id": "java.lang.security.audit.formatted-sql-string.formatted-sql-string",
        "path": WINDOWS + TEST_FILE,
        "start": {"line": 50, "col": 9, "offset": 2000}, "end": {"line": 51, "col": 30, "offset": 2040},
        "extra": {"message": "Detected a formatted string in a SQL statement (see src/main/java docs).",
                  "severity": "ERROR", "lines": 'String sql = "SELECT * FROM users WHERE id=" + id;',
                  "metadata": {"cwe": ["CWE-89: SQL Injection"], "references": ["https://owasp.org/x"]}},
    }],
    "errors": [],
    "paths": {"scanned": [WINDOWS + TEST_FILE, HELPER]},
    "time": {"fixpoint_timeouts": [{
        "message": f"Fixpoint timeout while performing taint analysis at {WINDOWS + TEST_FILE}:39:16 [rules: 1]",
        "location": {"path": WINDOWS + TEST_FILE, "start": {"line": 39}},
    }], "rules": [], "total_time": 12.5},
    "engine_requested": "OSS",
    "skipped_rules": [],
}


class Normaliser(unittest.TestCase):
    def setUp(self):
        self.before = copy.deepcopy(FIXTURE)
        self.after = record_scan.normalise_paths(FIXTURE)

    def test_paths_become_relative_to_the_benchmark_root(self):
        self.assertEqual(self.after["results"][0]["path"], RELATIVE)
        self.assertEqual(self.after["paths"]["scanned"],
                         [RELATIVE, "src/main/java/org/owasp/benchmark/helpers/DatabaseHelper.java"])
        timeout = self.after["time"]["fixpoint_timeouts"][0]
        self.assertEqual(timeout["location"]["path"], RELATIVE)
        self.assertEqual(timeout["message"],
                         f"Fixpoint timeout while performing taint analysis at {RELATIVE}:39:16 [rules: 1]")

    def test_everything_else_untouched(self):
        self.assertEqual(FIXTURE, self.before)                    # input not modified
        expected = copy.deepcopy(self.before)
        expected["results"][0]["path"] = RELATIVE
        expected["paths"]["scanned"] = self.after["paths"]["scanned"]
        expected["time"]["fixpoint_timeouts"][0] = self.after["time"]["fixpoint_timeouts"][0]
        self.assertEqual(self.after, expected)
        self.assertEqual(record_scan.count_rewritten(self.before, self.after), 5)

    def test_repo_relative_paths_made_relative_to_benchmark_root(self):
        # A scan run from the repository root (how the original recorded scan was made).
        for text in (r"Context\tmp\BenchmarkJava" + TEST_FILE, "Context/tmp/BenchmarkJava/" + RELATIVE):
            self.assertEqual(record_scan.relative_path(text), RELATIVE)
        message = r"Fixpoint timeout at Context\tmp\BenchmarkJava" + TEST_FILE + ":39:16 [rules: 2]"
        self.assertEqual(record_scan.relative_path(message), f"Fixpoint timeout at {RELATIVE}:39:16 [rules: 2]")

    def test_other_text_left_alone(self):
        for text in (RELATIVE, "see src/main/java docs", "java.lang.security.audit.formatted-sql-string",
                     "https://owasp.org/src/main/java/x", 'String sql = "SELECT * FROM users";'):
            self.assertEqual(record_scan.relative_path(text), text)

    def test_no_machine_specific_text_left(self):
        dumped = json.dumps(self.after)
        self.assertNotIn("someone", dumped)
        self.assertEqual(record_scan.leftover_absolute_paths(self.after), [])
        self.assertEqual(len(record_scan.leftover_absolute_paths(self.before)), 5)

    def test_ingest_reads_the_normalised_scan_the_same_way(self):
        before, _ = normalise(self.before)
        after, _ = normalise(self.after)
        self.assertEqual(before, after)
        self.assertEqual((after[0]["case_id"], after[0]["file"]), ("BenchmarkTest00001", RELATIVE))


class Command(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def run_main(self, data):
        source, out = self.tmp / "local.json", self.tmp / "data" / "recorded.json"
        source.write_text(json.dumps(data), encoding="utf-8")
        printed, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(printed), redirect_stderr(errors):
            code = record_scan.main(["--in", str(source), "--out", str(out)])
        return code, out, printed.getvalue(), errors.getvalue()

    def test_writes_relative_scan(self):
        code, out, printed, _ = self.run_main(FIXTURE)
        self.assertEqual(code, 0)
        self.assertIn("1 findings; 5 string(s) rewritten", printed)
        data, _ = load_semgrep(out)
        self.assertEqual(data, record_scan.normalise_paths(FIXTURE))

    def test_refuses_when_an_absolute_path_is_left(self):
        data = copy.deepcopy(FIXTURE)
        data["errors"] = [{"path": r"D:\elsewhere\pom.xml"}]       # not under the benchmark source tree
        code, out, _, errors = self.run_main(data)
        self.assertEqual(code, 1)
        self.assertIn("absolute path", errors)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
