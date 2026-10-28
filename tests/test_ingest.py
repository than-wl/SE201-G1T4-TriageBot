"""Offline tests for ingest, answer-key mapping, metrics, split and sample.

Run from the repo root: python -m unittest discover -s tests
"""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from triagebot import config  # noqa: E402
from triagebot.nodes.ingest import mapping, normalise as norm, run, split as split_mod  # noqa: E402
from triagebot.nodes.ingest.answer_key import load_answer_key  # noqa: E402
from triagebot.nodes.score import evaluate, metrics  # noqa: E402
from triagebot.schemas import NormalisedAlert  # noqa: E402

FIXTURES = ROOT / "tests/fixtures/ingest"
SEMGREP = FIXTURES / "semgrep.json"
ANSWER_KEY = FIXTURES / "expectedresults.csv"
ALERT_FIELDS = set(NormalisedAlert.__annotations__)
TESTCODE = "src/main/java/org/owasp/benchmark/testcode/"


def fixture_alerts():
    data = json.loads(SEMGREP.read_text(encoding="utf-8"))
    return norm.normalise(data, scan_date="2026-01-01T00:00:00+00:00")


def case(n):
    return f"BenchmarkTest{n:05d}"


class Paths(unittest.TestCase):
    windows = r"Context\tmp\BenchmarkJava\src\main\java\org\owasp\benchmark\testcode\BenchmarkTest00042.java"

    def test_case_id_from_windows_path(self):
        self.assertEqual(norm.case_id_from_path(self.windows), "BenchmarkTest00042")

    def test_case_id_only_for_testcode_files(self):
        self.assertIsNone(norm.case_id_from_path("src/main/java/org/owasp/benchmark/helpers/Utils.java"))
        self.assertIsNone(norm.case_id_from_path("src/main/java/other/BenchmarkTest00042.java"))
        self.assertIsNone(norm.case_id_from_path(TESTCODE + "BenchmarkTest00042Helper.java"))

    def test_to_relative_starts_at_src_main_java(self):
        self.assertEqual(norm.to_relative(self.windows), TESTCODE + "BenchmarkTest00042.java")
        self.assertEqual(norm.to_relative("/abs/BenchmarkJava/src/main/java/a/B.java"), "src/main/java/a/B.java")
        self.assertEqual(norm.to_relative("src/main/java/a/B.java"), "src/main/java/a/B.java")
        self.assertIsNone(norm.to_relative(r"Context\tmp\elsewhere\Scratch.java"))


class ExtractCwe(unittest.TestCase):
    def test_list_form(self):
        self.assertEqual(norm.extract_cwe({"cwe": ["CWE-89: Improper Neutralization ..."]}), "CWE-89")

    def test_single_string_form(self):
        self.assertEqual(norm.extract_cwe({"cwe": "CWE-328: Use of Weak Hash"}), "CWE-328")

    def test_missing_forms(self):
        for metadata in ({}, None, {"cwe": []}, {"cwe": "no id here"}):
            self.assertEqual(norm.extract_cwe(metadata), "")

    def test_several_cwes_keep_the_first(self):
        self.assertEqual(norm.extract_cwe({"cwe": ["CWE-327: a", "CWE-326: b"]}), "CWE-327")

    def test_leading_zeros_are_normalised(self):
        self.assertEqual(norm.extract_cwe({"cwe": ["CWE-089"]}), "CWE-89")


class NormaliseFixture(unittest.TestCase):
    def setUp(self):
        self.alerts, self.report = fixture_alerts()
        self.by_case = {}
        for alert in self.alerts:
            self.by_case.setdefault(alert["case_id"], []).append(alert)

    def test_exact_normalised_alert(self):
        self.assertEqual(self.by_case[case(1)], [{
            "case_id": case(1),
            "file": TESTCODE + "BenchmarkTest00001.java",
            "rule_id": "java.lang.security.audit.formatted-sql-string.formatted-sql-string",
            "cwe": "CWE-89", "start_line": 50, "end_line": 51,
            "message": "Detected a formatted string in a SQL statement.",
        }])

    def test_every_alert_has_exact_fields_and_relative_forward_slash_path(self):
        for alert in self.alerts:
            self.assertEqual(set(alert), ALERT_FIELDS)
            self.assertTrue(alert["file"].startswith(TESTCODE), alert["file"])
            self.assertNotIn("\\", alert["file"])
            self.assertEqual(alert["file"], TESTCODE + alert["case_id"] + ".java")

    def test_exact_duplicate_collapses_to_first(self):
        self.assertEqual(len(self.by_case[case(4)]), 1)
        self.assertEqual(self.by_case[case(4)][0]["end_line"], 44)

    def test_two_rules_on_one_case_are_both_kept(self):
        rules = {a["rule_id"] for a in self.by_case[case(5)]}
        self.assertEqual(len(rules), 2)

    def test_missing_cwe_becomes_empty_string_and_message_is_stripped(self):
        (alert,) = self.by_case[case(6)]
        self.assertEqual(alert["cwe"], "")
        self.assertEqual(alert["message"], "File opened from a request parameter.")

    def test_report_counts(self):
        r = self.report
        self.assertEqual(r["semgrep_version"], "1.178.0")
        self.assertEqual(r["scan_date"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(r["total_findings"], 12)
        self.assertEqual(r["test_file_findings"], 10)
        self.assertEqual(r["helper_file_findings_dropped"],
                         {"count": 1, "examples": ["src/main/java/org/owasp/benchmark/helpers/DatabaseHelper.java"]})
        self.assertEqual(r["unmapped_paths"], {"count": 1, "examples": ["Context/tmp/elsewhere/Scratch.java"]})
        self.assertEqual(r["exact_duplicates_collapsed"], 1)
        self.assertEqual(r["alerts"], 9)
        self.assertEqual(len(self.alerts), 9)
        self.assertEqual(r["alerts_without_cwe"], 1)
        self.assertEqual(r["alerts_with_multiple_cwes"]["count"], 1)
        self.assertEqual(r["alerts_with_multiple_cwes"]["details"][0]["dropped"], ["CWE-326"])
        self.assertEqual(r["cases_with_alerts"], 8)
        self.assertEqual(r["semgrep_errors"], 1)

    def test_every_finding_is_accounted_for(self):
        r = self.report
        self.assertEqual(r["total_findings"], r["test_file_findings"] + r["helper_file_findings_dropped"]["count"]
                         + r["unmapped_paths"]["count"])
        self.assertEqual(r["test_file_findings"], r["alerts"] + r["exact_duplicates_collapsed"])

    def test_load_semgrep_records_file_mtime(self):
        data, scan_date = norm.load_semgrep(SEMGREP)
        self.assertEqual(data["version"], "1.178.0")
        self.assertRegex(scan_date, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")


class AnswerKey(unittest.TestCase):
    def write(self, text):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding="utf-8")
        tmp.write(text)
        tmp.close()
        self.addCleanup(Path(tmp.name).unlink)
        return tmp.name

    def test_fixture_loads(self):
        key = load_answer_key(ANSWER_KEY)
        self.assertEqual(len(key), 10)
        self.assertEqual(key[case(1)], {"category": "sqli", "cwe": "CWE-89", "vulnerable": True})
        self.assertEqual(key[case(9)], {"category": "hash", "cwe": "CWE-328", "vulnerable": False})

    def test_malformed_rows_raise(self):
        for bad in ("BenchmarkTest00001,sqli,true\n", "BenchmarkTest00001,sqli,maybe,89\n",
                    "BenchmarkTest00001,sqli,true,CWE89\n", "Case1,sqli,true,89\n",
                    "BenchmarkTest00001,,true,89\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                load_answer_key(self.write("# header\n" + bad))

    def test_duplicate_case_id_raises(self):
        with self.assertRaises(ValueError):
            load_answer_key(self.write("BenchmarkTest00001,sqli,true,89\nBenchmarkTest00001,sqli,false,89\n"))


class Predictions(unittest.TestCase):
    def setUp(self):
        self.alerts, _ = fixture_alerts()
        self.key = load_answer_key(ANSWER_KEY)

    def test_every_case_gets_a_prediction(self):
        for mode in mapping.MODES:
            predictions = mapping.scanner_predictions(self.alerts, self.key, mode)
            self.assertEqual(set(predictions), set(self.key))
            self.assertTrue(all(type(v) is bool for v in predictions.values()))

    def test_file_and_cwe_modes_differ_only_on_wrong_or_missing_cwe(self):
        file_mode = mapping.scanner_predictions(self.alerts, self.key, "file")
        cwe_mode = mapping.scanner_predictions(self.alerts, self.key, "cwe")
        self.assertEqual({c for c in self.key if file_mode[c]},
                         {case(n) for n in (1, 2, 3, 4, 5, 6, 9, 10)})
        differ = {c for c in self.key if file_mode[c] != cwe_mode[c]}
        # 00003: vulnerable sqli flagged only as CWE-79; 00006: flagged with no CWE.
        self.assertEqual(differ, {case(3), case(6)})
        self.assertFalse(cwe_mode[case(3)])

    def test_accepted_equivalences_are_exactly_the_decided_ones(self):
        self.assertEqual(mapping.ACCEPTED_CWE_EQUIVALENTS, {"CWE-327": {"CWE-326"}})
        self.assertTrue(mapping.cwe_matches("CWE-326", "CWE-327"))
        self.assertFalse(mapping.cwe_matches("CWE-327", "CWE-326"))   # one direction only
        self.assertFalse(mapping.cwe_matches("CWE-79", "CWE-501"))
        self.assertFalse(mapping.cwe_matches("CWE-79", "CWE-89"))
        self.assertFalse(mapping.cwe_matches("", "CWE-327"))

    def test_crypto_case_flagged_by_cwe_326_in_cwe_mode(self):
        key = {case(1): {"category": "crypto", "cwe": "CWE-327", "vulnerable": True},
               case(2): {"category": "trustbound", "cwe": "CWE-501", "vulnerable": True}}
        alerts = [dict(self.alerts[0], case_id=case(1), cwe="CWE-326"),
                  dict(self.alerts[0], case_id=case(2), cwe="CWE-79")]
        self.assertEqual(mapping.scanner_predictions(alerts, key, "cwe"), {case(1): True, case(2): False})
        rows = mapping.mismatch_report(alerts, key)
        self.assertEqual([(r["benchmark_cwe"], r["semgrep_cwe"]) for r in rows], [("CWE-501", "CWE-79")])

    def test_bad_mode_and_unknown_case_raise(self):
        with self.assertRaises(ValueError):
            mapping.scanner_predictions(self.alerts, self.key, "rule")
        stray = dict(self.alerts[0], case_id=case(99))
        with self.assertRaises(ValueError):
            mapping.scanner_predictions(self.alerts + [stray], self.key, "file")

    def test_mismatch_report(self):
        rows = mapping.mismatch_report(self.alerts, self.key)
        pairs = {(r["category"], r["benchmark_cwe"], r["semgrep_cwe"]): r for r in rows}
        self.assertEqual(set(pairs), {("sqli", "CWE-89", "CWE-79"), ("pathtraver", "CWE-22", "")})
        sqli = pairs["sqli", "CWE-89", "CWE-79"]
        self.assertEqual((sqli["alerts"], sqli["cases"], sqli["cases_without_matching_alert"]), (1, 1, 1))
        self.assertEqual(sqli["rule_ids"],
                         {"java.lang.security.audit.xss.no-direct-response-writer.no-direct-response-writer": 1})


class Metrics(unittest.TestCase):
    def test_confusion_hand_computed(self):
        predictions = {"a": True, "b": True, "c": False, "d": False, "e": True}
        labels = {"a": True, "b": False, "c": True, "d": False, "e": True}
        self.assertEqual(metrics.confusion(predictions, labels), {"tp": 2, "fp": 1, "fn": 1, "tn": 1})

    def test_confusion_rejects_different_case_sets(self):
        with self.assertRaises(ValueError):
            metrics.confusion({"a": True}, {"a": True, "b": False})

    def test_precision_recall_f1(self):
        result = metrics.precision_recall_f1({"tp": 5, "fp": 3, "fn": 1, "tn": 1})
        self.assertAlmostEqual(result["precision"], 5 / 8)
        self.assertAlmostEqual(result["recall"], 5 / 6)
        self.assertAlmostEqual(result["f1"], 10 / 14)

    def test_zero_denominators(self):
        self.assertEqual(metrics.precision_recall_f1({"tp": 0, "fp": 0, "fn": 0, "tn": 4}),
                         {"precision": None, "recall": None, "f1": None})
        self.assertEqual(metrics.precision_recall_f1({"tp": 0, "fp": 0, "fn": 2, "tn": 1}),
                         {"precision": None, "recall": 0.0, "f1": None})
        self.assertEqual(metrics.precision_recall_f1({"tp": 0, "fp": 2, "fn": 3, "tn": 0}),
                         {"precision": 0.0, "recall": 0.0, "f1": 0.0})

    def test_by_category_on_fixture(self):
        alerts, _ = fixture_alerts()
        key = load_answer_key(ANSWER_KEY)
        file_rows = metrics.by_category(mapping.scanner_predictions(alerts, key, "file"), key)
        cwe_rows = metrics.by_category(mapping.scanner_predictions(alerts, key, "cwe"), key)
        counts = lambda row: (row["tp"], row["fp"], row["fn"], row["tn"])  # noqa: E731
        self.assertEqual(counts(file_rows["overall"]), (5, 3, 1, 1))
        self.assertEqual(counts(cwe_rows["overall"]), (3, 3, 3, 1))
        self.assertEqual(counts(file_rows["sqli"]), (2, 1, 1, 1))
        self.assertEqual(counts(cwe_rows["sqli"]), (1, 1, 2, 1))
        self.assertEqual(file_rows["sqli"]["cases"], 5)
        self.assertEqual(list(file_rows), ["cmdi", "crypto", "hash", "pathtraver", "sqli", "xss", "overall"])
        self.assertIsNone(file_rows["hash"]["recall"])          # no vulnerable hash case


def synthetic_key():
    sizes = {("sqli", True): 7, ("sqli", False): 4, ("xss", True): 5, ("xss", False): 1, ("cmdi", True): 3}
    key, n = {}, 0
    for (category, vulnerable), size in sizes.items():
        for _ in range(size):
            n += 1
            key[case(n)] = {"category": category, "cwe": "CWE-1", "vulnerable": vulnerable}
    return key


class Split(unittest.TestCase):
    def setUp(self):
        self.key = synthetic_key()
        self.split = split_mod.assign_split(self.key, 201, 0.5)

    def test_deterministic(self):
        self.assertEqual(split_mod.assign_split(self.key, 201, 0.5), self.split)

    def test_complete_and_disjoint(self):
        self.assertEqual(set(self.split), set(self.key))
        self.assertEqual(set(self.split.values()), {"dev", "test"})

    def test_stratified(self):
        strata = {}
        for case_id, entry in self.key.items():
            strata.setdefault((entry["category"], entry["vulnerable"]), []).append(case_id)
        for stratum, cases in strata.items():
            with self.subTest(stratum=stratum):
                self.assertEqual(sum(self.split[c] == "test" for c in cases), round(len(cases) * 0.5))

    def test_stratum_counts(self):
        counts = split_mod.stratum_counts(self.key, self.split)
        self.assertEqual(counts["sqli/vulnerable"], {"dev": 3, "test": 4})
        self.assertEqual(counts["xss/safe"], {"dev": 1, "test": 0})

    def test_bad_fraction_raises(self):
        with self.assertRaises(ValueError):
            split_mod.assign_split(self.key, 201, 1.5)


def alert(case_id, cwe="CWE-89", line=10, rule="rule.a"):
    return {"case_id": case_id, "file": TESTCODE + case_id + ".java", "rule_id": rule, "cwe": cwe,
            "start_line": line, "end_line": line, "message": "m"}


class Sample(unittest.TestCase):
    def setUp(self):
        sqli = lambda vulnerable: {"category": "sqli", "cwe": "CWE-89", "vulnerable": vulnerable}  # noqa: E731
        self.key = {f"V{i}": sqli(True) for i in range(1, 6)} | {f"S{i}": sqli(False) for i in range(1, 4)}
        self.key |= {"T1": sqli(True), "W1": sqli(True),
                     "X1": {"category": "xss", "cwe": "CWE-79", "vulnerable": True}}
        self.split = {c: "dev" for c in self.key} | {"T1": "test"}
        self.alerts = [alert(c) for c in self.key if c not in ("V1", "W1")]
        self.alerts += [alert("V1", line=30, rule="rule.b"), alert("V1", line=20, rule="rule.z"),
                        alert("V1", line=20, rule="rule.a"), alert("V1", cwe="CWE-79", line=1),
                        alert("W1", cwe="CWE-79")]

    def select(self, size, seed=201):
        return split_mod.select_sample(self.alerts, self.key, self.split, "CWE-89", size, seed)

    def test_only_eligible_dev_cases(self):
        sample, summary = self.select(100)
        self.assertEqual({a["case_id"] for a in sample}, {f"V{i}" for i in range(1, 6)} | {"S1", "S2", "S3"})
        self.assertEqual((summary["eligible_vulnerable"], summary["eligible_safe"]), (5, 3))

    def test_can_select_held_out_partition(self):
        sample, summary = split_mod.select_sample(
            self.alerts, self.key, self.split, "CWE-89", 10, 201, partition="test")

        self.assertEqual([item["case_id"] for item in sample], ["T1"])
        self.assertEqual(summary["partition"], "test")

    def test_multiple_categories_are_combined_without_labels(self):
        tagged = [dict(item, vulnerable=True) for item in self.alerts]
        tagged.append(dict(alert("X1", cwe="CWE-79"), vulnerable=True))
        sample, summaries = split_mod.select_categories(
            tagged, self.key, self.split,
            {"CWE-89": 4, "CWE-79": 1}, 201, partition="dev")

        self.assertEqual(len(sample), 5)
        self.assertEqual(set(summaries), {"CWE-89", "CWE-79"})
        self.assertEqual(len({item["case_id"] for item in sample}), 5)
        self.assertTrue(all(set(item) == ALERT_FIELDS for item in sample))

    def test_one_alert_per_case_with_tie_break(self):
        sample, _ = self.select(100)
        self.assertEqual(len(sample), len({a["case_id"] for a in sample}))
        (v1,) = [a for a in sample if a["case_id"] == "V1"]
        self.assertEqual((v1["start_line"], v1["rule_id"], v1["cwe"]), (20, "rule.a", "CWE-89"))

    def test_balanced(self):
        for size, expected in ((6, (3, 3)), (4, (2, 2)), (5, (2, 3)), (7, (4, 3))):
            with self.subTest(size=size):
                sample, summary = self.select(size)
                vulnerable = sum(self.key[a["case_id"]]["vulnerable"] for a in sample)
                self.assertEqual((vulnerable, len(sample) - vulnerable), expected)
                self.assertEqual((summary["selected_vulnerable"], summary["selected_safe"]), expected)

    def test_deterministic(self):
        self.assertEqual(self.select(4), self.select(4))

    def test_shortfall_reported(self):
        sample, summary = self.select(20)
        self.assertEqual(len(sample), 8)
        self.assertEqual((summary["selected"], summary["shortfall"]), (8, 12))

    def test_returned_alerts_carry_only_alert_fields(self):
        tagged = [dict(a, vulnerable=True) for a in self.alerts]
        sample, _ = split_mod.select_sample(tagged, self.key, self.split, "CWE-89", 4, 201)
        for item in sample:
            self.assertEqual(set(item), ALERT_FIELDS)


class GoldenRule(unittest.TestCase):
    """The answer key never reaches the LLM-side files."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        with redirect_stdout(io.StringIO()) as stdout:
            run.main(["--semgrep", str(SEMGREP), "--answer-key", str(ANSWER_KEY), "--out", str(cls.out)])
        cls.printed = stdout.getvalue()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_all_outputs_written(self):
        for name in ("alerts.json", "selected_alerts.json", "ingest_report.json", "split.json",
                     "scanner_predictions.json", "baseline.json"):
            self.assertTrue((self.out / name).is_file(), name)

    def test_llm_side_files_hold_no_answer_key_data(self):
        alerts = json.loads((self.out / "alerts.json").read_text(encoding="utf-8"))
        selected = json.loads((self.out / "selected_alerts.json").read_text(encoding="utf-8"))
        self.assertEqual(len(alerts), 9)
        for item in alerts + selected["alerts"]:
            self.assertEqual(set(item), ALERT_FIELDS)
        for name in ("alerts.json", "selected_alerts.json"):
            text = (self.out / name).read_text(encoding="utf-8").lower()
            for word in ("vulnerable", "category", "true", "false", "real vulnerability"):
                self.assertNotIn(word, text, f"{word!r} found in {name}")

    def test_evaluator_accepts_selected_alerts(self):
        selected = json.loads((self.out / "selected_alerts.json").read_text(encoding="utf-8"))
        cases = evaluate.load_cases(self.out / "selected_alerts.json")
        self.assertEqual(cases, sorted(a["case_id"] for a in selected["alerts"]))

    def test_printed_tables_cover_both_modes(self):
        self.assertIn('mode "file"', self.printed)
        self.assertIn('mode "cwe"', self.printed)
        self.assertIn("| **overall** |", self.printed)


class BenchmarkRootFallback(unittest.TestCase):
    def test_fallback_to_local_clone(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(config._benchmark_root({}, tmp))
            local = Path(tmp) / "Context" / "tmp" / "BenchmarkJava"
            local.mkdir(parents=True)
            self.assertEqual(config._benchmark_root({}, tmp), str(local))
            self.assertIsInstance(config._benchmark_root({}, tmp), str)

    def test_environment_variable_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "Context" / "tmp" / "BenchmarkJava").mkdir(parents=True)
            self.assertEqual(config._benchmark_root({"BENCHMARK_ROOT": "/elsewhere"}, tmp), "/elsewhere")

    def test_empty_environment_variable_counts_as_unset(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(config._benchmark_root({"BENCHMARK_ROOT": ""}, tmp))
            local = Path(tmp) / "Context" / "tmp" / "BenchmarkJava"
            local.mkdir(parents=True)
            self.assertEqual(config._benchmark_root({"BENCHMARK_ROOT": ""}, tmp), str(local))


if __name__ == "__main__":
    unittest.main()
