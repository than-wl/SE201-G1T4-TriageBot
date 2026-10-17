"""Offline tests for the deterministic validator. Run from the repo root: python -m unittest discover -s tests"""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from triagebot.nodes.validate import validator  # noqa: E402

FILE_A = "testcode/BenchmarkTest00001.java"
FILE_B = "testcode/BenchmarkTest00002.java"
SOURCE_A = (
    'String param = request.getParameter("id");\n'
    'String sql = "SELECT * FROM users WHERE id=\'" + param + "\'";\n'
    "statement.executeQuery(sql);\n"
)
SOURCE_B = 'String bar = "constant";\nconnection.prepareStatement(bar);\n'
CASES = {
    "BenchmarkTest00001": {"file": FILE_A, "source": SOURCE_A},
    "BenchmarkTest00002": {"file": FILE_B, "source": SOURCE_B},
}


def result(case_id="BenchmarkTest00001", file=FILE_A, line=1, quote="request.getParameter", verdict="true_positive",
           explanation="Input from `request.getParameter` reaches the query."):
    return {"case_id": case_id, "verdict": verdict, "explanation": explanation,
            "citations": [{"file": file, "line": line, "quote": quote}]}


def good_pair():
    return [result(), result("BenchmarkTest00002", FILE_B, 1, '"constant"', "false_positive",
                             "The query text is a constant.")]


def run(raw):
    return validator.validate_results(raw, CASES)


def by_id(outcome):
    return {r["case_id"]: r for r in outcome["results"]}


class AcceptedTests(unittest.TestCase):
    def test_valid_source_citation_passes(self):
        outcome = run(good_pair())
        self.assertEqual(outcome["batch_errors"], [])
        for record in outcome["results"]:
            self.assertTrue(record["validated"], record["validation_errors"])
        self.assertEqual(by_id(outcome)["BenchmarkTest00002"]["verdict"], "false_positive")

    def test_single_agent_and_council_shapes_use_same_validator(self):
        flat = run(good_pair())
        council = run(json.dumps({"cases": good_pair()}))  # council role output, as JSON text
        self.assertEqual(flat, council)

    def test_single_object_without_case_id_for_single_case(self):
        body = {k: v for k, v in result().items() if k != "case_id"}
        outcome = validator.validate_results(body, {"BenchmarkTest00001": CASES["BenchmarkTest00001"]})
        self.assertTrue(outcome["results"][0]["validated"])

    def test_model_human_review_is_valid_and_kept(self):
        outcome = run([result(verdict="human_review"), good_pair()[1]])
        record = by_id(outcome)["BenchmarkTest00001"]
        self.assertTrue(record["validated"])
        self.assertEqual(record["verdict"], "human_review")

    def test_output_is_compact_and_ordered(self):
        outcome = run(list(reversed(good_pair())))
        self.assertEqual([r["case_id"] for r in outcome["results"]], list(CASES))
        self.assertEqual(set(outcome["results"][0]), {
            "case_id", "verdict", "original_verdict", "validated", "explanation", "citations", "validation_errors"})


class RejectedTests(unittest.TestCase):
    def assert_fallback(self, outcome, case_id="BenchmarkTest00001", reason=None):
        record = by_id(outcome)[case_id]
        self.assertFalse(record["validated"])
        self.assertEqual(record["verdict"], "human_review")
        self.assertEqual(record["citations"], [])
        self.assertTrue(record["validation_errors"])
        if reason:
            self.assertTrue(any(reason in e for e in record["validation_errors"]), record["validation_errors"])
        return record

    def test_fabricated_quote_rejected(self):
        # Deliberately fabricated AI claim: claims sanitisation that is not in the source.
        fake = result(verdict="false_positive", line=2, quote="sanitizeSQL(param)",
                      explanation="The value is cleaned by `sanitizeSQL` before use.")
        record = self.assert_fallback(run([fake, good_pair()[1]]), reason="not an exact substring")
        self.assertEqual(record["original_verdict"], "false_positive")  # kept for scoring...
        self.assertEqual(record["verdict"], "human_review")  # ...but never trusted or passed through

    def test_wrong_file_rejected(self):
        self.assert_fallback(run([result(file=FILE_B), good_pair()[1]]), reason="wrong file")

    def test_out_of_range_line_rejected(self):
        for line in (0, 4, 999, -1):
            self.assert_fallback(run([result(line=line), good_pair()[1]]), reason="out of range")

    def test_non_integer_line_rejected(self):
        for line in ("1", 1.0, True, None):
            self.assert_fallback(run([result(line=line), good_pair()[1]]), reason="out of range")

    def test_empty_or_blank_quote_rejected(self):
        for quote in ("", "   ", None):
            self.assert_fallback(run([result(quote=quote), good_pair()[1]]), reason="empty quote")

    def test_quote_must_be_on_cited_line(self):
        self.assert_fallback(run([result(line=3), good_pair()[1]]), reason="exact substring")

    def test_line_number_prefix_in_quote_rejected(self):
        self.assert_fallback(run([result(quote="1: String param"), good_pair()[1]]), reason="exact substring")

    def test_malformed_json_rejected(self):
        for raw in ("{not json", "", b"\xff\xfe", "[1, 2"):
            outcome = run(raw)
            self.assertIn("Malformed JSON", outcome["batch_errors"])
            for case_id in CASES:
                self.assert_fallback(outcome, case_id)

    def test_missing_output_rejected(self):
        outcome = run(None)
        for case_id in CASES:
            self.assert_fallback(outcome, case_id)

    def test_unrecognised_top_level_shape_rejected(self):
        for raw in ({"verdict": "true_positive"}, 42, "null", {"cases": "x"}):
            outcome = run(raw)
            self.assertTrue(outcome["batch_errors"])
            for case_id in CASES:
                self.assert_fallback(outcome, case_id)

    def test_missing_case_rejected(self):
        outcome = run([result()])
        self.assert_fallback(outcome, "BenchmarkTest00002", reason="No result returned")
        self.assertTrue(by_id(outcome)["BenchmarkTest00001"]["validated"])
        self.assertEqual(len(outcome["results"]), 2)

    def test_duplicate_case_rejected_and_neither_copy_trusted(self):
        outcome = run(good_pair() + [result(verdict="false_positive")])
        self.assert_fallback(outcome, "BenchmarkTest00001", reason="Duplicate")
        self.assertTrue(by_id(outcome)["BenchmarkTest00002"]["validated"])
        self.assertTrue(any("Duplicate" in e for e in outcome["batch_errors"]))

    def test_unknown_case_reported_and_not_returned(self):
        outcome = run(good_pair() + [result("BenchmarkTest99999")])
        self.assertEqual(outcome["unknown_case_ids"], ["BenchmarkTest99999"])
        self.assertEqual([r["case_id"] for r in outcome["results"]], list(CASES))
        self.assertTrue(all(r["validated"] for r in outcome["results"]))

    def test_missing_or_bad_case_id_is_unknown(self):
        for bad in (None, 5, ["x"]):
            item = result()
            item["case_id"] = bad
            outcome = run([item, good_pair()[1]])
            self.assertEqual(len(outcome["unknown_case_ids"]), 1)
            self.assert_fallback(outcome, "BenchmarkTest00001", reason="No result returned")

    def test_unsupported_verdict_rejected(self):
        for verdict in ("vulnerable", "TRUE_POSITIVE", "", None, ["true_positive"], {}):
            record = self.assert_fallback(run([result(verdict=verdict), good_pair()[1]]), reason="Invalid verdict")
            self.assertIsNone(record["original_verdict"])

    def test_missing_explanation_rejected(self):
        for explanation in ("", "  ", None, 5):
            self.assert_fallback(run([result(explanation=explanation), good_pair()[1]]), reason="Missing explanation")

    def test_missing_citations_rejected(self):
        for citations in ([], None, "x"):
            item = result()
            item["citations"] = citations
            self.assert_fallback(run([item, good_pair()[1]]), reason="Missing citations")

    def test_malformed_citation_rejected(self):
        for citation in ("x", {"file": FILE_A, "line": 1}, {"file": FILE_A, "line": 1, "quote": "a", "extra": 1}):
            item = result()
            item["citations"] = [citation]
            self.assert_fallback(run([item, good_pair()[1]]), reason="invalid shape")

    def test_one_bad_citation_among_good_rejects_result(self):
        item = result()
        item["citations"].append({"file": FILE_A, "line": 2, "quote": "not in source"})
        self.assert_fallback(run([item, good_pair()[1]]), reason="Citation 2")

    def test_extra_or_missing_result_keys_rejected(self):
        extra = dict(result(), confidence=0.9)
        self.assert_fallback(run([extra, good_pair()[1]]), reason="Invalid result shape")
        missing = result()
        del missing["explanation"]
        self.assert_fallback(run([missing, good_pair()[1]]), reason="Invalid result shape")

    def test_non_dict_items_rejected(self):
        outcome = run([result(), "garbage", None])
        self.assertEqual(len(outcome["unknown_case_ids"]), 2)
        self.assert_fallback(outcome, "BenchmarkTest00002", reason="No result returned")

    def test_unknown_identifier_in_explanation_rejected(self):
        item = result(explanation="Value passes through `Encoder.escapeSql()` first.")
        self.assert_fallback(run([item, good_pair()[1]]), reason="does not appear in the source")

    def test_known_identifiers_and_non_identifiers_accepted(self):
        item = result(explanation="`request.getParameter()` feeds `param`; SQL like `SELECT *` is ignored.")
        self.assertTrue(by_id(run([item, good_pair()[1]]))["BenchmarkTest00001"]["validated"])

    def test_invalid_never_becomes_false_positive(self):
        broken = [result(verdict="false_positive", quote="fabricated"), result(
            "BenchmarkTest00002", FILE_B, 99, "x", "false_positive")]
        outcome = run(broken)
        self.assertTrue(all(r["verdict"] == "human_review" and not r["validated"] for r in outcome["results"]))

    def test_inputs_are_not_mutated(self):
        data = good_pair()
        before = copy.deepcopy(data)
        run(data)
        self.assertEqual(data, before)

    def test_empty_cases_is_programmer_error(self):
        with self.assertRaises(ValueError):
            validator.validate_results([], {})


class CompatibilityTests(unittest.TestCase):
    def test_body_check_agrees_with_feasibility_smoke_validate(self):
        try:
            sys.path.insert(0, str(ROOT / "verification"))
            import openrouter_smoke  # feasibility script, imported read-only; needs python-dotenv
        except ImportError:
            self.skipTest("python-dotenv not installed")
        good = {k: v for k, v in result().items() if k != "case_id"}
        bad = copy.deepcopy(good)
        bad["citations"][0]["quote"] = "sanitizeSQL(param)"
        for value in (good, bad, {}, {"verdict": "x"}):
            self.assertEqual(bool(openrouter_smoke.validate(value, FILE_A, SOURCE_A)),
                             bool(validator.check_body(value, FILE_A, SOURCE_A)))


if __name__ == "__main__":
    unittest.main()
