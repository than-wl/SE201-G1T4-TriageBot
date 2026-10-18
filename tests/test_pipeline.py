"""End-to-end tests for the orchestration seam in triagebot.pipeline."""

from pathlib import Path
import json
import tempfile
import unittest

from triagebot import pipeline


ALERT = {
    "case_id": "BenchmarkTest00001",
    "file": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java",
    "rule_id": "java.lang.security.audit.sqli",
    "cwe": "CWE-89",
    "start_line": 2,
    "end_line": 2,
    "message": "SQL query built from request data",
}


class EmptyKnowledgeBase:
    def retrieve(self, alert, extra_terms=None):
        return {"source": "fixture", "cwe_matched": True, "chunks": []}


class CannedCaller:
    def __init__(self, response):
        self.response = response
        self.last_call = None

    def complete(self, request):
        self.last_call = {
            "model": "fixture-model",
            "latency_seconds": 0.25,
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.001},
        }
        return self.response


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        source = self.root / ALERT["file"]
        source.parent.mkdir(parents=True)
        source.write_text("class Demo {\nString query = input;\n}\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_single_agent_runs_from_alert_to_validated_result(self):
        response = {
            "verdict": "true_positive",
            "explanation": "The query uses `input`.",
            "citations": [{"file": ALERT["file"], "line": 2, "quote": "String query = input;"}],
            "guidance": [],
        }

        run = pipeline.triage(
            ALERT,
            mode="single",
            caller_factory=lambda: CannedCaller(response),
            kb=EmptyKnowledgeBase(),
            benchmark_root=self.root,
        )

        self.assertEqual(run["case_id"], ALERT["case_id"])
        self.assertEqual(run["mode"], "single")
        self.assertEqual(run["review"]["verdict"], "true_positive")
        self.assertEqual(run["review"]["model"], "fixture-model")
        self.assertEqual(run["validated"]["verdict"], "true_positive")
        self.assertTrue(run["validated"]["validated"])
        self.assertEqual(run["validated"]["usage"]["cost"], 0.001)

    def test_council_runs_both_specialists_then_chair_and_sums_usage(self):
        response = {
            "verdict": "false_positive",
            "explanation": "The value `input` is fixed in this fixture.",
            "citations": [{"file": ALERT["file"], "line": 2, "quote": "input"}],
            "guidance": [],
        }
        created = []

        def factory():
            caller = CannedCaller(response)
            created.append(caller)
            return caller

        run = pipeline.triage(
            ALERT,
            mode="council",
            caller_factory=factory,
            kb=EmptyKnowledgeBase(),
            benchmark_root=self.root,
        )

        self.assertEqual(len(created), 3)
        self.assertEqual([r["role"] for r in run["role_reports"]],
                         ["analyst", "skeptic", "chair"])
        self.assertEqual(run["review"]["role"], "chair")
        self.assertEqual(run["review"]["usage"]["prompt_tokens"], 30)
        self.assertEqual(run["review"]["usage"]["completion_tokens"], 15)
        self.assertEqual(run["review"]["usage"]["cost"], 0.003)
        self.assertTrue(run["validated"]["validated"])
        self.assertEqual(run["validated"]["verdict"], "false_positive")

    def test_sample_run_writes_evaluator_compatible_configurations(self):
        response = {
            "verdict": "true_positive",
            "explanation": "The query uses `input`.",
            "citations": [{"file": ALERT["file"], "line": 2, "quote": "input"}],
            "guidance": [],
        }
        out = self.root / "results"

        saved = pipeline.run_sample(
            [ALERT],
            modes=("single", "council"),
            out_dir=out,
            caller_factory=lambda: CannedCaller(response),
            kb=EmptyKnowledgeBase(),
            benchmark_root=self.root,
        )

        self.assertEqual(set(saved), {"B-single-agent", "C-council", "D-validated-council"})
        for name in saved:
            path = out / f"{name}.json"
            self.assertTrue(path.is_file())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["model"], "fixture-model")
            self.assertEqual(len(data["results"]), 1)
        validated = json.loads((out / "D-validated-council.json").read_text(encoding="utf-8"))
        self.assertTrue(validated["results"][0]["validated"])


if __name__ == "__main__":
    unittest.main()
