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
        self.request = request
        self.last_call = {
            "model": "fixture-model",
            "latency_seconds": 0.25,
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.001},
        }
        return self.response


class SequenceFactory:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.created = []

    def __call__(self):
        caller = CannedCaller(next(self.responses))
        self.created.append(caller)
        return caller


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

    def test_single_agent_repairs_a_verdict_that_conflicts_with_its_analysis(self):
        contradictory = {
            "verdict": "false_positive",
            "explanation": "Untrusted input reaches the query without protection.",
            "citations": [{"file": ALERT["file"], "line": 2, "quote": "input"}],
            "guidance": [],
            "analysis": {
                "source": "input", "sink": "query",
                "reaches_sink": "yes", "protection": "none",
                "protection_effective": "no",
            },
        }
        repaired = dict(contradictory, verdict="true_positive")
        factory = SequenceFactory([contradictory, repaired])

        run = pipeline.triage(
            ALERT, mode="single", caller_factory=factory,
            kb=EmptyKnowledgeBase(), benchmark_root=self.root)

        self.assertEqual(len(factory.created), 2)
        self.assertEqual(run["review"]["verdict"], "true_positive")
        self.assertEqual(run["validated"]["verdict"], "true_positive")
        self.assertEqual(run["review"]["usage"]["cost"], 0.002)

    def test_cwe_specific_checklist_is_routed_into_the_system_prompt(self):
        response = {
            "verdict": "human_review", "explanation": "More analysis needed.",
            "citations": [{"file": ALERT["file"], "line": 2, "quote": "input"}],
            "guidance": [],
        }
        expectations = {
            "CWE-78": "command string versus an argument or environment array",
            "CWE-90": "LDAP filter construction",
        }
        for cwe, expected in expectations.items():
            with self.subTest(cwe=cwe):
                caller = CannedCaller(response)
                pipeline.triage(
                    dict(ALERT, cwe=cwe), mode="single", caller_factory=lambda: caller,
                    kb=EmptyKnowledgeBase(), benchmark_root=self.root)
                self.assertIn(expected, caller.request["system"])

    def test_payload_includes_a_helper_far_beyond_the_alert(self):
        source = self.root / ALERT["file"]
        lines = ["class Demo {", "String query = helper(input);"]
        lines += [f"int filler{i} = {i};" for i in range(3, 90)]
        lines += ["String helper(String value) {", "return value;", "}", "}"]
        source.write_text("\n".join(lines) + "\n", encoding="utf-8")
        response = {
            "verdict": "human_review", "explanation": "More analysis needed.",
            "citations": [{"file": ALERT["file"], "line": 2, "quote": "int filler2"}],
            "guidance": [],
        }

        run = pipeline.triage(
            ALERT, mode="single", caller_factory=lambda: CannedCaller(response),
            kb=EmptyKnowledgeBase(), benchmark_root=self.root)

        self.assertIn(
            "90: String helper(String value) {",
            run["payload"]["source"]["lines"])

    def test_payload_includes_directly_referenced_project_helper_file(self):
        source = self.root / ALERT["file"]
        source.write_text(
            "class Demo {\nString query = helpers.Transform.clean(input);\n}\n",
            encoding="utf-8")
        helper_file = "src/main/java/helpers/Transform.java"
        helper = self.root / helper_file
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_text(
            "package helpers;\npublic class Transform {\n"
            "public static String clean(String value) { return value; }\n}\n",
            encoding="utf-8")
        response = {
            "verdict": "human_review", "explanation": "More analysis needed.",
            "citations": [{"file": helper_file, "line": 3, "quote": "String clean"}],
            "guidance": [],
        }
        caller = CannedCaller(response)

        run = pipeline.triage(
            ALERT, mode="single", caller_factory=lambda: caller,
            kb=EmptyKnowledgeBase(), benchmark_root=self.root)

        related = run["payload"]["source"]["related"]
        self.assertEqual([item["file"] for item in related], [helper_file])
        self.assertIn(
            "3: public static String clean(String value) { return value; }",
            related[0]["lines"])
        self.assertIn(f"--- Related source: {helper_file}", caller.request["user"])
        self.assertTrue(run["validated"]["validated"],
                        run["validated"]["validation_errors"])

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

    def test_council_repairs_a_verdict_that_conflicts_with_its_analysis(self):
        base = {
            "verdict": "human_review", "explanation": "More evidence is needed.",
            "citations": [{"file": ALERT["file"], "line": 2, "quote": "input"}],
            "guidance": [],
            "analysis": {
                "source": "input", "sink": "query",
                "reaches_sink": "uncertain", "protection": "none shown",
                "protection_effective": "uncertain",
            },
        }
        contradictory = dict(base, verdict="false_positive",
                             explanation="Untrusted input reaches the query without protection.",
                             analysis={
                                 "source": "input", "sink": "query",
                                 "reaches_sink": "yes", "protection": "none",
                                 "protection_effective": "no",
                             })
        repaired = dict(contradictory, verdict="true_positive")
        factory = SequenceFactory([base, base, contradictory, repaired])

        run = pipeline.triage(
            ALERT, mode="council", caller_factory=factory,
            kb=EmptyKnowledgeBase(), benchmark_root=self.root)

        self.assertEqual(len(factory.created), 4)
        self.assertEqual(run["review"]["verdict"], "true_positive")
        self.assertEqual(run["validated"]["verdict"], "true_positive")
        self.assertEqual(run["review"]["usage"]["cost"], 0.004)

    def test_council_escalates_when_one_repair_is_still_inconsistent(self):
        base = {
            "verdict": "human_review", "explanation": "More evidence is needed.",
            "citations": [{"file": ALERT["file"], "line": 2, "quote": "input"}],
            "guidance": [],
            "analysis": {
                "source": "input", "sink": "query",
                "reaches_sink": "uncertain", "protection": "none shown",
                "protection_effective": "uncertain",
            },
        }
        contradictory = dict(base, verdict="false_positive",
                             explanation="Input reaches the query without protection.",
                             analysis={
                                 "source": "input", "sink": "query",
                                 "reaches_sink": "yes", "protection": "none",
                                 "protection_effective": "no",
                             })
        factory = SequenceFactory([base, base, contradictory, contradictory])

        run = pipeline.triage(
            ALERT, mode="council", caller_factory=factory,
            kb=EmptyKnowledgeBase(), benchmark_root=self.root)

        self.assertEqual(len(factory.created), 4)
        self.assertEqual(run["review"]["verdict"], "human_review")
        self.assertEqual(run["validated"]["verdict"], "human_review")
        self.assertEqual(run["review"]["usage"]["cost"], 0.004)

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
