"""Phase 1 graph regressions; fixtures only, no network or API keys."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from triagebot import pipeline
from triagebot.council_graph import CouncilContext, build_council_graph
from triagebot.nodes.review.prompts import to_prompt_block
from test_pipeline import ALERT, EmptyKnowledgeBase


def valid_response():
    return {
        "verdict": "true_positive",
        "explanation": "The query uses `input`.",
        "citations": [{"file": ALERT["file"], "line": 2, "quote": "input"}],
        "guidance": [],
    }


class RecordingFactory:
    def __init__(self, responses=None, on_call=None):
        self.responses = responses or {}
        self.on_call = on_call
        self.calls = []
        self.created = 0
        self.lock = threading.Lock()

    def __call__(self):
        with self.lock:
            self.created += 1
        owner = self

        class Caller:
            last_call = None

            def complete(self, request):
                role = next(
                    (r for r in ("analyst", "skeptic", "chair")
                     if f"You are the {r.title()}" in request["system"]), "single"
                )
                with owner.lock:
                    owner.calls.append((role, deepcopy(request)))
                if owner.on_call:
                    owner.on_call(role)
                self.last_call = {
                    "model": "fixture-model", "latency_seconds": 0.25,
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5,
                              "cost": 0.001},
                }
                return deepcopy(owner.responses.get(role, valid_response()))

        return Caller()


class CouncilGraphTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        source = self.root / ALERT["file"]
        source.parent.mkdir(parents=True)
        source.write_text("class Demo {\nString query = input;\n}\n", encoding="utf-8")

    def run_council(self, factory=None, alert=None):
        return pipeline.triage(
            alert or deepcopy(ALERT), mode="council",
            caller_factory=factory or RecordingFactory(),
            kb=EmptyKnowledgeBase(), benchmark_root=self.root,
        )

    def context(self, factory):
        return CouncilContext(factory, EmptyKnowledgeBase(), self.root)

    def test_specialists_really_overlap_and_chair_runs_once_after_both(self):
        barrier = threading.Barrier(2, timeout=10)
        completed = set()
        lock = threading.Lock()

        def on_call(role):
            if role in ("analyst", "skeptic"):
                # A sequential implementation breaks this barrier and fails.
                barrier.wait()
                with lock:
                    completed.add(role)
            else:
                with lock:
                    self.assertEqual(completed, {"analyst", "skeptic"})

        factory = RecordingFactory(on_call=on_call)
        result = self.run_council(factory)
        self.assertEqual([r for r, _ in factory.calls].count("chair"), 1)
        self.assertEqual(factory.created, 3)
        self.assertTrue(result["validated"]["validated"])

    def test_identical_evidence_and_no_specialist_cross_anchoring(self):
        factory = RecordingFactory()
        result = self.run_council(factory)
        evidence = to_prompt_block(result["payload"])
        requests = dict(factory.calls)
        self.assertEqual(requests["analyst"]["user"], evidence)
        self.assertEqual(requests["skeptic"]["user"], evidence)
        self.assertTrue(requests["chair"]["user"].startswith(evidence))
        self.assertIn("--- Analyst report", requests["chair"]["user"])
        self.assertIn("--- Skeptic report", requests["chair"]["user"])
        for role in ("analyst", "skeptic"):
            self.assertNotIn("--- Analyst report", requests[role]["user"])
            self.assertNotIn("--- Skeptic report", requests[role]["user"])

    def test_state_updates_have_separate_specialist_keys_and_are_json_safe(self):
        graph = build_council_graph()
        updates = list(graph.stream(
            {"alert": deepcopy(ALERT)}, context=self.context(RecordingFactory()),
            stream_mode="updates",
        ))
        names = [next(iter(update)) for update in updates]
        self.assertEqual(names[0], "build_context")
        self.assertEqual(set(names[1:3]), {"analyst", "skeptic"})
        self.assertEqual(names[3:], ["chair", "validate"])
        state = {"alert": deepcopy(ALERT)}
        for update in updates:
            for name, delta in update.items():
                if name in ("analyst", "skeptic"):
                    self.assertEqual(set(delta), {f"{name}_report", f"{name}_elapsed_seconds"})
                state.update(delta)
        json.dumps(state)
        self.assertEqual(set(state), {
            "alert", "payload", "analyst_report", "skeptic_report",
            "review", "role_reports", "validated", "analyst_elapsed_seconds",
            "skeptic_elapsed_seconds", "chair_elapsed_seconds",
        })

    def test_phase1_graph_has_no_checkpointer_or_human_interrupts(self):
        graph = build_council_graph()
        self.assertIsNone(graph.checkpointer)
        output = graph.invoke(
            {"alert": deepcopy(ALERT)}, context=self.context(RecordingFactory())
        )
        self.assertNotIn("__interrupt__", output)
        self.assertIn("validated", output)

    def test_single_baseline_never_builds_a_graph(self):
        factory = RecordingFactory()
        with patch("triagebot.council_graph.build_council_graph",
                   side_effect=AssertionError("baseline entered LangGraph")):
            result = pipeline.triage(
                deepcopy(ALERT), mode="single", caller_factory=factory,
                kb=EmptyKnowledgeBase(), benchmark_root=self.root,
            )
        self.assertEqual([r for r, _ in factory.calls], ["single"])
        self.assertEqual(len(result["role_reports"]), 1)
        self.assertTrue(result["validated"]["validated"])

    def test_transport_error_contract_escalates_without_retry(self):
        factory = RecordingFactory(responses={
            role: {"_error": "fixture timeout"}
            for role in ("analyst", "skeptic", "chair")
        })
        result = self.run_council(factory)
        self.assertEqual(factory.created, 3)
        self.assertEqual(len(factory.calls), 3)
        self.assertEqual(result["validated"]["verdict"], "human_review")
        self.assertFalse(result["validated"]["validated"])
        self.assertTrue(result["validated"]["validation_errors"])

    def test_one_specialist_failure_is_still_joined_and_chair_can_review(self):
        factory = RecordingFactory(responses={"analyst": {"_error": "fixture error"}})
        result = self.run_council(factory)
        self.assertEqual(len(factory.calls), 3)
        self.assertEqual(result["role_reports"][0]["verdict"], "human_review")
        self.assertIn("Model call failed", dict(factory.calls)["chair"]["user"])
        # Preserve existing behaviour: no new gate overrules a supported Chair.
        self.assertEqual(result["validated"]["verdict"], "true_positive")

    def test_fabricated_chair_quote_is_rejected_after_graph_review(self):
        bad = valid_response()
        bad["citations"][0]["quote"] = "fabricated source text"
        result = self.run_council(RecordingFactory(responses={"chair": bad}))
        self.assertEqual(result["review"]["verdict"], "true_positive")
        self.assertEqual(result["validated"]["original_verdict"], "true_positive")
        self.assertEqual(result["validated"]["verdict"], "human_review")
        self.assertFalse(result["validated"]["validated"])

    def test_usage_and_order_preserve_the_public_contract(self):
        result = self.run_council()
        self.assertEqual(set(result), {
            "case_id", "mode", "payload", "role_reports", "review", "validated",
        })
        self.assertEqual([r["role"] for r in result["role_reports"]],
                         ["analyst", "skeptic", "chair"])
        self.assertEqual(result["role_reports"][2], result["review"])
        for record in (result["review"], result["validated"]):
            self.assertEqual(record["usage"]["prompt_tokens"], 30)
            self.assertEqual(record["usage"]["completion_tokens"], 15)
            self.assertAlmostEqual(record["usage"]["cost"], 0.003)
            self.assertEqual(record["model"], "fixture-model")
            self.assertGreaterEqual(record["latency_seconds"], 0)

    def test_unexpected_node_exception_is_not_retried(self):
        def fail(role):
            if role == "chair":
                raise RuntimeError("unexpected fixture exception")
        factory = RecordingFactory(on_call=fail)
        with self.assertRaisesRegex(RuntimeError, "unexpected fixture exception"):
            self.run_council(factory)
        self.assertEqual([r for r, _ in factory.calls].count("chair"), 1)

    def test_same_compiled_graph_isolates_concurrent_invocation_contexts(self):
        graph = build_council_graph()
        second = dict(ALERT, case_id="BenchmarkTest00002")
        factory_a = RecordingFactory()
        factory_b = RecordingFactory(responses={"chair": dict(
            valid_response(), verdict="false_positive"
        )})
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(graph.invoke, {"alert": deepcopy(ALERT)},
                            context=self.context(factory_a))
            b = pool.submit(graph.invoke, {"alert": second},
                            context=self.context(factory_b))
            state_a, state_b = a.result(), b.result()
        self.assertEqual(state_a["review"]["case_id"], ALERT["case_id"])
        self.assertEqual(state_b["review"]["case_id"], second["case_id"])
        self.assertEqual(state_a["review"]["verdict"], "true_positive")
        self.assertEqual(state_b["review"]["verdict"], "false_positive")
        self.assertEqual(len(factory_a.calls), 3)
        self.assertEqual(len(factory_b.calls), 3)

    def test_invalid_mode_rejected_before_model_calls(self):
        factory = RecordingFactory()
        with self.assertRaisesRegex(ValueError, "unsupported review mode"):
            pipeline.triage(ALERT, mode="unknown", caller_factory=factory)
        self.assertEqual(factory.created, 0)

    def test_source_path_escape_rejected_before_model_calls(self):
        factory = RecordingFactory()
        with self.assertRaisesRegex(ValueError, "escapes benchmark root"):
            self.run_council(factory, alert=dict(ALERT, file="../../outside.java"))
        self.assertEqual(factory.created, 0)

    def test_missing_source_rejected_before_model_calls(self):
        factory = RecordingFactory()
        with self.assertRaisesRegex(FileNotFoundError, "benchmark source missing"):
            self.run_council(factory, alert=dict(ALERT, file="missing.java"))
        self.assertEqual(factory.created, 0)


if __name__ == "__main__":
    unittest.main()
