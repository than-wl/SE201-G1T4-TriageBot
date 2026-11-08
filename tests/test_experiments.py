"""Offline tests for the experiment runner (triagebot/experiments.py) and its CLI.

Runs use a canned fixture caller (no network, no key, no cost), a fake
benchmark checkout, the ingest fixtures' answer key, and case sets built from
the ingest fixtures into a temporary data/samples/. The real registry
(experiments/registry.json) is used throughout.
"""
import isolated_store  # noqa: F401  (first: keeps every test off the real vector store)
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from rich.console import Console

from triagebot import __main__ as cli, config, experiments, profiles
from triagebot.nodes.ingest import eval_sets

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/ingest"
ANSWER_KEY = FIXTURES / "expectedresults.csv"
SECRET = "sk-or-v1-TEST-SENTINEL-DO-NOT-WRITE"
RULES = [
    {"name": "pilot", "partition": "dev", "sizes": {"CWE-89": 2}, "exclude": [], "purpose": "fixture"},
    {"name": "comparison", "partition": "dev", "sizes": {"CWE-78": 1, "CWE-79": 1},
     "exclude": ["pilot"], "purpose": "fixture"},
    {"name": "final-test", "partition": "dev", "sizes": {"CWE-78": 1, "CWE-79": 1}, "exclude": [],
     "purpose": "fixture"},
]
LABEL_KEYS = {"vulnerable", "category", "expected", "real vulnerability", "label"}
CLEAN = {"commit": "c" * 40, "dirty": False, "dirty_paths": []}


class StubKnowledgeBase:
    """Stands in for semantic retrieval in the step 6 tests (no catalogue, no fastembed)."""

    def __init__(self, *args, **kwargs):
        pass

    def retrieve(self, alert, extra_terms=None):
        return {"source": "fixture", "cwe_matched": True, "chunks": []}


class FixtureCallers:
    """A caller factory: cites the alert line, a verdict per role, fixed usage."""

    def __init__(self, fail_on_call=None, error_on_call=None):
        self.calls = 0
        self.fail_on_call, self.error_on_call = fail_on_call, error_on_call

    def __call__(self):
        owner = self

        class Caller:
            last_call = None

            def complete(self, request):
                owner.calls += 1
                if owner.calls == owner.fail_on_call:
                    raise RuntimeError("connection dropped")
                if owner.calls == owner.error_on_call:
                    return {"_error": "HTTP 500: provider error"}
                self.last_call = {"model": "fixture-model", "latency_seconds": 0.5,
                                  "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                                            "cost": 0.002}}
                user = request["user"]
                file = re.search(r"^file: (.+)$", user, re.M).group(1)
                line = int(re.search(r"^lines: (\d+)-", user, re.M).group(1))
                verdict = "false_positive" if "Skeptic" in request["system"] else "true_positive"
                return {"verdict": verdict, "explanation": "Input reaches the sink.",
                        "citations": [{"file": file, "line": line, "quote": "input"}],
                        "guidance": []}
        return Caller()


def plain_console(stream):
    return Console(file=stream, width=200, color_system=None, highlight=False)


def capture(func, *args, answers=(), **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.multiple(cli, console=plain_console(out), err_console=plain_console(err)), \
            mock.patch("builtins.input", side_effect=list(answers)) as asked, \
            redirect_stdout(out), redirect_stderr(err):
        result = func(*args, **kwargs)
    return result, out.getvalue(), err.getvalue(), asked.call_count


class ExperimentTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.samples = self.tmp / "samples"
        self.out = self.tmp / "experiments"
        self.bench = self.tmp / "BenchmarkJava"
        evidence = self.tmp / "evidence" / "old"
        evidence.mkdir(parents=True)
        (evidence / "selected_alerts.json").write_text(
            json.dumps({"alerts": [{"case_id": "BenchmarkTest00009"}]}), encoding="utf-8")
        files = eval_sets.build(FIXTURES / "semgrep.json", ANSWER_KEY, self.tmp / "evidence",
                                pilot_reference=False, rules=RULES, samples_dir=self.samples)
        eval_sets.write(files, self.samples)
        self.alerts = json.loads(files["comparison.json"])["alerts"]
        for alert in self.alerts:
            source = self.bench / alert["file"]
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("class Demo {\n" + "String v = input;\n" * 120 + "}\n", encoding="utf-8")
        patcher = mock.patch.multiple(config, SAMPLES_DIR=self.samples, EXPERIMENTS_OUT=self.out,
                                      ANSWER_KEY=ANSWER_KEY, BENCHMARK_ROOT=str(self.bench))
        patcher.start()
        self.addCleanup(patcher.stop)
        env = mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": SECRET, "OPENROUTER_MODEL": "fixture-model"})
        env.start()
        self.addCleanup(env.stop)

    def run_cli(self, step, *, answers=("y",), callers=None, **kwargs):
        callers = callers or FixtureCallers()
        result = capture(cli.experiment_run, step, answers=answers, caller_factory=callers,
                         benchmark_root=str(self.bench), **kwargs)
        return result, callers

    def run_step_1(self):
        (code, _, errors, _), _ = self.run_cli("1")                     # before + after
        self.assertEqual((code, errors), (0, ""))
        (code, _, errors, _), _ = self.run_cli("1", side="after", repeat=2)
        self.assertEqual((code, errors), (0, ""))

    # --- registry and listing -------------------------------------------------------------

    def test_registry_describes_the_six_steps(self):
        steps = experiments.load_registry()
        self.assertEqual([s["id"] for s in steps], ["1", "1b", "1c", "2", "3", "4", "5", "6"])
        by_id = {s["id"]: s for s in steps}
        self.assertEqual(by_id["1"]["before"], {"profile": "base", "modes": ["single"]})
        self.assertEqual((by_id["1"]["after"]["profile"], by_id["1"]["after"]["repeats"]), ("base", 2))
        for step_id, before, profile in (("2", "1-after", "evidence"), ("3", "2-after", "worksheet"),
                                         ("4", "2-after", "semantic")):
            self.assertEqual(by_id[step_id]["before"], {"reuse": before})
            self.assertEqual(by_id[step_id]["after"], {"profile": profile, "modes": ["council"]})
        for step_id in "1234":
            self.assertEqual(by_id[step_id]["case_set"], "comparison")
            self.assertTrue(by_id[step_id]["question"])
        self.assertEqual((by_id["5"]["case_set"], by_id["6"]["case_set"]), ("mutation", "final-test"))
        self.assertNotIn("planned", by_id["5"])          # runnable since PROMPT_05 (decision 30)
        for side in ("before", "after"):
            self.assertEqual((by_id["5"][side]["profile"], by_id["5"][side]["modes"]),
                             ("semantic", ["single", "council"]))
        self.assertEqual((by_id["5"]["after"]["source"], by_id["5"]["after"]["labels"]), ("mutant", "flipped"))
        self.assertNotIn("source", by_id["5"]["before"])
        self.assertEqual((by_id["5"]["scoring"], by_id["5"]["same_commit"]), ("mutation", True))
        self.assertNotIn("planned", by_id["6"])          # runnable: the final version, run once
        self.assertEqual(by_id["6"]["before"], {"profile": "semantic", "modes": ["single"]})
        self.assertEqual(by_id["6"]["after"], {"profile": "semantic", "modes": ["council"]})
        self.assertIn("rule", by_id["4"])

    def test_list_and_show_work_offline_before_any_run(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.multiple(config, ANSWER_KEY=None):
            code, printed, errors, _ = capture(cli.main, ["experiment", "list"])
            self.assertEqual((code, errors), (0, ""))
            for step in experiments.load_registry():
                self.assertIn(step["question"], printed)
            self.assertIn("not run yet", printed)
            self.assertNotIn("planned (later task)", printed)     # every step is runnable
            code, printed, errors, _ = capture(cli.main, ["experiment", "show", "1"])
        self.assertEqual((code, errors), (0, ""))
        self.assertIn("No saved run for step 1 yet.", printed)
        self.assertIn("python -m triagebot experiment run 1", printed)

    def test_planned_and_reused_sides_cannot_be_run(self):
        with self.assertRaisesRegex(experiments.ExperimentError, "reuses the saved run 1-after"):
            experiments.plan("2", side="before")
        planned = [{"id": "9", "title": "Later", "question": "Later?", "case_set": "comparison",
                    "planned": "later task"}]
        with self.assertRaisesRegex(experiments.ExperimentError, "not runnable yet"):
            experiments.plan("9", registry=planned)
        self.assertEqual(experiments.list_steps(registry=planned)[0]["state"], "planned (later task)")
        with self.assertRaisesRegex(experiments.ExperimentError, "--repeat must be 1"):
            experiments.plan("2", side="after", repeat=2)
        code, _, errors, _ = capture(cli.main, ["experiment", "show", "9"])
        self.assertEqual(code, 1)
        self.assertIn("unknown step '9'", errors)

    # --- the paid run and its confirmation --------------------------------------------------

    def test_run_shows_the_estimate_and_stops_when_answered_no(self):
        callers = FixtureCallers()
        for answer in ("n", ""):
            (code, printed, errors, asked), _ = self.run_cli("1", side="after", limit=1,
                                                             answers=(answer,), callers=callers)
            self.assertEqual((code, errors, asked), (0, "", 1))
        for text in ("Step 1, after side: Does a council beat one agent?", "comparison: 2 cases",
                     "base (window ±25, related source off, worksheet off, retrieval map)",
                     "1 to run (first 1 of 2, --limit 1)", "3 (3 council per case)",
                     "about US$0.02", "Make 3 paid model calls", "Cancelled: no model calls were made."):
            self.assertIn(text, printed)
        self.assertEqual(callers.calls, 0)
        self.assertFalse(self.out.exists())

    def test_cli_run_arguments_reach_the_runner(self):
        with mock.patch.object(cli, "experiment_run", return_value=0) as run:
            cli.main(["experiment", "run", "1", "--side", "after", "--repeat", "2", "--limit", "5"])
            cli.main(["experiment", "run", "3"])
            cli.main(["experiment", "run", "6", experiments.RERUN_FLAG])
        self.assertEqual(run.call_args_list, [
            mock.call("1", "after", 2, 5, None, rerun_final_test=False),
            mock.call("3", None, 1, None, None, rerun_final_test=False),
            mock.call("6", None, 1, None, None, rerun_final_test=True)])

    def test_estimate_uses_the_per_case_constants(self):
        before, after = experiments.plan("1")
        self.assertEqual((before["calls"], before["estimated_cost"]),
                         (2, round(2 * config.EXPERIMENT_COST_PER_CASE["single"], 4)))
        self.assertEqual((after["calls"], after["estimated_cost"]),
                         (6, round(2 * config.EXPERIMENT_COST_PER_CASE["council"], 4)))
        self.assertEqual(after["max_repair_calls"], 0)          # base profile: no worksheet

    def test_run_needs_the_answer_key_before_any_call(self):
        callers = FixtureCallers()
        (code, _, errors, asked), _ = self.run_cli("1", answer_key=self.tmp / "missing.csv",
                                                   callers=callers)
        with mock.patch.multiple(config, ANSWER_KEY=None):
            (code, _, errors, asked), _ = self.run_cli("1", callers=callers)
        self.assertEqual((code, asked, callers.calls), (1, 0, 0))
        self.assertIn("answer key not found", errors)

    def test_run_saves_after_every_case_and_resumes_without_repeating(self):
        plan = experiments.plan("1", side="after")[0]
        with self.assertRaisesRegex(RuntimeError, "connection dropped"):
            experiments.execute(plan, ANSWER_KEY, FixtureCallers(fail_on_call=4), str(self.bench))
        folder = self.out / "1-after"
        lines = (folder / experiments.RESULTS_LOG).read_text(encoding="utf-8").splitlines()
        self.assertEqual([json.loads(line)["case_id"] for line in lines], [self.alerts[0]["case_id"]])
        self.assertEqual(experiments.run_status("1-after")["state"], "partial")
        with open(folder / experiments.RESULTS_LOG, "a", encoding="utf-8", newline="\n") as log:
            log.write('{"case_id": "BenchmarkTest0')                # a line cut off by a crash

        resumed = experiments.plan("1", side="after")[0]
        self.assertEqual((resumed["already_saved"], len(resumed["remaining"])), (1, 1))
        callers = FixtureCallers()
        manifest = experiments.execute(resumed, ANSWER_KEY, callers, str(self.bench))
        self.assertEqual(callers.calls, 3)                       # only the unfinished case
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(len(manifest["sessions"]), 2)
        self.assertEqual(len((folder / experiments.RESULTS_LOG).read_text(encoding="utf-8").splitlines()), 2)
        self.assertEqual(experiments.plan("1", side="after")[0]["remaining"], [])

    def test_run_writes_every_evidence_file(self):
        self.run_step_1()
        for name, configs in (("1-before", ["B-single-agent"]),
                              ("1-after", ["C-council", "D-validated-council"]),
                              ("1-after-repeat-2", ["C-council", "D-validated-council"])):
            folder = self.out / name
            for file in configs + ["evaluation", "evaluation_by_cwe", "run_manifest"]:
                self.assertTrue((folder / f"{file}.json").is_file(), f"{name}/{file}")
            self.assertTrue((folder / "report.md").is_file())
            saved = json.loads((folder / f"{configs[0]}.json").read_text(encoding="utf-8"))
            self.assertEqual(len(saved["results"]), 2)
            by_cwe = json.loads((folder / "evaluation_by_cwe.json").read_text(encoding="utf-8"))
            self.assertEqual(sorted(by_cwe["by_cwe"]), ["CWE-78", "CWE-79"])

        manifest = json.loads((self.out / "1-after" / "run_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["profile"]["name"], "base")
        self.assertEqual(manifest["profile"]["settings"], profiles.PROFILES["base"])
        self.assertEqual(manifest["profile"]["engineering_fixes"], list(profiles.ENGINEERING_FIXES))
        set_manifest = json.loads((self.samples / "comparison.manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["case_set"]["name"], "comparison")
        self.assertEqual(manifest["case_set"]["sha256"], set_manifest["sample"]["sha256"])
        self.assertEqual(manifest["model"], {"requested": "fixture-model", "reported": ["fixture-model"]})
        self.assertEqual(manifest["temperature"], config.REVIEW_TEMPERATURE)
        self.assertIn("commit", manifest["git"])
        self.assertIn("dirty", manifest["git"])
        self.assertTrue(manifest["started_at"] and manifest["finished_at"])
        self.assertEqual(manifest["totals"], {"model_calls": 6, "failed_calls": 0, "prompt_tokens": 600,
                                              "completion_tokens": 120, "cost_usd": 0.012})

        report = (self.out / "1-after" / "report.md").read_text(encoding="utf-8")
        for text in ("# Step 1, after side: Does a council beat one agent?", "## What changed",
                     "| Precision |", "C council (raw)", "D council (validated)",
                     "python -m triagebot experiment replay 1", "`base` profile"):
            self.assertIn(text, report)

    def test_failed_calls_are_counted(self):
        plan = experiments.plan("1", side="after")[0]
        manifest = experiments.execute(plan, ANSWER_KEY, FixtureCallers(error_on_call=2), str(self.bench))
        self.assertEqual(manifest["totals"]["failed_calls"], 1)

    def test_show_puts_before_and_after_side_by_side_with_the_noise(self):
        self.run_step_1()
        table = experiments.show_table("1")
        self.assertEqual(table["headers"], ["Measure", "Before B", "After C", "After D",
                                            "After #2 C", "After #2 D", "Noise C", "Noise D"])
        self.assertEqual(table["legend"][:3], [
            "Before: run 1-before (base profile, single)",
            "After: run 1-after (base profile, council)",
            "After #2: run 1-after-repeat-2 (base profile, council)"])
        self.assertIn("1-after-repeat-2 minus 1-after", table["legend"][3])
        self.assertEqual([row[0] for row in table["rows"]], [m[0] for m in experiments.METRICS])
        rows = {row[0]: row for row in table["rows"]}
        self.assertEqual(rows["Total cost (US$)"][1:4], ["0.0040", "0.0120", "0.0120"])
        self.assertEqual(rows["Precision"][-2:], ["+0.0", "+0.0"])   # identical runs: no noise
        code, printed, errors, _ = capture(cli.main, ["experiment", "show", "1"])
        self.assertEqual((code, errors), (0, ""))
        self.assertIn("Real vulnerabilities dismissed", printed)
        self.assertIn("Noise C", printed)
        self.assertIn("the noise between identical runs", printed)

        states = {row["step"]["id"]: row["state"] for row in experiments.list_steps()}
        self.assertEqual(states, {"1": "run", "1b": "not run yet", "1c": "not run yet",
                                  "2": "not run yet", "3": "not run yet",
                                  "4": "not run yet", "5": "not run yet",
                                  "6": "not run yet"})
        later = experiments.show_table("2")
        self.assertEqual(later["headers"], ["Measure", "Before C", "Before D"])
        self.assertEqual(later["legend"][0],
                         "Before: run 1-after (base profile, council, reused from step 1)")
        self.assertEqual(later["missing"], ["2-after"])

    def test_replay_rescores_and_detects_tampering(self):
        self.run_step_1()
        code, printed, errors, _ = capture(cli.main, ["experiment", "replay", "1"])
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(printed.count("matches"), 3)
        self.assertNotIn("DIFFERS", printed)

        evaluation = self.out / "1-after" / "evaluation.json"
        data = json.loads(evaluation.read_text(encoding="utf-8"))
        data["configurations"][1]["precision"] = 0.01
        evaluation.write_text(json.dumps(data), encoding="utf-8")
        outputs = self.out / "1-before" / "B-single-agent.json"
        data = json.loads(outputs.read_text(encoding="utf-8"))
        data["results"][0]["verdict"] = "false_positive"
        outputs.write_text(json.dumps(data), encoding="utf-8")
        code, printed, _, _ = capture(cli.main, ["experiment", "replay", "1"])
        self.assertEqual(code, 1)
        self.assertIn("DIFFERS  evaluation.json", printed)
        self.assertIn("DIFFERS  saved outputs match results.jsonl", printed)

    def test_replay_needs_the_answer_key(self):
        with mock.patch.multiple(config, ANSWER_KEY=None):
            code, _, errors, _ = capture(cli.main, ["experiment", "replay", "1"])
        self.assertEqual(code, 1)
        self.assertIn("answer key", errors)

    def test_a_run_cannot_be_resumed_with_other_settings(self):
        plan = experiments.plan("1", side="after")[0]
        experiments.execute(plan, ANSWER_KEY, FixtureCallers(), str(self.bench))
        with self.assertRaisesRegex(experiments.ExperimentError, "smaller --limit"):
            experiments.plan("1", side="after", limit=1)
        with self.assertRaisesRegex(experiments.ExperimentError, "at least 1"):
            experiments.plan("1", side="after", limit=0)
        path = self.out / "1-after" / "run_manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["profile"]["settings"]["SOURCE_WINDOW_LINES"] = 60
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(experiments.ExperimentError, "different profile"):
            experiments.plan("1", side="after")
        with mock.patch.dict(os.environ, {"OPENROUTER_MODEL": "another-model"}):
            manifest["profile"]["settings"]["SOURCE_WINDOW_LINES"] = 25
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(experiments.ExperimentError, "different model"):
                experiments.plan("1", side="after")

    def test_a_semantic_run_records_its_retrieval_set_up_and_scope_hash(self):
        plan = experiments.plan("4", side="after")[0]
        plan["dir"].mkdir(parents=True)
        experiments._start_manifest(plan, {"commit": None, "dirty": None, "dirty_paths": []})
        path = self.out / "4-after" / "run_manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        settings = manifest["profile"]["settings"]
        self.assertEqual(settings, profiles.PROFILES["semantic"])
        self.assertEqual((settings["SEMANTIC_GROUNDING"], settings["SEMANTIC_MAX_CHUNK_CHARS"],
                          settings["KB_TARGET_PLATFORM"]), ("mitre_record", 1800, "java"))
        scope = config.KB_DIR / "scope.json"
        self.assertEqual(manifest["retrieval"]["kb_scope_sha256"],
                         hashlib.sha256(scope.read_bytes()).hexdigest())
        self.assertEqual(manifest["retrieval"]["embedding_model"], config.EMBEDDING_MODEL)
        # A changed scope.json cannot be resumed into the same run.
        manifest["retrieval"]["kb_scope_sha256"] = "0" * 64
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(experiments.ExperimentError, "different retrieval set-up"):
            experiments.plan("4", side="after")
        # Map runs record no retrieval block, as before.
        self.assertIsNone(experiments.plan("1", side="after")[0]["retrieval"])

    def test_a_limited_run_extends_to_the_full_set(self):
        experiments.execute(experiments.plan("1", side="before", limit=1)[0], ANSWER_KEY,
                            FixtureCallers(), str(self.bench))
        self.assertIn("covers only the first 1 of 2 cases", " ".join(experiments.show_table("1")["notes"]))
        callers = FixtureCallers()
        experiments.execute(experiments.plan("1", side="before")[0], ANSWER_KEY, callers, str(self.bench))
        self.assertEqual(callers.calls, 1)
        manifest = json.loads((self.out / "1-before" / "run_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(len(manifest["case_set"]["cases"]), 2)
        self.assertIsNone(manifest["case_set"]["limit"])

    # --- step 6: the final test is run once ------------------------------------------------------

    def offline_semantic(self):
        """The semantic profile without its prepare steps: a stub knowledge base, no fastembed."""
        stack = ExitStack()
        stack.enter_context(mock.patch.object(profiles, "missing_prerequisites", return_value=[]))
        stack.enter_context(mock.patch("triagebot.nodes.context.retrieval.KnowledgeBase", StubKnowledgeBase))
        stack.enter_context(mock.patch.object(experiments, "git_state", return_value=CLEAN))
        return stack

    def test_step_6_runs_the_final_version_single_and_council_at_the_step_4_costs(self):
        step = experiments.get_step("6")
        self.assertFalse(step.get("planned"))
        self.assertTrue(experiments.is_final_test(step))
        before, after = experiments.plan("6")
        self.assertEqual((before["name"], before["profile"], before["modes"]), ("6-before", "semantic", ["single"]))
        self.assertEqual((after["name"], after["profile"], after["modes"]), ("6-after", "semantic", ["council"]))
        self.assertEqual(before["cost_per_case"], {"single": 0.0043})
        self.assertEqual(after["cost_per_case"], {"council": 0.0146})
        cases = before["cases_in_set"]
        self.assertEqual((before["calls"], after["calls"]), (cases, 3 * cases))
        self.assertEqual(before["estimated_cost"], round(cases * 0.0043, 4))
        # 120 final-test cases: about US$0.52 single + US$1.75 council.
        self.assertEqual((round(120 * 0.0043, 2), round(120 * 0.0146, 2)), (0.52, 1.75))
        # Other steps keep the config estimates.
        self.assertEqual(experiments.plan("1")[0]["cost_per_case"],
                         {"single": config.EXPERIMENT_COST_PER_CASE["single"]})

    def test_the_final_test_refuses_a_dirty_tree(self):
        callers = FixtureCallers()
        dirty = {"commit": "a" * 40, "dirty": True, "dirty_paths": ["triagebot/config.py"]}
        with mock.patch.object(experiments, "git_state", return_value=dirty):
            (code, printed, errors, asked), _ = self.run_cli("6", callers=callers)
        self.assertEqual((code, asked, callers.calls), (1, 0, 0))
        self.assertIn("commit first", errors)
        self.assertIn("records the commit it ran on", errors)
        self.assertIn("triagebot/config.py", errors)
        self.assertFalse(self.out.exists())
        with mock.patch.object(experiments, "git_state",
                               return_value={"commit": None, "dirty": None, "dirty_paths": []}):
            (code, _, errors, _), _ = self.run_cli("6", callers=callers)
        self.assertEqual(code, 1)
        self.assertIn("Git commit could not be read", errors)
        # Other steps are not guarded.
        with mock.patch.object(experiments, "git_state", return_value=dirty):
            (code, _, errors, _), _ = self.run_cli("1", side="before", answers=("n",))
        self.assertEqual((code, errors), (0, ""))

    def test_the_final_test_runs_once_and_shows_single_and_council_by_cwe(self):
        with self.offline_semantic():
            (code, printed, errors, _), callers = self.run_cli("6")
            self.assertEqual((code, errors), (0, ""), printed)
            cases = len(experiments.plan("6")[0]["alerts"])
            self.assertEqual(callers.calls, 4 * cases)
            for name in ("6-before", "6-after"):
                self.assertEqual(experiments.run_status(name)["state"], "complete")

            table = experiments.show_table("6")
            self.assertEqual(table["headers"], ["Measure", "Single B", "Council C", "Council D"])
            self.assertEqual(table["legend"][:2], ["Single: run 6-before (semantic profile, single)",
                                                   "Council: run 6-after (semantic profile, council)"])
            self.assertEqual(table["by_cwe"]["headers"], ["CWE", "Measure", "Single B", "Council C", "Council D"])
            cwes = {row[0] for row in table["by_cwe"]["rows"]}
            self.assertEqual(len(table["by_cwe"]["rows"]), len(cwes) * len(experiments.CWE_METRICS))
            self.assertIsNone(experiments.show_table("1")["by_cwe"])
            code, shown, errors, _ = capture(cli.main, ["experiment", "show", "6"])
            self.assertEqual((code, errors), (0, ""))
            self.assertIn("By weakness (CWE)", shown)
            self.assertIn("Single B", shown)
            code, replayed, errors, _ = capture(cli.main, ["experiment", "replay", "6"])
            self.assertEqual((code, errors), (0, ""))
            self.assertEqual(replayed.count("matches"), 2)
            report = (self.out / "6-after" / "report.md").read_text(encoding="utf-8")
            self.assertIn(experiments.RERUN_FLAG, report)
            self.assertNotIn("delete this folder", report)

            # A second run is refused, before any question or call.
            (code, _, errors, asked), callers = self.run_cli("6")
            self.assertEqual((code, asked, callers.calls), (1, 0, 0))
            self.assertIn("already has results on the final test", errors)
            self.assertIn(experiments.RERUN_FLAG, errors)

            # With the flag, answering no changes nothing.
            (code, printed, errors, _), callers = self.run_cli("6", answers=("n",), rerun_final_test=True)
            self.assertEqual((code, errors, callers.calls), (0, "", 0))
            self.assertIn("Starting over: 6-before", printed)
            self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["6-after", "6-before"])

            # With the flag and yes, the old results are kept aside and the run starts from nothing.
            (code, printed, errors, _), callers = self.run_cli("6", rerun_final_test=True)
            self.assertEqual((code, errors), (0, ""), printed)
            self.assertEqual(callers.calls, 4 * cases)
            names = sorted(p.name for p in self.out.iterdir())
            self.assertEqual(names[:2], ["6-after", "6-after-superseded-" + names[1].rsplit("-", 1)[1]])
            self.assertEqual(len(names), 4)
            self.assertTrue(all(n.startswith(("6-after", "6-before")) for n in names))
            manifest = json.loads((self.out / "6-after" / "run_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["sessions"]), 1)

    def test_an_interrupted_final_test_resumes_without_the_flag(self):
        with self.offline_semantic():
            plan = experiments.plan("6", side="after")[0]
            with self.assertRaisesRegex(RuntimeError, "connection dropped"):
                experiments.execute(plan, ANSWER_KEY, FixtureCallers(fail_on_call=4), str(self.bench))
            self.assertEqual(experiments.run_status("6-after")["state"], "partial")
            (code, printed, errors, _), callers = self.run_cli("6", side="after")
            self.assertEqual((code, errors), (0, ""), printed)
            self.assertIn("1 already saved", printed)
            self.assertEqual(callers.calls, 3 * (plan["cases_in_set"] - 1))   # only the unfinished cases
            manifest = json.loads((self.out / "6-after" / "run_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual((manifest["status"], len(manifest["sessions"])), ("complete", 2))
            self.assertFalse(any("superseded" in p.name for p in self.out.iterdir()))

    def test_a_limited_final_test_run_is_extended_not_refused(self):
        with self.offline_semantic():
            (code, _, errors, _), _ = self.run_cli("6", side="before", limit=1)
            self.assertEqual((code, errors), (0, ""))
            (code, printed, errors, _), callers = self.run_cli("6", side="before")
            self.assertEqual((code, errors), (0, ""), printed)
            self.assertEqual(callers.calls, len(experiments.plan("6")[0]["alerts"]) - 1)

    def test_the_rerun_flag_is_only_for_the_final_test(self):
        (code, _, errors, asked), callers = self.run_cli("1", rerun_final_test=True)
        self.assertEqual((code, asked, callers.calls), (1, 0, 0))
        self.assertIn("applies only to a step whose case set is final-test", errors)

    # --- what the evidence may not contain ------------------------------------------------------

    def test_evidence_has_no_key_no_machine_paths_and_no_labels_on_the_model_side(self):
        self.run_step_1()
        forbidden = [SECRET, str(self.tmp), self.tmp.as_posix(), str(ROOT), ROOT.as_posix(),
                     str(Path.home())]
        files = sorted(p for p in self.out.rglob("*") if p.is_file())
        self.assertEqual(len(files), 20)          # 6 + 7 + 7 files in the three run folders
        for path in files:
            text = path.read_text(encoding="utf-8")
            for value in forbidden:
                self.assertNotIn(value, text, f"{value!r} in {path.name}")
                self.assertNotIn(value.replace("\\", "\\\\"), text, f"{value!r} in {path.name}")
            self.assertNotIn(b"\r\n", path.read_bytes(), f"{path.name} must use LF")

        def keys(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    yield key
                    yield from keys(item)
            elif isinstance(value, list):
                for item in value:
                    yield from keys(item)

        model_side = [p for p in files if p.name in (
            "results.jsonl", "B-single-agent.json", "C-council.json", "D-validated-council.json")]
        self.assertEqual(len(model_side), 8)
        for path in model_side:
            text = path.read_text(encoding="utf-8")
            values = ([json.loads(line) for line in text.splitlines()] if path.suffix == ".jsonl"
                      else [json.loads(text)])
            found = set(keys(values)) & LABEL_KEYS
            self.assertEqual(found, set(), f"answer-key field in {path.parent.name}/{path.name}")


if __name__ == "__main__":
    unittest.main()
