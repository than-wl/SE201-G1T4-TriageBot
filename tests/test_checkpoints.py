"""Real file-backed SQLite, safe provenance and true subprocess recovery tests."""
from collections import Counter
from contextlib import closing
from copy import deepcopy
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from rich.console import Console
from triagebot import __main__ as cli, config
from triagebot.checkpoints import (
    _database, _execution_lock, create_council_run, inspect_council_run,
    resume_council_run,
)
from triagebot.nodes.context.retrieval import KnowledgeBase


ALERT = {"case_id": "BenchmarkTest00001", "file": "Demo.java", "rule_id": "fixture.sqli",
         "cwe": "CWE-89", "start_line": 2, "end_line": 2, "message": "query uses input"}


class FixtureFactory:
    def __init__(self):
        self.calls = []

    def __call__(self):
        owner = self

        class Caller:
            last_call = None

            def complete(self, request):
                owner.calls.append(request)
                self.last_call = {"model": "fixture-model", "latency_seconds": 0.25,
                                  "usage": {"prompt_tokens": 10, "completion_tokens": 5,
                                            "cost": 0.001}}
                return {"verdict": "true_positive", "explanation": "The query uses `input`.",
                        "citations": [{"file": "Demo.java", "line": 2, "quote": "input"}],
                        "guidance": []}
        return Caller()


class CheckpointTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "sessions.sqlite"
        self.log = self.root / "calls.txt"
        (self.root / "Demo.java").write_text("class Demo {\nString query = input;\n}\n")
        (self.root / "alert.json").write_text(json.dumps(ALERT))
        kb = self.root / "kb"
        (kb / "docs").mkdir(parents=True)
        (kb / "cwe_map.json").write_text(json.dumps({"CWE-89": ["SQL"]}))
        (kb / "common.json").write_text('{"chunks": []}')
        (kb / "docs/SQL.json").write_text(json.dumps({"chunks": [{
            "chunk_id": "SQL#1", "doc": "SQL", "section": "Safe queries",
            "text": "Use query parameter binding", "url": "https://example.test/guidance",
        }]}))
        self.kb = KnowledgeBase(kb)
        self.factory = FixtureFactory()

    def create(self, alert=None, db=None):
        return create_council_run(
            deepcopy(alert or ALERT), db or self.db, kb=self.kb,
            benchmark_root=self.root, model="fixture-model",
        )

    def resume(self, tid, **kwargs):
        opts = dict(kb=KnowledgeBase(self.root / "kb"), benchmark_root=self.root,
                    model="fixture-model", caller_factory=self.factory, allow_replay=True)
        opts.update(kwargs)
        return resume_council_run(tid, self.db, **opts)

    def worker(self, action, tid="unused", expected=0):
        worker = Path(__file__).with_name("checkpoint_worker.py")
        env = dict(os.environ)
        env.pop("OPENROUTER_API_KEY", None)
        env["LANGSMITH_TRACING"] = "false"
        env["LANGCHAIN_TRACING_V2"] = "false"
        process = subprocess.run(
            [sys.executable, str(worker), action, str(self.db), str(self.root), tid, str(self.log)],
            text=True, capture_output=True, timeout=40, env=env,
        )
        self.assertEqual(process.returncode, expected, process.stderr + process.stdout)
        return process

    def test_creation_saves_pending_run_before_any_model_client(self):
        tid = self.create()
        self.assertTrue(self.db.is_file())
        status = inspect_council_run(tid, self.db)
        self.assertEqual(status["next_nodes"], ["build_context"])
        self.assertEqual(status["status"], "pending")
        self.assertIsNone(status["result"])
        self.assertEqual(self.factory.calls, [])

    def test_same_case_gets_unique_sessions_and_completed_resume_is_free(self):
        a, b = self.create(), self.create()
        self.assertNotEqual(a, b)
        result = self.resume(a)
        self.assertEqual(len(self.factory.calls), 3)
        self.assertEqual(inspect_council_run(b, self.db)["status"], "pending")
        with patch("triagebot.checkpoints.OpenRouterCaller", side_effect=AssertionError("paid call")):
            # No key, source root, KB or model needed to return a completed result.
            again = resume_council_run(a, self.db)
        self.assertEqual(result, again)
        self.assertEqual(len(self.factory.calls), 3)

    def test_public_output_shape_and_committed_usage_stay_compatible(self):
        result = self.resume(self.create())
        self.assertEqual(set(result), {"case_id", "mode", "payload", "role_reports", "review", "validated"})
        self.assertEqual([r["role"] for r in result["role_reports"]], ["analyst", "skeptic", "chair"])
        self.assertEqual(result["review"]["usage"]["prompt_tokens"], 30)
        self.assertAlmostEqual(result["review"]["usage"]["cost"], 0.003)
        self.assertEqual(result["review"]["usage"], result["validated"]["usage"])
        self.assertTrue(result["validated"]["validated"])

    def test_incomplete_resume_requires_billing_acknowledgment(self):
        tid = self.create()
        with self.assertRaisesRegex(ValueError, "billing uncertainty"):
            self.resume(tid, allow_replay=False)
        self.assertEqual(self.factory.calls, [])

    def test_source_change_refuses_resume_without_calls(self):
        tid = self.create()
        (self.root / "Demo.java").write_text("changed source")
        with self.assertRaisesRegex(ValueError, "source_sha256"):
            self.resume(tid)
        self.assertEqual(self.factory.calls, [])

    def test_kb_change_refuses_resume_without_calls(self):
        tid = self.create()
        (self.root / "kb/common.json").write_text('{"chunks": [], "revision": 2}')
        with self.assertRaisesRegex(ValueError, "kb_sha256"):
            self.resume(tid)
        self.assertEqual(self.factory.calls, [])

    def test_supplied_kb_is_reloaded_instead_of_reusing_stale_document_cache(self):
        self.kb.retrieve(ALERT)  # Warm the old document cache.
        doc = self.root / "kb/docs/SQL.json"
        data = json.loads(doc.read_text())
        data["chunks"][0]["text"] = "Updated query guidance"
        doc.write_text(json.dumps(data))
        tid = self.create()
        result = self.resume(tid, kb=self.kb)
        self.assertEqual(result["payload"]["guidance"]["chunks"][0]["text"],
                         "Updated query guidance")

    def test_model_change_refuses_resume_without_calls(self):
        tid = self.create()
        with self.assertRaisesRegex(ValueError, "model"):
            self.resume(tid, model="different-model")
        self.assertEqual(self.factory.calls, [])

    def test_runtime_config_change_refuses_resume_without_calls(self):
        tid = self.create()
        with patch.object(config, "SOURCE_WINDOW_LINES", config.SOURCE_WINDOW_LINES + 1):
            with self.assertRaisesRegex(ValueError, "config"):
                self.resume(tid)
        self.assertEqual(self.factory.calls, [])

    def test_package_version_change_refuses_resume_without_calls(self):
        tid = self.create()
        with patch("triagebot.checkpoints.version", return_value="incompatible-version"):
            with self.assertRaisesRegex(ValueError, "versions"):
                self.resume(tid)
        self.assertEqual(self.factory.calls, [])

    def test_state_provenance_mismatch_refuses_resume(self):
        tid = self.create()
        with closing(sqlite3.connect(self.db)) as conn, conn:
            raw = conn.execute("SELECT provenance FROM triagebot_runs WHERE thread_id=?", (tid,)).fetchone()[0]
            manifest = json.loads(raw)
            manifest["model"] = "tampered"
            conn.execute("UPDATE triagebot_runs SET provenance=? WHERE thread_id=?", (json.dumps(manifest), tid))
        with self.assertRaisesRegex(ValueError, "provenance do not match"):
            self.resume(tid)
        self.assertEqual(self.factory.calls, [])

    def test_file_db_required_not_memory(self):
        with self.assertRaisesRegex(ValueError, "file-backed"):
            self.create(db=":memory:")

    def test_unknown_and_malformed_ids_fail(self):
        self.create()
        for bad in ("../../other", "' OR 1=1 --", str(uuid4())):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                inspect_council_run(bad, self.db)
        self.assertEqual(self.factory.calls, [])

    def test_missing_db_is_not_silently_created_by_inspection(self):
        with self.assertRaisesRegex(ValueError, "does not exist"):
            inspect_council_run(str(uuid4()), self.db)
        self.assertFalse(self.db.exists())

    def test_unrelated_sqlite_database_not_modified(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("CREATE TABLE unrelated (value TEXT)")
        with self.assertRaisesRegex(ValueError, "separate file"):
            self.create()
        with closing(sqlite3.connect(self.db)) as conn, conn:
            names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        self.assertEqual(names, ["unrelated"])

    def test_extra_answer_key_field_is_rejected_before_persistence(self):
        with self.assertRaisesRegex(ValueError, "NormalisedAlert"):
            self.create(alert=dict(ALERT, vulnerable=True))
        self.assertFalse(self.db.exists())

    def test_path_escape_is_rejected_before_persistence(self):
        with self.assertRaisesRegex(ValueError, "escapes benchmark root"):
            self.create(alert=dict(ALERT, file="../outside.java"))
        self.assertFalse(self.db.exists())

    def test_checkpoint_contains_no_environment_key_or_answer_key_file(self):
        secret = "fixture-private-key-DO-NOT-STORE"
        label = "fixture-answer-key-sentinel-DO-NOT-STORE"
        (self.root / "expectedresults-1.2.csv").write_text(label)
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": secret}):
            self.resume(self.create())
        raw = self.db.read_bytes()
        self.assertNotIn(secret.encode(), raw)
        self.assertNotIn(label.encode(), raw)
        with _database(self.db) as (_, saver):
            # Runtime objects are not in graph state.
            from triagebot.state import CouncilState
            fields = set(CouncilState.__annotations__)
            all_state = [{key: val for key, val in item.checkpoint["channel_values"].items()
                          if key in fields} for item in saver.list(None)]
            text = json.dumps(all_state)
            self.assertNotIn("caller_factory", text)
            self.assertNotIn("review_started", text)

    def test_execution_lock_prevents_a_second_executor_but_not_status(self):
        tid = self.create()
        with _execution_lock(self.db):
            self.assertEqual(inspect_council_run(tid, self.db)["status"], "pending")
            proc = self.worker("recover", tid, expected=74)
            self.assertIn("Another council executor", proc.stderr)
        self.assertFalse(self.log.exists())
        self.resume(tid)  # Lock was released, not permanently left stale.

    def test_create_in_one_process_reopen_in_another(self):
        tid = self.worker("create").stdout.strip()
        pending = json.loads(self.worker("inspect", tid).stdout)
        self.assertEqual(pending["next_nodes"], ["build_context"])
        result = json.loads(self.worker("recover", tid).stdout)
        self.assertTrue(result["validated"]["validated"])
        self.assertEqual(Counter(self.log.read_text().splitlines()),
                         {"analyst": 1, "skeptic": 1, "chair": 1})

    def test_hard_crash_in_chair_recovers_specialists_without_repeating_them(self):
        tid = self.worker("create").stdout.strip()
        self.worker("crash-chair", tid, expected=73)
        pending = inspect_council_run(tid, self.db)
        self.assertEqual(pending["next_nodes"], ["chair"])
        result = json.loads(self.worker("recover", tid).stdout)
        counts = Counter(self.log.read_text().splitlines())
        self.assertEqual(counts, {"analyst": 1, "skeptic": 1, "chair": 2})
        # Cost is for COMMITTED reports, not proof of the actual billing total.
        self.assertEqual(result["review"]["usage"]["prompt_tokens"], 30)
        self.assertEqual(inspect_council_run(tid, self.db)["status"], "completed")

    def test_hard_crash_in_repair_recovers_without_repeating_the_chair(self):
        tid = self.worker("create").stdout.strip()
        self.worker("crash-repair", tid, expected=73)   # the Chair contradicted its own analysis
        self.assertEqual(inspect_council_run(tid, self.db)["next_nodes"], ["repair"])
        result = json.loads(self.worker("recover", tid).stdout)
        counts = Counter(self.log.read_text().splitlines())
        self.assertEqual(counts, {"analyst": 1, "skeptic": 1, "chair": 1, "repair": 2})
        self.assertEqual(result["review"]["verdict"], "true_positive")
        # Analyst, Skeptic, the Chair's own report, and the repaired report.
        self.assertEqual([r["role"] for r in result["role_reports"]],
                         ["analyst", "skeptic", "chair", "chair"])
        self.assertEqual(result["review"]["usage"]["prompt_tokens"], 40)
        self.assertTrue(result["validated"]["validated"])

    def test_successful_parallel_pending_write_is_not_replayed(self):
        tid = self.worker("create").stdout.strip()
        self.worker("fail-skeptic", tid, expected=74)
        self.assertEqual(inspect_council_run(tid, self.db)["last_error_type"], "RuntimeError")
        self.worker("recover", tid)
        self.assertEqual(Counter(self.log.read_text().splitlines()),
                         {"analyst": 1, "skeptic": 2, "chair": 1})

    def test_resume_at_validation_needs_no_timer_or_new_model_calls(self):
        tid = self.worker("create").stdout.strip()
        self.worker("stop-before-validate", tid)
        self.assertEqual(inspect_council_run(tid, self.db)["next_nodes"], ["validate"])
        before = self.log.read_text()
        with _database(self.db) as (_, saver):
            values = saver.get_tuple({"configurable": {"thread_id": tid}}).checkpoint["channel_values"]
            expected = round(max(values["analyst_elapsed_seconds"], values["skeptic_elapsed_seconds"])
                             + values["chair_elapsed_seconds"] + values["repair_elapsed_seconds"], 3)
        result = json.loads(self.worker("recover", tid).stdout)
        self.assertEqual(result["review"]["latency_seconds"], expected)
        self.assertEqual(self.log.read_text(), before)
        self.assertTrue(result["validated"]["validated"])
        self.assertGreaterEqual(result["review"]["latency_seconds"], 0)
        self.assertEqual(result["review"]["usage"]["prompt_tokens"], 30)

    def test_source_changed_during_review_is_not_validated_against_new_file(self):
        tid = self.create()
        factory = self.factory
        outer = self
        def make_caller():
            caller = factory()
            original = caller.complete
            def complete(request):
                result = original(request)
                if "You are the Chair" in request["system"]:
                    (outer.root / "Demo.java").write_text("different source")
                return result
            caller.complete = complete
            return caller
        with self.assertRaisesRegex(ValueError, "Source changed"):
            self.resume(tid, caller_factory=make_caller)
        self.assertEqual(len(factory.calls), 3)
        self.assertEqual(inspect_council_run(tid, self.db)["next_nodes"], ["validate"])

    @unittest.skipIf(os.name == "nt", "POSIX file-mode assertion")
    def test_new_database_has_private_permissions(self):
        self.create()
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)

    def test_status_cli_runs_without_api_clients_or_source(self):
        tid = self.create()
        (self.root / "Demo.java").unlink()
        output = StringIO()
        with patch.object(cli, "console", Console(file=output, width=160)), \
             patch("triagebot.checkpoints.OpenRouterCaller", side_effect=AssertionError("model")):
            rc = cli.main(["council-status", "--db", str(self.db), "--thread-id", tid])
        self.assertEqual(rc, 0)
        status = json.loads(output.getvalue())
        self.assertEqual(status["thread_id"], tid)
        self.assertNotIn("result", status)
        self.assertEqual(self.factory.calls, [])

    def test_resume_cli_refuses_incomplete_run_without_flag(self):
        tid = self.create()
        errors = StringIO()
        with patch.object(cli, "err_console", Console(file=errors, width=160)):
            rc = cli.main(["council-resume", "--db", str(self.db), "--thread-id", tid])
        self.assertEqual(rc, 1)
        self.assertIn("allow-replay", errors.getvalue())
        self.assertEqual(self.factory.calls, [])

    def test_start_cli_prints_id_before_execution_and_uses_expected_arguments(self):
        sample = self.root / "sample.json"
        sample.write_text(json.dumps([ALERT]))
        tid = str(uuid4())
        output = StringIO()
        fixture_result = {"case_id": ALERT["case_id"], "mode": "council", "validated": {}}
        def execute(*args, **kwargs):
            self.assertIn(tid, output.getvalue())
            return fixture_result
        with patch.object(cli, "console", Console(file=output, width=160)), \
             patch("triagebot.checkpoints.create_council_run", return_value=tid) as create, \
             patch("triagebot.checkpoints.resume_council_run", side_effect=execute) as resume:
            rc = cli.main(["council-start", "--case", ALERT["case_id"], "--sample", str(sample),
                           "--db", str(self.db), "--out", str(self.root / "out"),
                           "--benchmark-root", str(self.root)])
        self.assertEqual(rc, 0)
        create.assert_called_once_with(ALERT, str(self.db), benchmark_root=str(self.root))
        resume.assert_called_once_with(tid, str(self.db), allow_replay=True, benchmark_root=str(self.root))
        saved = json.loads((self.root / "out" / f"council-{tid}.json").read_text())
        self.assertEqual(saved, fixture_result)

    def test_resume_cli_returns_completed_result_without_model_calls(self):
        tid = self.create()
        self.resume(tid)
        output = StringIO()
        with patch.object(cli, "console", Console(file=output, width=160)), \
             patch("triagebot.checkpoints.OpenRouterCaller", side_effect=AssertionError("model")):
            rc = cli.main(["council-resume", "--db", str(self.db), "--thread-id", tid,
                           "--out", str(self.root / "out")])
        self.assertEqual(rc, 0)
        self.assertTrue((self.root / "out" / f"council-{tid}.json").is_file())


if __name__ == "__main__":
    unittest.main()
