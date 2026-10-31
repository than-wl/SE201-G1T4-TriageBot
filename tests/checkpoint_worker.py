"""Subprocess-only fixture driver for real SQLite restart/recovery tests.

No network, API key, labels or real model. Not a product CLI command.
"""
import json
import os
from pathlib import Path
import sys
import threading
import time

# Windows O_APPEND is seek-to-end plus write, not an atomic append: the two
# specialist threads can overwrite each other's line. Serialise whole lines.
_LOG_LOCK = threading.Lock()

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from triagebot.checkpoints import (
    _database, _execution_lock, _record, create_council_run,
    inspect_council_run, resume_council_run,
)
from triagebot.council_graph import CouncilContext, build_council_graph
from triagebot.nodes.context.retrieval import KnowledgeBase


def main():
    action, db, root, thread_id, log = sys.argv[1:]
    root = Path(root)
    kb = KnowledgeBase(root / "kb")

    class Caller:
        last_call = None

        def complete(self, request):
            role = next(r for r in ("analyst", "skeptic", "chair")
                        if f"You are the {r.title()}" in request["system"])
            with _LOG_LOCK:
                fd = os.open(log, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
                try:
                    os.write(fd, (role + "\n").encode())
                finally:
                    os.close(fd)
            if role == "analyst":
                (root / "analyst.done").write_text("done")
            if action == "crash-chair" and role == "chair":
                os._exit(73)  # Real process death: no finally blocks run.
            if action == "fail-skeptic" and role == "skeptic":
                deadline = time.monotonic() + 10
                while not (root / "analyst.done").exists():
                    if time.monotonic() > deadline:
                        raise RuntimeError("Analyst fixture did not complete")
                    time.sleep(0.01)
                time.sleep(0.2)  # Allow the successful branch write to finish.
                raise RuntimeError("controlled specialist failure")
            self.last_call = {
                "model": "fixture-model", "latency_seconds": 0.25,
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.001},
            }
            return {
                "verdict": "true_positive", "explanation": "The query uses `input`.",
                "citations": [{"file": "Demo.java", "line": 2, "quote": "input"}],
                "guidance": [],
            }

    if action == "create":
        alert = json.loads((root / "alert.json").read_text())
        print(create_council_run(alert, db, kb=kb, benchmark_root=root, model="fixture-model"))
    elif action == "inspect":
        print(json.dumps(inspect_council_run(thread_id, db)))
    elif action == "stop-after-chair":
        with _execution_lock(Path(db)), _database(Path(db)) as (conn, saver):
            _, saved, _ = _record(conn, thread_id)
            ctx = CouncilContext(Caller, kb, root, persistent=True,
                                 expected_source_sha256=saved["source_sha256"])
            graph = build_council_graph(saver, interrupt_after=["chair"])
            graph.invoke(None, config={"configurable": {"thread_id": thread_id}},
                         context=ctx, durability="sync")
        print("stopped after chair")
    else:
        result = resume_council_run(
            thread_id, db, kb=kb, benchmark_root=root, model="fixture-model",
            caller_factory=Caller, allow_replay=True,
        )
        print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        sys.exit(74)
