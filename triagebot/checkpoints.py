"""Opt-in local SQLite council sessions; no automatic paid-call recovery.

Only use a trusted local DB. A file lock permits one executor per database;
SQLite still supports parallel graph nodes and read-only status inspection.
Public ephemeral triage/evaluation remain unchanged.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import sqlite3
import sys
from uuid import UUID, uuid4

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import START

from triagebot import config
from triagebot.council_graph import CouncilContext, build_council_graph, council_result
from triagebot.llm.openrouter import OpenRouterCaller, configured_model
from triagebot.nodes.context.retrieval import KnowledgeBase
from triagebot.schemas import NormalisedAlert


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _thread_id(value):
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Thread ID must be a canonical UUID") from None
    return value


def _db_path(value):
    value = config.COUNCIL_DB if value is None else value
    if str(value) in ("", ":memory:"):
        raise ValueError("A file-backed SQLite database is required, not :memory:")
    return Path(value).expanduser().resolve()


@contextmanager
def _execution_lock(path):
    """Nonblocking OS lock, released even if the process dies (POSIX/Windows)."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.with_name(path.name + ".run.lock").open("a+b") as handle:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError("Another council executor is using this database") from None
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def _database(path, *, create=False):
    if not create and not path.is_file():
        raise ValueError("Checkpoint database does not exist")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if create and not path.exists():
        # Private by default on POSIX; never alter permissions of an existing DB.
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
    try:
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if tables and "triagebot_runs" not in tables:
            raise ValueError("Not a TriageBot checkpoint database; use a separate file")
        if not create and "triagebot_runs" not in tables:
            raise ValueError("Not a TriageBot checkpoint database")
        if create:
            conn.execute("""CREATE TABLE IF NOT EXISTS triagebot_runs (
                thread_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                provenance TEXT NOT NULL, last_error TEXT
            )""")
            conn.commit()
        saver = SqliteSaver(conn)
        saver.setup()
        yield conn, saver
    finally:
        conn.close()


def _safe_alert(alert):
    fields = set(NormalisedAlert.__annotations__)
    if not isinstance(alert, dict) or set(alert) != fields:
        raise ValueError("Persisted input must contain only NormalisedAlert fields")
    strings = fields - {"start_line", "end_line"}
    if any(not isinstance(alert[key], str) for key in strings):
        raise ValueError("Alert text fields must be strings")
    if any(type(alert[key]) is not int or alert[key] < 1
           for key in ("start_line", "end_line")):
        raise ValueError("Alert line numbers must be positive integers")
    if alert["end_line"] < alert["start_line"]:
        raise ValueError("Alert end_line must not precede start_line")
    return dict(alert)


def _fresh_kb(kb):
    # Reload lazy document caches so fingerprints and retrieval see the same corpus.
    if kb is None:
        return KnowledgeBase()
    if not isinstance(kb, KnowledgeBase):
        raise ValueError("Durable runs require the file-backed KnowledgeBase")
    return KnowledgeBase(kb.kb_dir)


def _provenance(alert, kb, benchmark_root, model):
    root = Path(benchmark_root or config.BENCHMARK_ROOT or "").resolve()
    if not (benchmark_root or config.BENCHMARK_ROOT):
        raise ValueError("Set BENCHMARK_ROOT or pass benchmark_root for durable runs")
    source = (root / alert["file"]).resolve()
    if not source.is_relative_to(root):
        raise ValueError("Alert file escapes benchmark root")
    if not hasattr(kb, "kb_dir"):
        raise ValueError("Durable runs require a versionable, file-backed knowledge base")
    kb_root = Path(kb.kb_dir)
    kb_files = sorted(kb_root.rglob("*.json"))
    if not kb_files:
        raise ValueError("Knowledge base contains no JSON corpus")
    product = Path(__file__).resolve().parent
    code = {str(p.relative_to(product)): _sha(p.read_bytes())
            for p in sorted(product.rglob("*.py"))}
    corpus = {str(p.relative_to(kb_root)): _sha(p.read_bytes()) for p in kb_files}
    return {
        "schema": config.COUNCIL_CHECKPOINT_SCHEMA,
        "mode": "council", "alert": _safe_alert(alert),
        "source_sha256": _sha(source.read_bytes()),
        "model": model, "code_sha256": _sha(_json(code).encode()),
        "kb_sha256": _sha(_json(corpus).encode()),
        "config": {name: getattr(config, name) for name in (
            "SOURCE_WINDOW_LINES", "GUIDANCE_MAX_CHARS", "RETRIEVAL_TOP_K",
            "REVIEW_MAX_TOKENS", "REVIEW_TEMPERATURE", "BENCHMARK_COMMIT")},
        "versions": {name: version(name) for name in (
            "langgraph", "langgraph-checkpoint", "langgraph-checkpoint-sqlite",
            "langchain-core")},
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "timing_method": "active_model_node_critical_path_v1",
    }


def _record(conn, thread_id):
    row = conn.execute(
        "SELECT created_at, provenance, last_error FROM triagebot_runs WHERE thread_id=?",
        (_thread_id(thread_id),),
    ).fetchone()
    if row is None:
        raise ValueError("Unknown council thread ID")
    return row[0], json.loads(row[1]), row[2]


def create_council_run(alert, db_path=None, *, kb=None, benchmark_root=None, model=None):
    """Persist a new session BEFORE any model calls; return its unique ID."""
    alert = _safe_alert(alert)
    kb = _fresh_kb(kb)
    provenance = _provenance(alert, kb, benchmark_root, model or configured_model())
    path = _db_path(db_path)
    thread_id = str(uuid4())
    with _execution_lock(path), _database(path, create=True) as (conn, saver):
        created = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT INTO triagebot_runs VALUES (?, ?, ?, NULL)",
                     (thread_id, created, _json(provenance)))
        conn.commit()
        try:
            graph = build_council_graph(saver)
            graph.update_state({"configurable": {"thread_id": thread_id}},
                               {"alert": alert, "run_provenance": provenance}, as_node=START)
        except Exception:
            conn.execute("DELETE FROM triagebot_runs WHERE thread_id=?", (thread_id,))
            conn.commit()
            raise
    return thread_id


def inspect_council_run(thread_id, db_path=None):
    """Inspect without constructing clients, reading sources, or running nodes."""
    path = _db_path(db_path)
    with _database(path) as (conn, saver):
        created, provenance, last_error = _record(conn, thread_id)
        snapshot = build_council_graph(saver).get_state(
            {"configurable": {"thread_id": thread_id}}
        )
        if not snapshot.values:
            raise ValueError("Run manifest has no graph checkpoint; cannot resume safely")
        complete = not snapshot.next and "validated" in snapshot.values
        return {
            "thread_id": thread_id, "case_id": provenance["alert"]["case_id"],
            "mode": "council", "created_at": created,
            "status": "completed" if complete else "pending",
            "next_nodes": list(snapshot.next), "last_error_type": last_error,
            "requested_model": provenance["model"],
            "timing_method": provenance["timing_method"],
            "result": council_result(snapshot.values) if complete else None,
        }


def resume_council_run(thread_id, db_path=None, *, allow_replay=False,
                       caller_factory=None, kb=None, benchmark_root=None, model=None):
    """Continue SAME thread with input=None; explicit recovery consent required.

    Completed runs are returned without clients or source checks and never rerun.
    Incomplete runs can replay uncommitted calls after a crash; NOT exactly-once.
    """
    _thread_id(thread_id)
    path = _db_path(db_path)
    if not path.is_file():
        raise ValueError("Checkpoint database does not exist")
    with _execution_lock(path), _database(path) as (conn, saver):
        _, saved, _ = _record(conn, thread_id)
        cfg = {"configurable": {"thread_id": thread_id}}
        graph = build_council_graph(saver)
        snapshot = graph.get_state(cfg)
        if not snapshot.values or snapshot.values.get("run_provenance") != saved:
            raise ValueError("Checkpoint and run provenance do not match")
        if not snapshot.next and "validated" in snapshot.values:
            return council_result(snapshot.values)
        if not allow_replay:
            raise ValueError("Recovery may repeat a paid call; pass allow_replay=True "
                             "(CLI: --allow-replay) to acknowledge billing uncertainty")
        kb = _fresh_kb(kb)
        current = _provenance(saved["alert"], kb, benchmark_root, model or configured_model())
        mismatches = [key for key in saved if saved[key] != current.get(key)]
        if mismatches:
            raise ValueError("Incompatible resume; changed: " + ", ".join(mismatches))
        context = CouncilContext(
            caller_factory=caller_factory or (lambda: OpenRouterCaller(model=saved["model"])),
            kb=kb, benchmark_root=benchmark_root or config.BENCHMARK_ROOT,
            persistent=True, expected_source_sha256=saved["source_sha256"],
        )
        try:
            state = graph.invoke(None, config=cfg, context=context, durability="sync")
        except Exception as exc:
            # No raw exception text in this manifest (the graph DB remains sensitive).
            conn.execute("UPDATE triagebot_runs SET last_error=? WHERE thread_id=?",
                         (type(exc).__name__, thread_id))
            conn.commit()
            raise
        conn.execute("UPDATE triagebot_runs SET last_error=NULL WHERE thread_id=?", (thread_id,))
        conn.commit()
        if "validated" not in state:
            raise ValueError("Council did not finish; inspect the saved thread")
        return council_result(state)
