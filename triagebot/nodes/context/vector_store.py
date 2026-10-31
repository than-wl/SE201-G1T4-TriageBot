"""SQLite store for knowledge-base chunks and their embeddings (file-based, no server).

One row per chunk, holding the chunk fields and its unit vector as a float32 BLOB.
sync() makes the table match the chunks on disk: it embeds only chunks that are
new or whose text or embedding model changed, and deletes rows for removed
chunks. So adding a document later means chunking it and calling sync() again.

Search is exact cosine similarity over the loaded matrix (numpy). The table does
not depend on how search is done, so an index can be added later without
migrating the data.
"""

import hashlib
import json
import sqlite3
from pathlib import Path

import numpy as np

from triagebot import config
from triagebot.nodes.context.embeddings import chunk_text

SCHEMA = """
CREATE TABLE IF NOT EXISTS kb_chunks (
    chunk_id    TEXT PRIMARY KEY,
    doc         TEXT NOT NULL,
    section     TEXT NOT NULL,
    text        TEXT NOT NULL,
    url         TEXT NOT NULL,
    fingerprint TEXT NOT NULL,   -- sha256 of (model, chunk text): changes force a re-embed
    model       TEXT NOT NULL,
    vector      BLOB NOT NULL    -- float32, unit length
)"""


def _fingerprint(chunk: dict, model: str) -> str:
    return hashlib.sha256(json.dumps([model, chunk_text(chunk)]).encode()).hexdigest()


class VectorStore:
    """Open one SQLite file (or ":memory:") holding the KB chunks and their vectors."""

    def __init__(self, path: str | Path | None = None, model_name: str | None = None) -> None:
        self.path = str(path or config.KB_VECTOR_DB)
        self.model = model_name or config.EMBEDDING_MODEL
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def sync(self, chunks: list[dict], embedder) -> int:
        """Make the table match ``chunks``; return how many chunks were (re-)embedded."""
        ids = [c["chunk_id"] for c in chunks]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate chunk_id in the knowledge base")
        stored = dict(self._conn.execute("SELECT chunk_id, fingerprint FROM kb_chunks"))
        wanted = {c["chunk_id"]: _fingerprint(c, self.model) for c in chunks}

        stale = [cid for cid in stored if cid not in wanted]
        todo = [c for c in chunks if stored.get(c["chunk_id"]) != wanted[c["chunk_id"]]]
        if todo:
            vectors = embedder.embed_documents([chunk_text(c) for c in todo])
            rows = [(c["chunk_id"], c["doc"], c["section"], c["text"], c["url"],
                     wanted[c["chunk_id"]], self.model,
                     np.asarray(v, dtype=np.float32).tobytes())
                    for c, v in zip(todo, vectors)]
            self._conn.executemany(
                "INSERT OR REPLACE INTO kb_chunks "
                "(chunk_id, doc, section, text, url, fingerprint, model, vector) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        if stale:
            self._conn.executemany("DELETE FROM kb_chunks WHERE chunk_id = ?",
                                   [(cid,) for cid in stale])
        self._conn.commit()
        return len(todo)

    def load(self) -> tuple[list[dict], np.ndarray]:
        """Every stored chunk (in chunk_id order) and the matrix of their unit vectors."""
        rows = self._conn.execute(
            "SELECT chunk_id, doc, section, text, url, vector FROM kb_chunks ORDER BY chunk_id"
        ).fetchall()
        chunks = [{"chunk_id": r[0], "doc": r[1], "section": r[2], "text": r[3], "url": r[4]}
                  for r in rows]
        if not rows:
            return chunks, np.zeros((0, 0), dtype=np.float32)
        matrix = np.vstack([np.frombuffer(r[5], dtype=np.float32) for r in rows])
        return chunks, matrix
