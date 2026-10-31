"""SQLite vector store: incremental sync, re-embedding rules and round-trip fidelity. Offline."""
import tempfile
import unittest
from pathlib import Path

import numpy as np

from triagebot.nodes.context.vector_store import VectorStore


class CountingEmbedder:
    """Deterministic 3-d unit vectors; counts how many texts it was asked to embed."""

    def __init__(self):
        self.embedded = 0

    def embed_documents(self, texts):
        self.embedded += len(texts)
        rows = np.array([[len(t) % 7 + 1.0, t.count("a") + 1.0, 1.0] for t in texts],
                        dtype=np.float32)
        return rows / np.linalg.norm(rows, axis=1, keepdims=True)


def chunk(cid, text="Use parameterised queries."):
    return {"chunk_id": cid, "doc": "SQL_Sheet", "section": "SQL", "text": text,
            "url": "https://example.test/sql"}


class VectorStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "vectors.sqlite"
        self.embedder = CountingEmbedder()

    def store(self, model_name=None):
        store = VectorStore(self.path, model_name=model_name)
        self.addCleanup(store.close)
        return store

    def test_first_sync_embeds_everything_and_repeat_sync_embeds_nothing(self):
        chunks = [chunk("a#1"), chunk("a#2", "Never concatenate input.")]
        self.assertEqual(self.store().sync(chunks, self.embedder), 2)
        self.assertEqual(self.store().sync(chunks, self.embedder), 0)
        self.assertEqual(self.embedder.embedded, 2)

    def test_only_changed_and_new_chunks_are_embedded(self):
        store = self.store()
        store.sync([chunk("a#1"), chunk("a#2")], self.embedder)
        before = self.embedder.embedded
        self.assertEqual(store.sync([chunk("a#1", "Changed text."), chunk("a#2"),
                                     chunk("a#3", "Brand new guidance.")], self.embedder), 2)
        self.assertEqual(self.embedder.embedded - before, 2)

    def test_removed_chunks_are_deleted(self):
        store = self.store()
        store.sync([chunk("a#1"), chunk("a#2")], self.embedder)
        self.assertEqual(store.sync([chunk("a#1")], self.embedder), 0)
        chunks, matrix = store.load()
        self.assertEqual([c["chunk_id"] for c in chunks], ["a#1"])
        self.assertEqual(matrix.shape[0], 1)

    def test_changing_the_embedding_model_re_embeds_everything(self):
        chunks = [chunk("a#1"), chunk("a#2")]
        self.store().sync(chunks, self.embedder)
        self.assertEqual(self.store(model_name="another-model").sync(chunks, self.embedder), 2)

    def test_duplicate_chunk_ids_are_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate chunk_id"):
            self.store().sync([chunk("a#1"), chunk("a#1", "other")], self.embedder)

    def test_loaded_vectors_match_what_was_embedded(self):
        chunks = [chunk("a#1"), chunk("a#2", "Never concatenate input.")]
        store = self.store()
        store.sync(chunks, self.embedder)
        loaded_chunks, matrix = store.load()
        expected = self.embedder.embed_documents(
            [f"{c['section']}\n{c['text']}" for c in chunks])
        self.assertEqual(matrix.dtype, np.float32)
        np.testing.assert_allclose(matrix, expected, rtol=1e-6)
        self.assertEqual([c["text"] for c in loaded_chunks], [c["text"] for c in chunks])

    def test_empty_store_loads_cleanly(self):
        chunks, matrix = self.store().load()
        self.assertEqual(chunks, [])
        self.assertEqual(matrix.shape, (0, 0))


if __name__ == "__main__":
    unittest.main()
