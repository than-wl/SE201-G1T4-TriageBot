"""SQLite vector store: incremental sync, re-embedding rules and round-trip fidelity. Offline."""
import isolated_store  # noqa: F401  (first: keeps every test off the real vector store)
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

from triagebot import config
from triagebot.nodes.context import vector_store
from triagebot.nodes.context.retrieval import KnowledgeBase
from triagebot.nodes.context.vector_store import LargeDeleteError, VectorStore


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

    # --- the large-delete guard (design decision 30) ---------------------------------------

    def test_a_sync_that_would_delete_more_than_half_is_refused_and_changes_nothing(self):
        store = self.store()
        store.sync([chunk(f"a#{n}") for n in range(10)], self.embedder)
        # The 8 Nov wipe: a one-chunk fixture knowledge base synced against the full store.
        with self.assertRaisesRegex(LargeDeleteError, "would delete 10 of its 10 rows"):
            store.sync([chunk("SQL#1", "Use query parameter binding")], self.embedder)
        self.assertEqual(len(store.load()[0]), 10)
        with self.assertRaisesRegex(LargeDeleteError, "would delete 6 of its 10 rows"):
            store.sync([chunk(f"a#{n}") for n in range(4)], self.embedder)
        self.assertEqual(len(store.load()[0]), 10)

    def test_up_to_half_may_go_and_allow_large_delete_rebuilds_on_purpose(self):
        store = self.store()
        store.sync([chunk(f"a#{n}") for n in range(10)], self.embedder)
        store.sync([chunk(f"a#{n}") for n in range(5)], self.embedder)      # exactly half: allowed
        self.assertEqual(len(store.load()[0]), 5)
        store.sync([chunk("b#1")], self.embedder, allow_large_delete=True)
        self.assertEqual([c["chunk_id"] for c in store.load()[0]], ["b#1"])

    def test_prepare_is_the_one_caller_that_allows_a_large_delete(self):
        with mock.patch.object(KnowledgeBase, "_semantic_index", return_value=(["x"], None)) as index:
            self.assertEqual(vector_store.prepare(self.path), 1)
        index.assert_called_once_with(allow_large_delete=True)


class TestsUseAThrowawayStoreTest(unittest.TestCase):
    """No test may reach Context/tmp/kb_vectors.sqlite (the 8 Nov wipe, design decision 30)."""

    def test_the_configured_store_is_a_temporary_file_during_tests(self):
        self.assertNotEqual(Path(config.KB_VECTOR_DB).resolve(), isolated_store.REAL_STORE.resolve())
        self.assertEqual(Path(config.KB_VECTOR_DB), isolated_store.TEST_STORE)
        self.assertIn(Path(tempfile.gettempdir()).resolve(), Path(config.KB_VECTOR_DB).resolve().parents)

    def test_a_knowledge_base_other_than_the_committed_one_never_gets_the_file_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb_dir = Path(tmp) / "kb"
            kb_dir.mkdir()
            (kb_dir / "cwe_map.json").write_text(json.dumps({"CWE-89": ["SQL"]}), encoding="utf-8")
            (kb_dir / "common.json").write_text(json.dumps({"chunks": [chunk("SQL#1")]}), encoding="utf-8")
            with mock.patch.object(config, "KB_VECTOR_DB", isolated_store.REAL_STORE):
                self.assertEqual(KnowledgeBase(kb_dir, mode="semantic")._vector_db, ":memory:")
                self.assertEqual(KnowledgeBase(mode="semantic")._vector_db, isolated_store.REAL_STORE)
                self.assertEqual(KnowledgeBase(mode="semantic", embedder=CountingEmbedder())._vector_db,
                                 ":memory:")
            explicit = Path(tmp) / "chosen.sqlite"
            self.assertEqual(KnowledgeBase(kb_dir, mode="semantic", vector_db=explicit)._vector_db, explicit)


if __name__ == "__main__":
    unittest.main()
