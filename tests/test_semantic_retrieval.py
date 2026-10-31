"""Semantic retrieval over the cheat sheets: catalogue lookup, ranking, threshold, grounding.

Offline: a keyword-based fake embedder stands in for fastembed, and a tiny
catalogue and knowledge base are written to a temporary folder.
"""
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import numpy as np

from triagebot import config
from triagebot.execution import validation_case
from triagebot.nodes.context.cwe_catalogue import CweCatalogue, install
from triagebot.nodes.context.retrieval import KnowledgeBase
from triagebot.nodes.validate.validator import validate_results

CATALOGUE = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-8"><Weaknesses>
  <Weakness ID="89" Name="SQL Injection" Status="Stable">
    <Description>Input reaches an SQL command without neutralisation.</Description>
  </Weakness>
  <Weakness ID="916" Name="Hashing Too Weakly" Status="Draft">
    <Description>Password hash is computed with a weak hash function.</Description>
  </Weakness>
  <Weakness ID="1" Name="Old Entry" Status="Deprecated">
    <Description>Retired.</Description>
  </Weakness>
</Weaknesses></Weakness_Catalog>
"""


def _unit(values):
    vector = np.array(values, dtype=np.float32)
    return vector / np.linalg.norm(vector)


class KeywordEmbedder:
    """Two dimensions: how often "sql" and "hash" occur. Records the queries it was asked."""

    def __init__(self):
        self.queries = []

    @staticmethod
    def _vector(text):
        lowered = text.lower()
        return _unit([lowered.count("sql"), lowered.count("hash"), 0.01])

    def embed_documents(self, texts):
        return np.array([self._vector(t) for t in texts], dtype=np.float32)

    def embed_query(self, text):
        self.queries.append(text)
        return self._vector(text)


class SemanticRetrievalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.kb_dir = root / "kb"
        (self.kb_dir / "docs").mkdir(parents=True)
        (self.kb_dir / "cwe_map.json").write_text("{}", encoding="utf-8")
        (self.kb_dir / "common.json").write_text(json.dumps({"chunks": [
            {"chunk_id": "common#001", "doc": "common", "section": "General",
             "text": "Validate all input.", "url": "https://example.test/common"}]}), encoding="utf-8")
        (self.kb_dir / "docs" / "SQL_Sheet.json").write_text(json.dumps({"chunks": [
            {"chunk_id": "SQL_Sheet#001", "doc": "SQL_Sheet", "section": "SQL",
             "text": "Use parameterised SQL queries.", "url": "https://example.test/sql"},
            {"chunk_id": "SQL_Sheet#002", "doc": "SQL_Sheet", "section": "SQL",
             "text": "Never concatenate input into an SQL statement.", "url": "https://example.test/sql"}]}),
            encoding="utf-8")
        (self.kb_dir / "docs" / "Hash_Sheet.json").write_text(json.dumps({"chunks": [
            {"chunk_id": "Hash_Sheet#001", "doc": "Hash_Sheet", "section": "Hashing",
             "text": "Use a slow hash such as bcrypt for password hash storage.",
             "url": "https://example.test/hash"}]}), encoding="utf-8")
        self.catalogue = CweCatalogue(self._write(root / "cwec.xml", CATALOGUE))
        self.embedder = KeywordEmbedder()

    @staticmethod
    def _write(path, text):
        path.write_text(text, encoding="utf-8")
        return path

    def kb(self, **kwargs):
        opts = dict(mode="semantic", embedder=self.embedder, catalogue=self.catalogue)
        opts.update(kwargs)
        return KnowledgeBase(self.kb_dir, **opts)

    @staticmethod
    def alert(cwe):
        return {"case_id": "C1", "file": "Demo.java", "rule_id": "r", "cwe": cwe,
                "start_line": 2, "end_line": 2, "message": "m"}

    def test_lookup_normalises_ids_and_skips_deprecated_records(self):
        self.assertEqual(self.catalogue.lookup("CWE-89")["name"], "SQL Injection")
        self.assertEqual(self.catalogue.lookup("CWE-89: Improper Neutralization")["name"], "SQL Injection")
        self.assertIsNone(self.catalogue.lookup("CWE-1"))      # deprecated -> miss
        self.assertIsNone(self.catalogue.lookup("CWE-404"))    # unknown -> miss
        self.assertIsNone(self.catalogue.lookup(""))

    def test_install_refuses_an_unpinned_or_mismatched_catalogue(self):
        root = Path(self.tmp.name)
        archive = root / "cwec.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("cwec_test.xml", CATALOGUE)
        with self.assertRaisesRegex(ValueError, "not pinned"):
            install(url=archive.as_uri(), sha256="", out_dir=root / "out")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            install(url=archive.as_uri(), sha256="0" * 64, out_dir=root / "out")
        self.assertFalse((root / "out").exists() and any((root / "out").iterdir()))

    def test_install_extracts_xml_when_hash_matches(self):
        root = Path(self.tmp.name)
        archive = root / "cwec.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("cwec_test.xml", CATALOGUE)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        target = install(url=archive.as_uri(), sha256=digest, out_dir=root / "out")
        self.assertEqual(target.name, "cwec_test.xml")
        self.assertEqual(CweCatalogue(target).lookup("CWE-916")["name"], "Hashing Too Weakly")

    def test_best_chunks_come_first_and_the_query_is_the_mitre_text(self):
        result = self.kb().retrieve(self.alert("CWE-89"))
        self.assertTrue(result["cwe_matched"])
        self.assertEqual(result["chunks"][0]["chunk_id"], "SQL_Sheet#001")
        self.assertNotIn("Hash_Sheet#001", [c["chunk_id"] for c in result["chunks"]][:2])
        self.assertTrue(self.embedder.queries[-1].startswith("SQL Injection. Input reaches"))

    def test_scores_below_the_threshold_are_not_grounded(self):
        with patch.object(config, "SEMANTIC_MIN_SCORE", 1.01):   # cosine cannot exceed 1
            result = self.kb().retrieve(self.alert("CWE-89"))
        self.assertFalse(result["cwe_matched"])
        self.assertEqual(result["chunks"], [])

    def test_missing_unknown_or_deprecated_cwe_is_not_grounded(self):
        kb = self.kb()
        for cwe in ("", "CWE-404", "CWE-1"):
            with self.subTest(cwe=cwe):
                result = kb.retrieve(self.alert(cwe))
                self.assertFalse(result["cwe_matched"])
                self.assertEqual(result["chunks"], [])

    def test_unknown_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown retrieval mode"):
            KnowledgeBase(self.kb_dir, mode="vector-ish")

    def test_default_map_mode_does_not_touch_the_embedder(self):
        kb = KnowledgeBase(self.kb_dir, mode="map", embedder=self.embedder, catalogue=self.catalogue)
        kb.retrieve(self.alert("CWE-89"))
        self.assertEqual(self.embedder.queries, [])

    def test_validation_routes_ungrounded_cases_to_human_review(self):
        source = "class Demo {\nString query = input;\n}\n"
        raw = {"case_id": "C1", "verdict": "false_positive", "explanation": "The query uses input.",
               "citations": [{"file": "Demo.java", "line": 2, "quote": "input"}]}
        grounded = validate_results(raw, {"C1": {"file": "Demo.java", "source": source,
                                                 "guidance_chunks": [], "guidance_matched": True}})
        ungrounded = validate_results(raw, {"C1": {"file": "Demo.java", "source": source,
                                                   "guidance_chunks": [], "guidance_matched": False}})
        self.assertEqual(grounded["results"][0]["verdict"], "false_positive")
        self.assertTrue(grounded["results"][0]["validated"])
        self.assertEqual(ungrounded["results"][0]["verdict"], "human_review")
        self.assertFalse(ungrounded["results"][0]["validated"])
        self.assertEqual(ungrounded["results"][0]["original_verdict"], "false_positive")

    def test_validation_case_carries_the_grounding_flag(self):
        payload = {"alert": {"file": "Demo.java"}, "guidance": {"chunks": [], "cwe_matched": False}}
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "Demo.java").write_text("class Demo {}\n", encoding="utf-8")
            case = validation_case(payload, root)
        self.assertIs(case["guidance_matched"], False)

    def test_exact_repeated_chunks_are_kept_once_for_the_semantic_store(self):
        doc = self.kb_dir / "docs" / "SQL_Sheet.json"
        data = json.loads(doc.read_text(encoding="utf-8"))
        data["chunks"].append(dict(data["chunks"][0]))           # verbatim repeat
        doc.write_text(json.dumps(data), encoding="utf-8")
        ids = [c["chunk_id"] for c in self.kb()._all_chunks()]
        self.assertEqual(ids.count("SQL_Sheet#001"), 1)
        self.assertEqual(len(ids), len(set(ids)))

    def test_a_chunk_id_with_different_content_is_refused(self):
        doc = self.kb_dir / "docs" / "SQL_Sheet.json"
        data = json.loads(doc.read_text(encoding="utf-8"))
        conflicting = dict(data["chunks"][0], text="Different text under the same ID.")
        data["chunks"].append(conflicting)
        doc.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "different content"):
            self.kb()._all_chunks()


if __name__ == "__main__":
    unittest.main()
