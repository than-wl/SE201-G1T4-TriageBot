"""The semantic retrieval set-up fixed before step 4 (design decision 28): rules R1 to R5.

Offline: a keyword-based fake embedder, a small MITRE catalogue and a small
knowledge base written to a temporary folder (tests/semantic_fixture.py). The
real committed KB is read only as JSON (scope.json and the chunk sizes); nothing
is embedded with a real model.
"""
import hashlib
import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from semantic_fixture import CATALOGUE, KeywordEmbedder, alert, write_kb
from triagebot import config, profiles
from triagebot.nodes.context import retrieval
from triagebot.nodes.context.cwe_catalogue import (MITIGATIONS_HEADING, CweCatalogue,
                                                   load_entries, trim_paragraphs)
from triagebot.nodes.context.retrieval import KnowledgeBase, excluded_docs, load_scope, split_chunk

ORIGINAL = profiles.SEMANTIC_SETUPS["original"]
IMPROVED = profiles.SEMANTIC_SETUPS["improved"]
REAL_KB = config.KB_DIR


def ids(chunks):
    return [c["chunk_id"] for c in chunks]


def squash(text):
    return re.sub(r"\s+", "", text)


class FixtureTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.kb_dir = write_kb(self.root / "kb")
        xml = self.root / "cwec.xml"
        xml.write_text(CATALOGUE, encoding="utf-8")
        self.catalogue = CweCatalogue(xml)
        self.embedder = KeywordEmbedder()

    def kb(self, mode="semantic", **kwargs):
        return KnowledgeBase(self.kb_dir, mode=mode, embedder=self.embedder,
                             catalogue=self.catalogue, **kwargs)

    def retrieve(self, cwe, setup=None, **extra):
        with profiles.applied({**(setup or {}), **extra}):
            return self.kb().retrieve(alert(cwe))


class RegressionTest(FixtureTest):
    def test_config_defaults_are_the_improved_set_up(self):
        # Decision 29: semantic retrieval with the set-up step 4 measured is the default.
        self.assertEqual({k: getattr(config, k) for k in IMPROVED}, IMPROVED)
        self.assertEqual(config.RETRIEVAL_MODE, "semantic")
        self.assertEqual(config.SEMANTIC_MIN_SCORE, 0.0)
        self.assertEqual({k: v for k, v in profiles.PROFILES["semantic"].items() if k in IMPROVED},
                         IMPROVED)

    def test_all_flags_off_returns_exactly_what_it_returned_before(self):
        # Recorded from the decision 21 code on this fixture before the rules were added.
        # The original set-up is set explicitly: the config defaults are the improved one.
        expected = {
            "CWE-89": ["Django_Sheet#001", "SQL_Sheet#001", "SQL_Sheet#002", "Evasion_Sheet#001",
                       "Old_Sheet#001", "Big_Sheet#001"],
            "CWE-916": ["Hash_Sheet#001", "common#001", "Java_Sheet#001", "Django_Sheet#001",
                        "SQL_Sheet#001", "SQL_Sheet#002"],
        }
        for cwe, chunk_ids in expected.items():
            with self.subTest(cwe=cwe):
                result = self.retrieve(cwe, ORIGINAL)
                self.assertEqual(result["source"], "OWASP Cheat Sheet Series")
                self.assertTrue(result["cwe_matched"])
                self.assertEqual(ids(result["chunks"]), chunk_ids)
        self.assertEqual(self.embedder.queries[:2], [
            "SQL Injection. Input reaches an SQL command without neutralisation.",
            "Hashing Too Weakly. Password hash is computed with a weak hash function."])
        for cwe in ("CWE-1", "CWE-404", ""):
            self.assertEqual(self.retrieve(cwe, ORIGINAL),
                             {"source": "OWASP Cheat Sheet Series", "cwe_matched": False, "chunks": []})

    def test_the_original_set_up_set_explicitly_does_not_depend_on_the_defaults(self):
        # --explain --setup original and semantic_setup_check apply SEMANTIC_SETUPS["original"]
        # themselves, so they give the same output whatever the config defaults are.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "verification"))
        import semantic_setup_check as setup_check

        self.assertEqual(setup_check.configurations()["original"], ORIGINAL)
        self.assertEqual(setup_check.configurations()["improved"], IMPROVED)
        outputs = []
        for defaults in (ORIGINAL, IMPROVED):
            with profiles.applied(defaults):
                kb = self.kb()
                outputs.append((retrieval.explain("CWE-89", "original", kb=kb),
                                [c["chunk_id"] for c in setup_check.collect(kb, "CWE-89", ORIGINAL)["pack"]]))
        self.assertEqual(outputs[0], outputs[1])
        self.assertIn("original set-up", outputs[0][0])
        self.assertIn("MITRE chunk: not attached (R2 off)", outputs[0][0])
        self.assertEqual(outputs[0][1], ["Django_Sheet#001", "SQL_Sheet#001", "SQL_Sheet#002",
                                         "Evasion_Sheet#001", "Old_Sheet#001", "Big_Sheet#001"])

    def test_map_mode_is_unaffected_by_the_new_flags(self):
        (self.kb_dir / "cwe_map.json").write_text(json.dumps({"CWE-89": ["SQL_Sheet", "Big_Sheet"]}),
                                                  encoding="utf-8")
        for cwe in ("CWE-89", "CWE-404"):
            with profiles.applied(ORIGINAL):
                before = self.kb(mode="map").retrieve(alert(cwe))
            with profiles.applied(IMPROVED):
                after = self.kb(mode="map").retrieve(alert(cwe))
            self.assertEqual(before, after)
        self.assertEqual(self.embedder.queries, [])

    def test_map_mode_on_the_real_kb_is_unaffected(self):
        for cwe in ("CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-326"):
            with profiles.applied(ORIGINAL):
                before = KnowledgeBase(mode="map").retrieve(alert(cwe))
            with profiles.applied(IMPROVED):
                after = KnowledgeBase(mode="map").retrieve(alert(cwe))
            self.assertEqual(before, after, cwe)


class CatalogueParsingTest(FixtureTest):
    def test_alternate_terms_extended_description_and_mitigations(self):
        entry = self.catalogue.lookup("CWE-89")
        self.assertEqual(entry["id"], "89")
        self.assertEqual(entry["alternate_terms"], ["SQLi", "SQL injection"])
        self.assertEqual(entry["extended_description"], [
            "Without sufficient removal or quoting of SQL syntax, the input is read as SQL rather than data.",
            "This can be used to alter query logic."])
        self.assertEqual(entry["mitigations"], [
            {"phases": ["Architecture and Design"],
             "text": "Use a vetted library that prevents this weakness."},
            {"phases": ["Implementation", "Operation"],
             "text": "Use prepared statements. - Bind every parameter. - Never concatenate."}])
        self.assertEqual(entry["description"], "Input reaches an SQL command without neutralisation.")

    def test_a_record_without_the_optional_parts(self):
        entry = self.catalogue.lookup("CWE-916")
        self.assertEqual((entry["alternate_terms"], entry["extended_description"], entry["mitigations"]),
                         ([], [], []))
        self.assertNotIn("CWE-1", load_entries(self.catalogue.path))      # deprecated


class AlternateTermsTest(FixtureTest):           # R1
    def test_query_includes_the_alternate_terms(self):
        self.retrieve("CWE-89", IMPROVED)
        self.assertEqual(self.embedder.queries[-1],
                         "SQL Injection. Also known as: SQLi, SQL injection. "
                         "Input reaches an SQL command without neutralisation.")

    def test_without_alternate_terms_the_query_is_unchanged(self):
        entry = self.catalogue.lookup("CWE-916")
        self.assertEqual(CweCatalogue.query_text(entry, alternate_terms=True),
                         CweCatalogue.query_text(entry))
        self.retrieve("CWE-916", IMPROVED)
        self.assertEqual(self.embedder.queries[-1],
                         "Hashing Too Weakly. Password hash is computed with a weak hash function.")

    def test_the_query_cap_still_holds(self):
        self.retrieve("CWE-89", IMPROVED, SEMANTIC_QUERY_MAX_CHARS=30)
        self.assertEqual(self.embedder.queries[-1], "SQL Injection. Also known as: ")


class MitreGuidanceTest(FixtureTest):            # R2
    def test_the_mitre_chunk_comes_first_with_its_id_section_and_url(self):
        result = self.retrieve("CWE-89", IMPROVED)
        first = result["chunks"][0]
        self.assertEqual(first["chunk_id"], "MITRE-CWE-89")
        self.assertEqual(first["doc"], "MITRE_CWE")
        self.assertEqual(first["section"], "CWE-89: SQL Injection")
        self.assertEqual(first["url"], "https://cwe.mitre.org/data/definitions/89.html")
        self.assertLessEqual(len(first["text"]), 1500)
        self.assertNotIn("MITRE-CWE-89", ids(result["chunks"][1:]))
        self.assertEqual(result["source"], "MITRE CWE and OWASP Cheat Sheet Series")

    def test_the_text_is_description_extended_description_then_phased_mitigations(self):
        text = CweCatalogue.guidance_chunk(self.catalogue.lookup("CWE-89"), 1500)["text"]
        self.assertEqual(text.split("\n\n"), [
            "Input reaches an SQL command without neutralisation.",
            "Without sufficient removal or quoting of SQL syntax, the input is read as SQL rather than data.",
            "This can be used to alter query logic.",
            MITIGATIONS_HEADING,
            "- Architecture and Design: Use a vetted library that prevents this weakness.",
            "- Implementation / Operation: Use prepared statements. - Bind every parameter. - Never concatenate."])
        self.assertNotIn("EXAMPLE-TEXT-NOT-GUIDANCE", text)       # demonstrative examples left out
        self.assertNotIn("CVE-0000-0000", text)                   # observed examples left out

    def test_the_cap_cuts_at_a_paragraph_or_sentence_boundary(self):
        entry = self.catalogue.lookup("CWE-89")
        full = CweCatalogue.guidance_chunk(entry, 10_000)["text"]
        for cap in range(55, len(full) + 1):
            with self.subTest(cap=cap):
                text = CweCatalogue.guidance_chunk(entry, cap)["text"]
                self.assertLessEqual(len(text), cap)
                self.assertTrue(full.startswith(text))
                self.assertTrue(text.endswith("."), text[-30:])    # whole sentences only
                self.assertFalse(text.endswith(MITIGATIONS_HEADING))

    def test_a_single_overlong_first_sentence_is_cut_at_a_space(self):
        self.assertEqual(trim_paragraphs(["alpha beta gamma"], 12), "alpha beta")
        self.assertEqual(trim_paragraphs(["abcdefgh"], 5), "abcde")

    def test_the_total_including_it_stays_within_the_budget(self):
        for budget in (300, 800, 1600, 4000):
            for cap in (100, 1500):
                with self.subTest(budget=budget, cap=cap):
                    result = self.retrieve("CWE-89", IMPROVED, GUIDANCE_MAX_CHARS=budget,
                                           MITRE_GUIDANCE_MAX_CHARS=cap)
                    self.assertEqual(result["chunks"][0]["chunk_id"], "MITRE-CWE-89")
                    self.assertLessEqual(sum(len(c["text"]) for c in result["chunks"]), budget)
                    self.assertLessEqual(len(result["chunks"]), config.RETRIEVAL_TOP_K)

    def test_a_deprecated_or_unknown_cwe_gets_none(self):
        for cwe in ("CWE-1", "CWE-404"):
            with self.subTest(cwe=cwe):
                result = self.retrieve(cwe, IMPROVED)
                self.assertEqual(result["chunks"], [])
                self.assertFalse(result["cwe_matched"])

    def test_the_mitre_chunk_is_never_embedded_or_searched(self):
        self.retrieve("CWE-89", IMPROVED)
        self.assertFalse(any("Without sufficient removal" in t for t in self.embedder.embedded))


class ScopeTest(FixtureTest):                    # R3
    def pool(self, **settings):
        with profiles.applied({**IMPROVED, **settings}):
            kb = self.kb()
            kb._semantic_index()
            return kb._search_pool()

    def test_each_rule_excludes_what_it_should(self):
        pool = self.pool()
        for doc in ("Old_Sheet", "Evasion_Sheet", "Django_Sheet"):         # rules a, b, c
            self.assertNotIn(f"{doc}#001", pool)
        for chunk_id in ("Java_Sheet#001", "SQL_Sheet#001", "Hash_Sheet#001", "common#001",
                         "Big_Sheet#001.1"):
            self.assertIn(chunk_id, pool)
        result = self.retrieve("CWE-89", IMPROVED)
        self.assertFalse({"Old_Sheet#001", "Evasion_Sheet#001", "Django_Sheet#001"}
                         & set(ids(result["chunks"])))

    def test_a_python_target_keeps_python_sheets_and_drops_java_ones(self):
        pool = self.pool(KB_TARGET_PLATFORM="python")
        self.assertIn("Django_Sheet#001", pool)
        self.assertNotIn("Java_Sheet#001", pool)
        self.assertNotIn("Old_Sheet#001", pool)

    def test_scope_off_searches_every_sheet(self):
        pool = self.pool(SEMANTIC_KB_SCOPE=False)
        self.assertTrue({"Old_Sheet#001", "Evasion_Sheet#001", "Django_Sheet#001"} <= pool)

    def test_a_missing_scope_file_is_an_error_when_the_rule_is_on(self):
        (self.kb_dir / "scope.json").unlink()
        with self.assertRaisesRegex(FileNotFoundError, "scope.json"):
            self.retrieve("CWE-89", IMPROVED)
        self.assertTrue(self.retrieve("CWE-89", ORIGINAL)["cwe_matched"])   # not read when off

    def test_an_exclusion_without_a_reason_is_refused(self):
        bad = self.root / "bad.json"
        bad.write_text(json.dumps({"excluded": {"X": {"rule": "retired"}}}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "rule .* and a reason"):
            load_scope(bad)


class CommittedScopeTest(unittest.TestCase):     # R3 on the real kb/scope.json
    @classmethod
    def setUpClass(cls):
        cls.scope = load_scope(REAL_KB / "scope.json")
        cls.titles = {p.stem: json.loads(p.read_text(encoding="utf-8"))["title"]
                      for p in (REAL_KB / "docs").glob("*.json")}

    def listed(self):
        return (list(self.scope["excluded"]) + list(self.scope["platform"])
                + list(self.scope["general"]))

    def test_every_doc_named_exists_and_every_doc_is_listed_once(self):
        listed = self.listed()
        self.assertEqual(sorted(listed), sorted(self.titles))
        self.assertEqual(len(listed), len(set(listed)))

    def test_every_exclusion_has_a_rule_and_a_reason(self):
        for doc, entry in self.scope["excluded"].items():
            self.assertIn(entry["rule"], ("retired", "attack_catalogue"), doc)
            self.assertTrue(entry["reason"].strip(), doc)
        for doc, entry in self.scope["platform"].items():
            self.assertEqual(entry["rule"], "platform", doc)
            self.assertIn(entry["platform"], self.scope["platforms"], doc)
            self.assertTrue(entry["reason"].strip(), doc)

    def test_rule_a_matches_the_titles_exactly(self):
        retired = {doc for doc, e in self.scope["excluded"].items() if e["rule"] == "retired"}
        by_title = {doc for doc, title in self.titles.items()
                    if title.startswith("DEPRECATED:") or "(Historical)" in title}
        self.assertEqual(retired, by_title)

    def test_rule_b_names_only_the_xss_filter_evasion_sheet(self):
        self.assertEqual([d for d, e in self.scope["excluded"].items() if e["rule"] == "attack_catalogue"],
                         ["XSS_Filter_Evasion_Cheat_Sheet"])

    def test_java_target_keeps_java_sheets(self):
        excluded = excluded_docs(self.scope, "java")
        self.assertIn("Java_Security_Cheat_Sheet", self.scope["platform"])
        self.assertNotIn("Java_Security_Cheat_Sheet", excluded)
        self.assertIn("Django_Security_Cheat_Sheet", excluded)
        self.assertNotIn("Docker_Security_Cheat_Sheet", excluded)        # infrastructure: general
        python = excluded_docs(self.scope, "python")
        self.assertNotIn("Django_Security_Cheat_Sheet", python)
        self.assertIn("Java_Security_Cheat_Sheet", python)

    def test_the_common_set_comes_from_general_sheets(self):
        common = json.loads((REAL_KB / "common.json").read_text(encoding="utf-8"))["chunks"]
        self.assertTrue({c["doc"] for c in common} <= set(self.scope["general"]))

    def test_scope_json_is_lf_only(self):
        self.assertNotIn(b"\r\n", (REAL_KB / "scope.json").read_bytes())


class SplitTest(unittest.TestCase):              # R4
    def chunk(self, text, chunk_id="Doc#001"):
        return {"chunk_id": chunk_id, "doc": "Doc", "section": "S", "text": text,
                "url": "https://example.test/doc"}

    def assert_pieces(self, chunk, cap):
        pieces = split_chunk(chunk, cap)
        self.assertGreater(len(pieces), 1)
        self.assertEqual(ids(pieces), [f"{chunk['chunk_id']}.{n}" for n in range(1, len(pieces) + 1)])
        for piece in pieces:
            self.assertLessEqual(len(piece["text"]), cap)
            self.assertTrue(piece["text"].strip())
            self.assertEqual({k: piece[k] for k in ("doc", "section", "url")},
                             {k: chunk[k] for k in ("doc", "section", "url")})
        self.assertEqual(squash("".join(p["text"] for p in pieces)), squash(chunk["text"]))
        return pieces

    def test_a_small_chunk_is_unchanged(self):
        chunk = self.chunk("Short guidance.")
        self.assertEqual(split_chunk(chunk, 1800), [chunk])
        self.assertEqual(split_chunk(self.chunk("x" * 5000), 0), [self.chunk("x" * 5000)])

    def test_a_big_chunk_splits_at_blank_lines_first(self):
        paragraphs = [f"Paragraph {n}. " + "Text. " * 40 for n in range(10)]
        pieces = self.assert_pieces(self.chunk("\n\n".join(paragraphs)), 600)
        for piece in pieces:                                      # whole paragraphs only
            self.assertTrue(piece["text"].startswith("Paragraph"))

    def test_line_breaks_then_sentences(self):
        lines = "\n".join(f"line {n} " + "word " * 30 for n in range(20))
        for piece in self.assert_pieces(self.chunk(lines), 500):
            self.assertTrue(piece["text"].startswith("line"))
        one_paragraph = " ".join(f"Sentence {n} has a few words in it." for n in range(200))
        for piece in self.assert_pieces(self.chunk(one_paragraph), 1800):
            self.assertTrue(piece["text"].endswith("."))

    def test_a_single_huge_paragraph_without_sentence_ends_still_splits(self):
        self.assert_pieces(self.chunk("word " * 2000), 1800)
        self.assert_pieces(self.chunk("x" * 5000), 1800)

    def test_every_oversized_chunk_of_the_real_kb_splits_cleanly(self):
        kb = KnowledgeBase(mode="semantic")
        oversized = [c for c in kb._all_chunks() if len(c["text"]) > 1800]
        self.assertTrue(oversized)
        for chunk in oversized:
            pieces = split_chunk(chunk, 1800)
            self.assertTrue(all(len(p["text"]) <= 1800 for p in pieces), chunk["chunk_id"])
            self.assertEqual(squash("".join(p["text"] for p in pieces)), squash(chunk["text"]))


class SplitRetrievalTest(FixtureTest):
    def test_the_store_holds_chunks_and_pieces_and_each_set_up_searches_its_own(self):
        kb = self.kb()
        with profiles.applied(ORIGINAL):               # the original set-up: splitting off
            store_ids, _ = kb._semantic_index()
            self.assertIn("Big_Sheet#001", store_ids)
            self.assertIn("Big_Sheet#001.1", store_ids)    # prepared for the improved set-up
            self.assertIn("Big_Sheet#001", kb._search_pool())
            self.assertNotIn("Big_Sheet#001.1", kb._search_pool())
        with profiles.applied(IMPROVED):
            self.assertNotIn("Big_Sheet#001", kb._search_pool())
            self.assertIn("Big_Sheet#001.1", kb._search_pool())
            result = kb.retrieve(alert("CWE-89"))
        self.assertIn("Big_Sheet#001.1", ids(result["chunks"]))
        self.assertNotIn("Big_Sheet#001", ids(result["chunks"]))

    def test_switching_set_ups_does_not_re_embed(self):
        with profiles.applied(ORIGINAL):
            kb = self.kb(vector_db=self.root / "vectors.sqlite")
            kb.retrieve(alert("CWE-89"))
        embedded = len(self.embedder.embedded)
        with profiles.applied(IMPROVED):
            self.kb(vector_db=self.root / "vectors.sqlite").retrieve(alert("CWE-89"))
        self.assertEqual(len(self.embedder.embedded), embedded)


class GroundingTest(FixtureTest):                # R5
    def test_grounded_unknown_deprecated_and_missing(self):
        self.assertTrue(self.retrieve("CWE-89", IMPROVED)["cwe_matched"])
        for cwe in ("CWE-404", "CWE-1", ""):
            with self.subTest(cwe=cwe):
                result = self.retrieve(cwe, IMPROVED)
                self.assertFalse(result["cwe_matched"])
                self.assertEqual(result["chunks"], [])

    def test_the_mitre_record_rule_ignores_scores(self):
        result = self.retrieve("CWE-89", IMPROVED, SEMANTIC_MIN_SCORE=1.01)
        self.assertTrue(result["cwe_matched"])
        self.assertTrue(len(result["chunks"]) > 1)
        original = self.retrieve("CWE-89", ORIGINAL, SEMANTIC_MIN_SCORE=1.01)
        self.assertEqual((original["cwe_matched"], original["chunks"]), (False, []))

    def test_only_the_mitre_record_grounds_without_r2(self):
        result = self.retrieve("CWE-89", IMPROVED, SEMANTIC_MITRE_GUIDANCE=False)
        self.assertTrue(result["cwe_matched"])
        self.assertNotIn("MITRE-CWE-89", ids(result["chunks"]))

    def test_an_unknown_grounding_rule_is_refused(self):
        with self.assertRaisesRegex(ValueError, "SEMANTIC_GROUNDING"):
            self.retrieve("CWE-89", IMPROVED, SEMANTIC_GROUNDING="vibes")


class ProfileTest(unittest.TestCase):
    def test_the_semantic_profile_turns_on_all_five_rules(self):
        semantic = profiles.PROFILES["semantic"]
        self.assertEqual({k: semantic[k] for k in IMPROVED}, IMPROVED)
        self.assertEqual(IMPROVED, {
            "SEMANTIC_QUERY_ALT_TERMS": True, "SEMANTIC_MITRE_GUIDANCE": True,
            "MITRE_GUIDANCE_MAX_CHARS": 1500, "SEMANTIC_KB_SCOPE": True,
            "KB_TARGET_PLATFORM": "java", "SEMANTIC_MAX_CHUNK_CHARS": 1800,
            "SEMANTIC_GROUNDING": "mitre_record"})
        for name in ("base", "evidence", "worksheet"):
            self.assertFalse(set(IMPROVED) & set(profiles.PROFILES[name]), name)

    def test_use_profile_restores_the_semantic_switches(self):
        with profiles.applied(ORIGINAL):        # differs from the profile, so a restore shows
            with profiles.use_profile("semantic", check_ready=False):
                self.assertTrue(config.SEMANTIC_KB_SCOPE)
                self.assertEqual(profiles.provenance()["settings"], profiles.PROFILES["semantic"])
            self.assertEqual({k: getattr(config, k) for k in ORIGINAL}, ORIGINAL)

    def test_retrieval_provenance_records_the_scope_hash(self):
        record = profiles.retrieval_provenance(profiles.PROFILES["semantic"])
        self.assertEqual(record["kb_scope_file"], "triagebot/nodes/context/kb/scope.json")
        self.assertEqual(record["kb_scope_sha256"],
                         hashlib.sha256((REAL_KB / "scope.json").read_bytes()).hexdigest())
        self.assertEqual(record["embedding_model"], config.EMBEDDING_MODEL)
        self.assertEqual(record["guidance_max_chars"], 4000)
        self.assertIsNone(profiles.retrieval_provenance(profiles.PROFILES["evidence"]))


def _payload(chunks):
    return {"alert": {"case_id": "BenchmarkTest00001", "rule_id": "java.sqli", "cwe": "CWE-89",
                      "message": "SQL built from input", "file": "Demo.java",
                      "start_line": 3, "end_line": 3},
            "source": {"lines": ["1: class Demo {", "3: stmt.execute(q);", "4: }"],
                       "related": [{"file": "Helper.java", "relationship": "called method",
                                    "lines": ["10: String clean(String v) { return v; }"]}]},
            "facts": {"source_apis": ["getParameter"], "sink_apis": ["execute"]},
            "guidance": {"source": "OWASP Cheat Sheet Series", "cwe_matched": bool(chunks),
                         "chunks": chunks}}


_CHUNKS = [{"chunk_id": "SQL_Sheet#001", "doc": "SQL_Sheet", "section": "SQL > Defense",
            "text": "Use parameterised queries.", "url": "https://example.test/sql"}]


class PromptHeaderTest(unittest.TestCase):
    """Only semantic mode relabels the guidance block; map-mode prompts are byte-identical."""

    # SHA-256 of every system prompt plus the evidence block (with and without guidance),
    # recorded from the code before the semantic heading was added.
    MAP_PROMPTS_SHA256 = {
        "base": "f152ea51132c95bd0286b5b66bb7f1cb296333f506ec1a4104319f94793dd390",
        "evidence": "f152ea51132c95bd0286b5b66bb7f1cb296333f506ec1a4104319f94793dd390",
        "worksheet": "a29e2e5db3565712717d59ee765fcc484e711ad36ab0d0bd8a62cd1ffb49c86a",
    }

    @staticmethod
    def prompts_text():
        from triagebot.nodes.review import prompts
        roles = ("analyst", "skeptic", "chair", "repair", "single")
        return "\n<>\n".join([prompts.system_prompt(r) for r in roles]
                             + [prompts.to_prompt_block(_payload(_CHUNKS)),
                                prompts.to_prompt_block(_payload([]))])

    def digest(self):
        return hashlib.sha256(self.prompts_text().encode("utf-8")).hexdigest()

    def test_map_mode_prompts_are_byte_identical(self):
        for name, expected in self.MAP_PROMPTS_SHA256.items():
            with self.subTest(profile=name):
                with profiles.use_profile(name, check_ready=False):
                    self.assertEqual(self.digest(), expected)
                    with profiles.applied(IMPROVED):     # the semantic switches do not leak into map
                        self.assertEqual(self.digest(), expected)

    def test_semantic_mode_labels_the_block_mitre_and_owasp(self):
        from triagebot.nodes.review import prompts
        with profiles.use_profile("evidence", check_ready=False):
            map_block = prompts.to_prompt_block(_payload(_CHUNKS))
        with profiles.use_profile("semantic", check_ready=False):
            semantic_block = prompts.to_prompt_block(_payload(_CHUNKS))
        self.assertIn("--- Retrieved guidance (MITRE CWE and OWASP Cheat Sheet Series); "
                      "cite only these, by chunk_id ---", semantic_block)
        self.assertNotIn("Retrieved OWASP guidance", semantic_block)
        self.assertEqual(semantic_block.replace(prompts.GUIDANCE_HEADERS["semantic"],
                                                prompts.GUIDANCE_HEADERS["map"]), map_block)


class ExplainTest(FixtureTest):
    def test_improved_set_up(self):
        with profiles.applied(ORIGINAL):        # differs from "improved", so a restore shows
            text = retrieval.explain("CWE-89", "improved", kb=self.kb())
            self.assertEqual({k: getattr(config, k) for k in ORIGINAL}, ORIGINAL)   # restored
        for line in ("improved set-up", "Also known as: SQLi, SQL injection.",
                     "Grounded: yes", "has a valid, non-deprecated MITRE record",
                     "MITRE chunk (MITRE-CWE-89", "Big_Sheet#001.1",
                     "Next 5 results that did not fit:"):
            self.assertIn(line, text)
        self.assertNotIn("Django_Sheet#001", text)

    def test_original_set_up(self):
        text = retrieval.explain("CWE-89", "original", kb=self.kb())
        self.assertIn("MITRE chunk: not attached (R2 off)", text)
        self.assertIn("score at least SEMANTIC_MIN_SCORE", text)
        self.assertIn("Big_Sheet#001 ", text)

    def test_an_ungrounded_cwe(self):
        text = retrieval.explain("CWE-1", "improved", kb=self.kb())
        self.assertIn("Grounded: no", text)
        self.assertIn("unknown or deprecated", text)

    def test_missing_prerequisites_name_the_prepare_commands(self):
        with patch.multiple(config, CWE_CATALOGUE_XML=self.root / "none.xml",
                            KB_VECTOR_DB=self.root / "none.sqlite"):
            err = io.StringIO()
            with redirect_stderr(err):
                code = retrieval.main(["--explain", "CWE-89"])
        self.assertEqual(code, 2)
        self.assertIn(profiles.CATALOGUE_COMMAND, err.getvalue())
        self.assertIn(profiles.VECTOR_STORE_COMMAND, err.getvalue())
        self.assertFalse((self.root / "none.sqlite").exists())       # nothing was embedded


if __name__ == "__main__":
    unittest.main()
