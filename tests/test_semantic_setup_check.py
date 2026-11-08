"""verification/semantic_setup_check.py: the free retrieval-quality check of rules R1 to R5.

Offline: the fake keyword embedder, small MITRE catalogue and small knowledge base of
tests/semantic_fixture.py, written to a temporary folder. No real model, catalogue or
vector store is read.
"""
import isolated_store  # noqa: F401  (first: keeps every test off the real vector store)
import json
import sys
import tempfile
import unittest
from pathlib import Path

from semantic_fixture import CATALOGUE, KeywordEmbedder, write_kb
from triagebot import profiles
from triagebot.nodes.context.cwe_catalogue import CweCatalogue
from triagebot.nodes.context.retrieval import KnowledgeBase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verification"))
import semantic_setup_check as check  # noqa: E402

FIXTURE_CWES = ["CWE-89", "CWE-916"]
META = {"grader": "test", "blind": True, "rubric": check.RUBRIC, "date": "2026-11-09"}
FAKE_PROVENANCE = {
    "date": "2026-11-09T00:00:00+00:00", "git": {"commit": "0" * 40, "dirty": False},
    "cwe_catalogue_sha256": "a" * 64, "embedding_model": "fake", "kb_scope_sha256": "b" * 64,
    "relevance_labels_sha256": "c" * 64, "relevance_labels_added_sha256": "d" * 64,
    "top_k": 6, "guidance_max_chars": 4000, "search_depth": 6,
}


def chunk(chunk_id, doc, chars):
    return {"chunk_id": chunk_id, "doc": doc, "section": "S", "text": "x" * chars, "url": "u"}


class FixtureCheck(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        kb_dir = write_kb(self.root / "kb")
        xml = self.root / "cwec.xml"
        xml.write_text(CATALOGUE, encoding="utf-8")
        self.kb = KnowledgeBase(kb_dir, mode="semantic", embedder=KeywordEmbedder(),
                                catalogue=CweCatalogue(xml))

    def results(self):
        return check.collect_all(self.kb, FIXTURE_CWES, check.configurations())

    def returned(self, results):
        """(cwe, chunk_id) of every chunk in any ranking or pack, with its doc."""
        return {(cwe, c["chunk_id"]): c["doc"] for per in results.values()
                for cwe, got in per.items() for c in got["ranking"] + got["pack"]}

    def graded_all(self, results, grade=1):
        labels = {cwe: {} for cwe in FIXTURE_CWES}
        for (cwe, chunk_id), doc in self.returned(results).items():
            if doc != check.MITRE_DOC:
                labels[cwe][chunk_id] = grade
        return labels


class ConfigurationTest(unittest.TestCase):
    def test_original_one_rule_each_and_improved(self):
        configs = check.configurations()
        self.assertEqual(list(configs), ["original", "+R1", "+R2", "+R3", "+R4", "+R5", "improved"])
        original, improved = profiles.SEMANTIC_SETUPS["original"], profiles.SEMANTIC_SETUPS["improved"]
        self.assertEqual(configs["original"], original)
        self.assertEqual(configs["improved"], improved)
        for rule, key in check.RULES.items():
            changed = {k for k in original if configs[f"+{rule}"][k] != original[k]}
            self.assertEqual(changed, {key}, rule)
            self.assertEqual(configs[f"+{rule}"][key], improved[key])

    def test_part_b_list_is_fixed(self):
        self.assertEqual(check.PART_B, (
            ("CWE-918", "Server_Side_Request_Forgery_Prevention_Cheat_Sheet"),
            ("CWE-611", "XML_External_Entity_Prevention_Cheat_Sheet"),
            ("CWE-502", "Deserialization_Cheat_Sheet"),
            ("CWE-352", "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet"),
            ("CWE-601", "Unvalidated_Redirects_and_Forwards_Cheat_Sheet"),
            ("CWE-1336", "Server_Side_Template_Injection_Prevention_Cheat_Sheet"),
            ("CWE-915", "Mass_Assignment_Cheat_Sheet"),
            ("CWE-1021", "Clickjacking_Defense_Cheat_Sheet"),
            ("CWE-434", "File_Upload_Cheat_Sheet"),
            ("CWE-943", "NoSQL_Security_Cheat_Sheet"),
        ))
        self.assertIsInstance(check.PART_B, tuple)
        self.assertEqual(check.PART_B_CONFIGS, ("original", "improved"))

    def test_every_part_b_sheet_is_in_the_real_kb(self):
        docs = ROOT / "triagebot" / "nodes" / "context" / "kb" / "docs"
        for _, sheet in check.PART_B:
            self.assertTrue((docs / f"{sheet}.json").is_file(), sheet)


class CollectTest(FixtureCheck):
    def test_the_pack_is_what_retrieve_returns_and_the_ranking_has_no_mitre_chunk(self):
        for name, settings in check.configurations().items():
            got = check.collect(self.kb, "CWE-89", settings)
            with profiles.applied({"RETRIEVAL_MODE": "semantic", **settings}):
                expected = self.kb.retrieve({"cwe": "CWE-89"})["chunks"]
            self.assertEqual([c["chunk_id"] for c in got["pack"]], [c["chunk_id"] for c in expected])
            self.assertLessEqual(len(got["ranking"]), check.SEARCH_DEPTH)
            self.assertNotIn(check.MITRE_DOC, {c["doc"] for c in got["ranking"]})
            self.assertEqual(got["mitre"] is not None, settings["SEMANTIC_MITRE_GUIDANCE"], name)

    def test_r4_ranks_pieces_and_r3_drops_other_platforms(self):
        results = self.results()
        ranked = lambda name: {c["doc"] for c, _ in results[name]["CWE-89"]["ranked"]}
        self.assertIn("Django_Sheet", ranked("original"))
        self.assertNotIn("Django_Sheet", ranked("+R3"))
        pieces = lambda name: [c["chunk_id"] for c, _ in results[name]["CWE-89"]["ranked"]
                               if c["doc"] == "Big_Sheet"]
        self.assertEqual(pieces("original"), ["Big_Sheet#001"])
        self.assertTrue(pieces("+R4"))
        self.assertTrue(all(cid.startswith("Big_Sheet#001.") for cid in pieces("+R4")))

    def test_plus_r5_matches_original_when_every_cwe_has_a_record(self):
        results = self.results()
        self.assertTrue(check.same_results(results["+R5"], results["original"]))
        self.assertFalse(check.same_results(results["+R3"], results["original"]))


class PhaseOneTest(FixtureCheck):
    def test_lists_only_ungraded_non_mitre_chunks(self):
        results = self.results()
        returned = self.returned(results)
        self.assertIn(check.MITRE_DOC, set(returned.values()))     # R2 configs attach it
        labels = {"CWE-89": {"SQL_Sheet#001": 2, "Big_Sheet#001": 1}, "CWE-916": {"Hash_Sheet#001": 2}}
        items = check.to_grade(results, labels)
        expected = {k for k, doc in returned.items()
                    if doc != check.MITRE_DOC and k[1] not in labels.get(k[0], {})}
        self.assertEqual({(i["cwe"], i["chunk_id"]) for i in items}, expected)
        self.assertNotIn(("CWE-89", "SQL_Sheet#001"), {(i["cwe"], i["chunk_id"]) for i in items})
        self.assertIn(("CWE-89", "Big_Sheet#001.1"), {(i["cwe"], i["chunk_id"]) for i in items})
        self.assertEqual(items, sorted(items, key=lambda i: (check.cwe_sort_key(i["cwe"]), i["chunk_id"])))

    def test_output_is_blind(self):
        labels_path = self.root / "labels.json"
        labels_path.write_text(json.dumps({"CWE-89": {}, "CWE-916": {}}), encoding="utf-8")
        out = self.root / "to_grade.json"
        counts = check.run_list(self.kb, json.loads(labels_path.read_text()), out)
        self.assertEqual(set(counts), set(FIXTURE_CWES))
        raw = out.read_bytes()
        self.assertNotIn(b"\r\n", raw)
        document = json.loads(raw)
        self.assertEqual(document["count"], sum(counts.values()))
        self.assertEqual(set(document), {"about", "rubric", "count", "chunks"})
        for item in document["chunks"]:
            self.assertEqual(set(item), {"cwe", "chunk_id", "doc", "section", "text"})
        text = raw.decode("utf-8")
        for word in ("rank", "score", "cosine", "config", "original", "improved", "+R", "setup",
                     "set-up"):
            self.assertNotIn(word, text.lower() if word.islower() else text, word)


class PhaseTwoTest(FixtureCheck):
    def write_labels(self, original, added):
        labels, extra = self.root / "labels.json", self.root / "added.json"
        labels.write_text(json.dumps(original), encoding="utf-8")
        extra.write_text(json.dumps(added), encoding="utf-8")
        return labels, extra

    def score(self, labels, extra):
        return check.run_score(self.kb, labels, extra, self.root / "out.json", self.root / "out.md",
                               prov=FAKE_PROVENANCE)

    def test_refuses_a_missing_grade(self):
        labels = self.graded_all(self.results())
        dropped = sorted(labels["CWE-89"])[0]
        del labels["CWE-89"][dropped]
        paths = self.write_labels(labels, {"_meta": META})
        with self.assertRaises(check.GradingError) as caught:
            self.score(*paths)
        self.assertIn(dropped, str(caught.exception))
        self.assertFalse((self.root / "out.json").exists())

    def test_refuses_a_conflict_an_invalid_grade_and_a_missing_meta(self):
        with self.assertRaises(check.GradingError):
            check.merge_labels({"CWE-89": {"a": 2}}, {"_meta": META, "CWE-89": {"a": 0}})
        with self.assertRaises(check.GradingError):
            check.merge_labels({}, {"_meta": META, "CWE-89": {"a": 3}})
        with self.assertRaises(check.GradingError):
            check.merge_labels({}, {"CWE-89": {"a": 2}})
        merged = check.merge_labels({"CWE-89": {"a": 2}}, {"_meta": META, "CWE-89": {"b": 0, "a": 2}})
        self.assertEqual(merged, {"CWE-89": {"a": 2, "b": 0}})

    def test_scores_when_every_grade_is_in_the_merged_files(self):
        labels = self.graded_all(self.results(), grade=2)
        original = {cwe: dict(list(g.items())[:1]) for cwe, g in labels.items()}
        added = {"_meta": META, **{cwe: dict(list(g.items())[1:]) for cwe, g in labels.items()}}
        report = self.score(*self.write_labels(original, added))
        self.assertEqual(list(report["part_a"]), list(check.configurations()))
        self.assertTrue(report["plus_r5_matches_original"])
        self.assertEqual(len(report["part_b"]), len(check.PART_B))
        self.assertFalse(report["part_b"][0]["improved"]["grounded"])  # not in the fixture catalogue
        self.assertEqual(report["part_a"]["improved"]["macro"]["mitre_present"], 2)
        self.assertEqual(report["part_a"]["original"]["macro"]["mitre_present"], 0)
        # Fixture scope excludes Django (python), the retired and the attack sheets.
        self.assertGreater(report["part_a"]["original"]["macro"]["wrong_platform_total"]["search"], 0)
        self.assertEqual(report["part_a"]["improved"]["macro"]["wrong_platform_total"]["search"], 0)
        md = (self.root / "out.md").read_text(encoding="utf-8")
        self.assertIn("Expected sheet in pack: 0 of 10 (original) vs 0 of 10 (improved)", md)
        self.assertNotIn(b"\r\n", (self.root / "out.json").read_bytes())


class MetricTest(unittest.TestCase):
    def test_precision_and_mean_grade(self):
        grades = [2, 0, 2, 1, 2, 0]
        self.assertAlmostEqual(check.precision_at(grades, 3), 2 / 3)
        self.assertAlmostEqual(check.precision_at(grades, 6), 0.5)
        self.assertAlmostEqual(check.mean_grade(grades), 7 / 6)
        self.assertAlmostEqual(check.precision_at([2, 2], 6), 2 / 6)   # short ranking: empty slots count 0
        self.assertIsNone(check.mean_grade([]))

    def test_search_metrics(self):
        ranking = [chunk(f"c{n}", "D", 10) for n in range(6)]
        grades = {"c0": 2, "c1": 2, "c2": 0, "c3": 1, "c4": 0, "c5": 2}
        got = check.search_metrics(ranking, grades)
        self.assertAlmostEqual(got["p_at_3"], 2 / 3)
        self.assertAlmostEqual(got["p_at_6"], 0.5)
        self.assertAlmostEqual(got["mean_grade"], 7 / 6)

    def test_pack_metrics_and_wrong_platform(self):
        pack = [chunk("MITRE-CWE-89", check.MITRE_DOC, 100), chunk("A#001", "A", 50),
                chunk("B#001", "Django_Sheet", 30), chunk("C#001", "C", 20)]
        grades = {"A#001": 2, "B#001": 1, "C#001": 0}
        got = check.pack_metrics(pack, grades)
        self.assertEqual({k: got[k] for k in ("mitre", "mitre_chars", "owasp_chunks", "grade_2",
                                               "grade_ge_1", "chars", "grade_2_chars")},
                         {"mitre": True, "mitre_chars": 100, "owasp_chunks": 3, "grade_2": 1,
                          "grade_ge_1": 2, "chars": 200, "grade_2_chars": 50})
        self.assertEqual(check.wrong_platform(pack, {"Django_Sheet": "platform python"}), 1)
        none = check.pack_metrics([chunk("A#001", "A", 50)], grades)
        self.assertEqual((none["mitre"], none["mitre_chars"]), (False, 0))

    def test_part_a_macro_averages_per_cwe(self):
        one = {"ranking": [chunk("a", "A", 10)], "pack": [chunk("a", "A", 10)]}
        two = {"ranking": [chunk("b", "P", 10), chunk("c", "A", 10)], "pack": [chunk("b", "P", 30)]}
        labels = {"CWE-1": {"a": 2}, "CWE-2": {"b": 0, "c": 2}}
        got = check.part_a({"x": {"CWE-1": one, "CWE-2": two}}, labels, {"P": "platform php"})["x"]
        self.assertAlmostEqual(got["macro"]["search"]["p_at_3"], (1 / 3 + 1 / 3) / 2)
        self.assertAlmostEqual(got["macro"]["search"]["mean_grade"], (2 + 1) / 2)
        self.assertAlmostEqual(got["macro"]["pack"]["chars"], 20)
        self.assertEqual(got["macro"]["wrong_platform_total"], {"search": 1, "pack": 1})

    def test_css_check_finds_mentions_under_r1_and_improved(self):
        css = dict(chunk("S#001", "S", 0), text="Load the CSS stylesheet from the CDN.")
        xss = dict(chunk("X#001", "X", 0), text="Encode output to stop cross-site scripting.")
        got = lambda chunks: {"ranking": chunks, "pack": []}
        results = {"original": {"CWE-79": got([xss])}, "+R1": {"CWE-79": got([css, xss])},
                   "improved": {"CWE-79": got([xss])}}
        found = check.css_check(results, {"CWE-79": {"S#001": 0, "X#001": 2}})
        self.assertEqual([f["chunk_id"] for f in found], ["S#001"])
        self.assertEqual((found[0]["grade"], found[0]["in_original"], found[0]["seen_in"]),
                         (0, False, ["+R1 ranking"]))


if __name__ == "__main__":
    unittest.main()
