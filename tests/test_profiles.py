"""Offline tests for the experiment profiles (triagebot/profiles.py).

One test per profile proves that the system prompt, the strict JSON schema
sent to OpenRouter and the evidence block match the profile table in
EXPERIMENTS.md. Model calls use canned fixture callers; the OpenRouter
request is captured with a patched urlopen, so nothing leaves the machine.
"""
from io import BytesIO
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from triagebot import config, pipeline, profiles
from triagebot.llm.openrouter import OpenRouterCaller
from triagebot.nodes.context.retrieval import KnowledgeBase

FILE = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"
HELPER_FILE = "src/main/java/helpers/Transform.java"
ALERT = {"case_id": "BenchmarkTest00001", "file": FILE, "rule_id": "fixture.sqli",
         "cwe": "CWE-89", "start_line": 70, "end_line": 70, "message": "query uses input"}
RESPONSE = {"verdict": "human_review", "explanation": "More analysis needed.",
            "citations": [{"file": FILE, "line": 70, "quote": "helper"}], "guidance": []}
ANALYSIS = {"source": "input", "sink": "query", "reaches_sink": "yes",
            "protection": "none", "protection_effective": "no"}


class EmptyKnowledgeBase:
    def retrieve(self, alert, extra_terms=None):
        return {"source": "fixture", "cwe_matched": True, "chunks": []}


class CannedCaller:
    def __init__(self, response, log):
        self.response, self.log, self.last_call = response, log, None

    def complete(self, request):
        self.log.append(request)
        self.last_call = {"model": "fixture-model", "latency_seconds": 0.1,
                          "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.001}}
        return dict(self.response)


def sent_schema():
    """The strict schema the live caller would send, captured offline."""
    captured = {}
    reply = {"model": "fixture", "choices": [{"message": {"content": json.dumps(RESPONSE)},
                                              "finish_reason": "stop"}], "usage": {}}

    def fake_urlopen(request, timeout):
        captured["payload"] = json.loads(request.data)
        return BytesIO(json.dumps(reply).encode("utf-8"))

    with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test"}), \
            patch("triagebot.llm.openrouter.urlopen", fake_urlopen):
        OpenRouterCaller().complete({"system": "s", "user": "u"})
    response_format = captured["payload"]["response_format"]
    assert response_format["json_schema"]["strict"] is True
    return response_format["json_schema"]["schema"]


class ProfileTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        lines = ["class Demo {"] + [f"int filler{n} = {n};" for n in range(2, 151)] + ["}"]
        lines[35 - 1] = "int marker35 = 35;"         # inside +-60, outside +-25 of line 70
        lines[70 - 1] = "String query = helper(helpers.Transform.clean(input));"
        lines[140 - 1] = "String helper(String value) {"
        lines[141 - 1] = "return value;"
        lines[142 - 1] = "}"
        source = self.root / FILE
        source.parent.mkdir(parents=True)
        source.write_text("\n".join(lines) + "\n", encoding="utf-8")
        helper = self.root / HELPER_FILE
        helper.parent.mkdir(parents=True)
        helper.write_text("package helpers;\npublic class Transform {\n"
                          "public static String clean(String value) { return value; }\n}\n",
                          encoding="utf-8")
        self.defaults = profiles.current_settings()

    def triage(self, response=RESPONSE, mode="single"):
        log = []
        run = pipeline.triage(ALERT, mode, caller_factory=lambda: CannedCaller(response, log),
                              kb=EmptyKnowledgeBase(), benchmark_root=self.root)
        return run, log

    def assert_profile(self, name, *, window, related, worksheet, retrieval):
        with profiles.use_profile(name, check_ready=False) as applied:
            self.assertEqual(config.ACTIVE_PROFILE, name)
            self.assertEqual(applied, profiles.PROFILES[name])
            run, log = self.triage()
            system, user = log[0]["system"], log[0]["user"]
            schema = sent_schema()
            mode = KnowledgeBase(mode=None).mode

        # Prompt: the worksheet is asked for only when it is on; no checklist ever.
        self.assertEqual('"analysis": {' in system, worksheet)
        self.assertEqual("reaches_sink=yes and protection_effective=no" in system, worksheet)
        self.assertNotIn("checklist", system.lower())
        # Strict schema: analysis required (and allowed) only with the worksheet.
        self.assertEqual("analysis" in schema["required"], worksheet)
        self.assertEqual("analysis" in schema["properties"], worksheet)
        self.assertFalse(schema["additionalProperties"])
        # Evidence block: window size and related source.
        source = run["payload"]["source"]
        numbers = [int(line.split(":", 1)[0]) for line in source["lines"]]
        self.assertEqual((numbers[0], max(n for n in numbers if n <= 70 + window)),
                         (70 - window, 70 + window))
        self.assertEqual("35: int marker35 = 35;" in user, window >= 35)
        self.assertEqual("140: String helper(String value) {" in user, related)
        self.assertEqual(f"--- Related source: {HELPER_FILE}" in user, related)
        self.assertEqual(bool(source["related"]), related)
        # Retrieval mode the profile selects (read when a KnowledgeBase is created).
        self.assertEqual(mode, retrieval)
        # Everything is restored afterwards.
        self.assertEqual(profiles.current_settings(), self.defaults)
        self.assertIsNone(config.ACTIVE_PROFILE)

    def test_base_profile(self):
        self.assert_profile("base", window=25, related=False, worksheet=False, retrieval="map")

    def test_evidence_profile(self):
        self.assert_profile("evidence", window=60, related=True, worksheet=False, retrieval="map")

    def test_worksheet_profile(self):
        self.assert_profile("worksheet", window=60, related=True, worksheet=True, retrieval="map")

    def test_semantic_profile(self):
        self.assert_profile("semantic", window=60, related=True, worksheet=False, retrieval="semantic")

    def test_profiles_match_the_documented_table(self):
        table = {name: (p["SOURCE_WINDOW_LINES"], p["SOURCE_RELATED_ENABLED"],
                        p["REVIEW_WORKSHEET_ENABLED"], p["RETRIEVAL_MODE"])
                 for name, p in profiles.PROFILES.items()}
        self.assertEqual(table, {
            "base": (25, False, False, "map"),
            "evidence": (60, True, False, "map"),
            "worksheet": (60, True, True, "map"),
            "semantic": (60, True, False, "semantic"),
        })

    def test_consistency_repair_fires_only_with_the_worksheet(self):
        contradictory = dict(RESPONSE, verdict="false_positive", analysis=ANALYSIS)
        for name, calls in (("base", 1), ("evidence", 1), ("worksheet", 2)):
            with self.subTest(profile=name), profiles.use_profile(name, check_ready=False):
                _, log = self.triage(contradictory)
                self.assertEqual(len(log), calls)
        with profiles.use_profile("evidence", check_ready=False):
            _, log = self.triage(contradictory, mode="council")
        self.assertEqual(len(log), 3)                      # Analyst, Skeptic, Chair: no repair

    def test_settings_are_restored_when_the_run_fails(self):
        with self.assertRaises(RuntimeError):
            with profiles.use_profile("base"):
                self.assertEqual(config.SOURCE_WINDOW_LINES, 25)
                raise RuntimeError("model call crashed")
        self.assertEqual(profiles.current_settings(), self.defaults)
        self.assertIsNone(config.ACTIVE_PROFILE)

    def test_unknown_profile(self):
        with self.assertRaisesRegex(profiles.ProfileError, "unknown profile 'fast'"):
            with profiles.use_profile("fast"):
                pass

    def test_semantic_profile_stops_until_catalogue_and_vector_store_exist(self):
        catalogue = self.root / "cwe.xml"
        store = self.root / "kb_vectors.sqlite"
        with patch.multiple(config, CWE_CATALOGUE_XML=catalogue, KB_VECTOR_DB=store):
            with self.assertRaises(profiles.ProfileError) as raised:
                with profiles.use_profile("semantic"):
                    self.fail("must not enter the profile")
            message = str(raised.exception)
            self.assertIn(profiles.CATALOGUE_COMMAND, message)
            self.assertIn(profiles.VECTOR_STORE_COMMAND, message)
            self.assertEqual(profiles.current_settings(), self.defaults)

            catalogue.write_text("<catalogue/>", encoding="utf-8")
            with sqlite3.connect(store) as conn:
                conn.execute("CREATE TABLE kb_chunks (chunk_id TEXT)")
                conn.execute("INSERT INTO kb_chunks VALUES ('SQL#1')")
            conn.close()
            self.assertEqual(profiles.missing_prerequisites("semantic"), [])
            with profiles.use_profile("semantic"):
                self.assertEqual(config.RETRIEVAL_MODE, "semantic")
        self.assertEqual(profiles.missing_prerequisites("base"), [])

    def test_provenance_names_the_profile_and_its_settings(self):
        self.assertEqual(profiles.provenance(), {"name": None, "settings": self.defaults})
        with profiles.use_profile("evidence", check_ready=False):
            self.assertEqual(profiles.provenance(),
                             {"name": "evidence", "settings": profiles.PROFILES["evidence"]})


if __name__ == "__main__":
    unittest.main()
