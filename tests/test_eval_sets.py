"""Offline tests for the frozen experiment case sets (triagebot/nodes/ingest/eval_sets.py).

The builder runs on the small ingest fixtures with rules sized to them; the
committed data/samples/ files are checked for label-freedom and fingerprints.
"""
import isolated_store  # noqa: F401  (first: keeps every test off the real vector store)
import json
from pathlib import Path
import tempfile
import unittest

from triagebot import config
from triagebot.nodes.ingest import eval_sets
from triagebot.schemas import NormalisedAlert

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/ingest"
SEMGREP = FIXTURES / "semgrep.json"
ANSWER_KEY = FIXTURES / "expectedresults.csv"
ALERT_FIELDS = set(NormalisedAlert.__annotations__)
LABEL_KEYS = ("vulnerable", "category", "real vulnerability", "expected", "label")

# Fixture split (seed 201): 00001 sqli real, 00002 sqli safe, 00004 cmdi real and
# 00005 xss safe are dev cases with a CWE-matching alert; 00003 (test) has none.
FIXTURE_RULES = [
    {"name": "pilot", "partition": "dev", "sizes": {"CWE-89": 2}, "exclude": [],
     "purpose": "fixture pilot"},
    {"name": "comparison", "partition": "dev", "sizes": {"CWE-78": 1, "CWE-79": 1},
     "exclude": ["pilot"], "purpose": "fixture comparison"},
    {"name": "final-test", "partition": "dev", "sizes": {"CWE-79": 1}, "exclude": ["retired"],
     "purpose": "fixture final test (dev here: the fixture's test half has no matching alert)"},
]


def case(n):
    return f"BenchmarkTest{n:05d}"


class FixtureBuild(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.evidence = self.tmp / "evidence"
        self.reference = self.write_sample(self.evidence / "checkpoint" / "selected_alerts.json",
                                           [case(1), case(2)])
        self.write_sample(self.evidence / "older" / "selected_alerts.json", [case(9)])
        audit = self.evidence / "fresh-120" / "prior_case_audit.json"
        audit.parent.mkdir(parents=True)
        audit.write_text(json.dumps({"prior_case_ids": [case(10)]}), encoding="utf-8")

    def write_sample(self, path, case_ids):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"alerts": [{"case_id": c} for c in case_ids]}), encoding="utf-8")
        return path

    def build(self, **overrides):
        args = dict(semgrep_path=SEMGREP, answer_key_path=ANSWER_KEY, evidence_dir=self.evidence,
                    pilot_reference=self.reference, rules=FIXTURE_RULES,
                    samples_dir=self.tmp / "samples")
        args.update(overrides)
        return eval_sets.build(**args)

    def test_building_twice_gives_byte_identical_files(self):
        first_dir, second_dir = self.tmp / "one", self.tmp / "two"
        eval_sets.write(self.build(), first_dir)
        eval_sets.write(self.build(), second_dir)
        names = sorted(p.name for p in first_dir.iterdir())
        self.assertEqual(names, sorted(p.name for p in second_dir.iterdir()))
        self.assertEqual(len(names), 7)
        for name in names:
            raw = (first_dir / name).read_bytes()
            self.assertEqual(raw, (second_dir / name).read_bytes(), name)
            self.assertNotIn(b"\r\n", raw, f"{name} must use LF line endings")

    def test_sets_follow_their_rules(self):
        files = self.build()
        ids = {name: [a["case_id"] for a in json.loads(files[f"{name}.json"])["alerts"]]
               for name in eval_sets.SET_NAMES}
        self.assertEqual(ids["pilot"], [case(1), case(2)])
        self.assertEqual(ids["comparison"], [case(4), case(5)])
        self.assertFalse(set(ids["comparison"]) & set(ids["pilot"]))
        self.assertEqual(ids["final-test"], [case(5)])

    def test_model_side_sample_files_hold_no_answer_key_data(self):
        files = self.build()
        for name in eval_sets.SET_NAMES:
            sample = json.loads(files[f"{name}.json"])
            for alert in sample["alerts"]:
                self.assertEqual(set(alert), ALERT_FIELDS)
            text = files[f"{name}.json"].lower()
            for word in LABEL_KEYS + ("true", "false", "real", "safe"):
                self.assertNotIn(f'"{word}"', text, f"{word!r} in {name}.json")

    def test_manifest_records_rule_seed_scan_and_fingerprints(self):
        files = self.build()
        manifest = json.loads(files["comparison.manifest.json"])
        self.assertEqual((manifest["split_seed"], manifest["sample_seed"]), (201, 201))
        self.assertEqual(manifest["partition"], "dev")
        self.assertEqual(manifest["scan"]["sha256"], eval_sets.file_sha256(SEMGREP))
        self.assertEqual(manifest["sample"]["sha256"],
                         eval_sets.lf_sha256(files["comparison.json"].encode("utf-8")))
        self.assertEqual(manifest["cases"], 2)
        self.assertEqual(manifest["composition"]["CWE-78"]["real"], 1)
        self.assertEqual(manifest["composition"]["CWE-79"]["safe"], 1)
        self.assertEqual(manifest["excludes"], {"sets": ["pilot"], "cases": 2})
        self.assertNotIn(case(4), files["comparison.manifest.json"])     # aggregates only
        self.assertNotIn(str(self.tmp), files["comparison.manifest.json"])

    def test_retired_list_is_the_union_of_earlier_samples(self):
        retired = json.loads(self.build()[eval_sets.RETIRED_NAME])
        self.assertEqual(retired["case_ids"], [case(1), case(2), case(9), case(10)])
        self.assertEqual(retired["count"], 4)
        self.assertTrue(retired["reason"])

    def test_final_test_never_takes_a_retired_case(self):
        self.write_sample(self.evidence / "later" / "selected_alerts.json", [case(5)])
        rules = [dict(rule) for rule in FIXTURE_RULES]
        rules[1] = dict(rules[1], sizes={"CWE-78": 1})  # keep 00005 out of the comparison set
        with self.assertRaisesRegex(eval_sets.EvalSetError, "final-test: not enough eligible"):
            self.build(rules=rules)
        rules[2] = dict(rules[2], exclude=[])           # without the exclusion: overlap is fatal
        with self.assertRaisesRegex(eval_sets.EvalSetError, "final-test overlaps 1 retired"):
            self.build(rules=rules)

    def test_comparison_never_takes_a_retired_case_outside_the_pilot(self):
        self.write_sample(self.evidence / "later" / "selected_alerts.json", [case(4)])
        with self.assertRaisesRegex(eval_sets.EvalSetError, "comparison overlaps 1 retired"):
            self.build()

    def test_pilot_must_equal_the_checkpoint_sample(self):
        wrong = self.write_sample(self.tmp / "wrong.json", [case(1), case(4)])
        with self.assertRaisesRegex(eval_sets.EvalSetError, "pilot does not equal"):
            self.build(pilot_reference=wrong)

    def test_lf_fingerprint_ignores_crlf_checkouts(self):
        self.assertEqual(eval_sets.lf_sha256(b"a\r\nb\r\n"), eval_sets.lf_sha256(b"a\nb\n"))

    def test_load_set_refuses_a_changed_file(self):
        out = self.tmp / "samples"
        eval_sets.write(self.build(), out)
        alerts, manifest = eval_sets.load_set("comparison", out)
        self.assertEqual(len(alerts), manifest["cases"])
        path = out / "comparison.json"
        path.write_text(path.read_text(encoding="utf-8").replace(case(4), case(7)), encoding="utf-8")
        with self.assertRaisesRegex(eval_sets.EvalSetError, "fingerprint"):
            eval_sets.load_set("comparison", out)
        with self.assertRaisesRegex(eval_sets.EvalSetError, "not found"):
            eval_sets.load_set("missing", out)


class CommittedSets(unittest.TestCase):
    """The frozen files in data/samples/ (the model reads only the alerts)."""

    def load(self, name):
        return json.loads((config.SAMPLES_DIR / name).read_text(encoding="utf-8"))

    def test_samples_are_label_free_normalised_alerts(self):
        for name in eval_sets.SET_NAMES:
            sample = self.load(f"{name}.json")
            self.assertEqual(set(sample), {"selection", "alerts"})
            for alert in sample["alerts"]:
                self.assertEqual(set(alert), ALERT_FIELDS, name)
            selection = json.dumps(sample["selection"]).lower()
            for word in LABEL_KEYS + ("real", "safe"):
                self.assertNotIn(f'"{word}"', selection, f"{word!r} in {name}.json")

    def test_sizes_composition_and_fingerprints(self):
        expected = {"pilot": (100, {"CWE-89": (50, 50)}),
                    "comparison": (96, {c: (12, 12) for c in config.EVAL_SET_CWES}),
                    "final-test": (120, {c: (15, 15) for c in config.EVAL_SET_CWES})}
        for name, (size, composition) in expected.items():
            with self.subTest(set=name):
                alerts, manifest = eval_sets.load_set(name)        # checks the fingerprint
                self.assertEqual(len(alerts), size)
                self.assertEqual(manifest["cases"], size)
                self.assertEqual({cwe: (row["real"], row["safe"])
                                  for cwe, row in manifest["composition"].items()}, composition)
                self.assertEqual(manifest["scan"]["file"], "data/semgrep/semgrep-owasp-p-java-1.178.0.json")
                self.assertEqual(manifest["scan"]["sha256"], eval_sets.file_sha256(config.RECORDED_SCAN))

    def test_no_overlaps_between_sets_and_retired(self):
        ids = {name: {a["case_id"] for a in eval_sets.load_set(name)[0]} for name in eval_sets.SET_NAMES}
        retired = set(self.load(eval_sets.RETIRED_NAME)["case_ids"])
        self.assertFalse(ids["comparison"] & ids["pilot"])
        self.assertFalse(ids["final-test"] & retired)
        self.assertFalse(ids["comparison"] & retired)
        self.assertLessEqual(ids["pilot"], retired)                   # the pilot was used before

    def test_pilot_is_the_checkpoint_sample(self):
        reference = json.loads(config.CHECKPOINT_EVIDENCE_SAMPLE.read_text(encoding="utf-8"))
        self.assertEqual([a["case_id"] for a in self.load("pilot.json")["alerts"]],
                         sorted(a["case_id"] for a in reference["alerts"]))

    def test_retired_list_matches_the_evidence_folder(self):
        committed = self.load(eval_sets.RETIRED_NAME)
        self.assertEqual(committed, eval_sets.retired_cases(config.EVIDENCE_DIR))
        self.assertEqual(committed["case_ids"], sorted(committed["case_ids"]))

    @unittest.skipUnless(config.ANSWER_KEY and Path(config.ANSWER_KEY).is_file(),
                         "needs the OWASP Benchmark answer key")
    def test_rebuild_reproduces_the_committed_files(self):
        for name, text in eval_sets.build().items():
            self.assertEqual(text.encode("utf-8").replace(b"\r\n", b"\n"),
                             (config.SAMPLES_DIR / name).read_bytes().replace(b"\r\n", b"\n"), name)


if __name__ == "__main__":
    unittest.main()
