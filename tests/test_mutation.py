"""Offline tests for step 5, the mutation test (EXPERIMENTS.md, design decision 30).

Covers the pattern and its eligibility rules on small fixture files, the flip
proof (a tie at 200 is rejected), the frozen set holding no labels, the overlay
root changing only the mutated file, the evidence pack of an original and its
mutant differing only on the mutated line (comments never reach the prompt), the
mutation score on a hand-made example, and a whole step 5 run with a fixture
caller. No network, no model, no real Benchmark checkout.
"""
import isolated_store  # noqa: F401  (first: keeps every test off the real vector store)
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from rich.console import Console

from triagebot import __main__ as cli, config, experiments, mutants, profiles
from triagebot.nodes.context.payload import build_payload
from triagebot.nodes.ingest import eval_sets, mutation_set
from triagebot.nodes.ingest.normalise import load_semgrep, normalise
from triagebot.nodes.review.prompts import to_prompt_block

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/ingest"
ANSWER_KEY = FIXTURES / "expectedresults.csv"
LABEL_KEYS = {"vulnerable", "category", "expected", "real vulnerability", "label", "labels"}
GIVEAWAY = "assigns param to bar on false condition"
CLEAN = {"commit": "c" * 40, "dirty": False, "dirty_paths": []}


def java_case(name, op="-", a=7, b=42, num=106, extra="", pad=0):
    """A Benchmark-style case: the alert line, a helper call and the constant ternary.

    ``pad`` blank lines before the package line move the code down (the ingest fixtures'
    alerts sit at lines 44 and 75).
    """
    return "\n" * pad + f"""package org.owasp.benchmark.testcode;

public class {name} extends HttpServlet {{
    public void doPost(HttpServletRequest request, HttpServletResponse response) {{
        String param = request.getParameter("vector");
        String bar = doSomething(request, param);
        String cmd = org.owasp.benchmark.helpers.Utils.getInsecureOSCommandString(bar);
        Runtime.getRuntime().exec(cmd);
    }}

    private static String doSomething(HttpServletRequest request, String param) {{
        String bar;
        // Simple ? condition that {GIVEAWAY}
        int num = {num};
        /* a block comment: (1 * 1) + num > 200 ? "x" : param */
        bar = ({a} * {b}) {op} num > 200 ? "This should never happen" : param;
{extra}        return bar;
    }}
}}
"""


UTILS = """package org.owasp.benchmark.helpers;

public class Utils {
    public static String getInsecureOSCommandString(String input) {
        String script = "insecureCmd.sh";
        return script + " " + input;
    }
}
"""


def write_benchmark(root, cases):
    """A fake checkout: the given {relative file: text}, a helper class, a script, a web file."""
    root = Path(root)
    files = {"src/main/java/org/owasp/benchmark/helpers/Utils.java": UTILS,
             "src/main/resources/insecureCmd.sh": "#!/bin/sh\necho $1\n",
             "src/main/webapp/index.html": "<html></html>\n", **cases}
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return root


def tree_bytes(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


def fixture_alerts():
    raw, scan_date = load_semgrep(FIXTURES / "semgrep.json")
    return normalise(raw, scan_date)[0]


def write_set(samples, name, alerts):
    """A frozen set in the shape load_set() reads (sample plus fingerprinted manifest)."""
    text = eval_sets.to_text({"selection": {"set": name}, "alerts": alerts})
    eval_sets.write({f"{name}.json": text, f"{name}.manifest.json": eval_sets.to_text(
        {"set": name, "sample": {"sha256": eval_sets.lf_sha256(text.encode("utf-8"))}})}, samples)


def keys_of(value):
    if isinstance(value, dict):
        return set(value) | set().union(*(keys_of(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(keys_of(v) for v in value)) if value else set()
    return set()


def plain_console(stream):
    return Console(file=stream, width=220, color_system=None, highlight=False)


def capture(func, *args, answers=(), **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.multiple(cli, console=plain_console(out), err_console=plain_console(err)), \
            mock.patch("builtins.input", side_effect=list(answers)) as asked, \
            redirect_stdout(out), redirect_stderr(err):
        result = func(*args, **kwargs)
    return result, out.getvalue(), err.getvalue(), asked.call_count


class StubKnowledgeBase:
    """Guidance that depends on the alert only, as semantic retrieval does (no fastembed)."""

    def __init__(self, *args, **kwargs):
        self.calls = []

    def retrieve(self, alert, extra_terms=None):
        self.calls.append(alert["cwe"])
        return {"source": "fixture", "cwe_matched": True, "chunks": [
            {"chunk_id": f"{alert['cwe']}#1", "doc": "Sheet", "section": "Defences",
             "text": f"Guidance for {alert['cwe']}.", "url": "https://example.test/sheet"}]}


class ReadingCallers:
    """A caller factory that reads the constant condition in the prompt: a perfect reviewer.

    True condition: the constant is used (false_positive); false: the input flows
    (true_positive). Cites the condition's line with a quote taken from the prompt.
    """

    def __init__(self):
        self.calls = 0
        self.prompts = []

    def __call__(self):
        owner = self

        class Caller:
            last_call = None

            def complete(self, request):
                owner.calls += 1
                user = request["user"]
                owner.prompts.append(user)
                self.last_call = {"model": "fixture-model", "latency_seconds": 0.1,
                                  "usage": {"prompt_tokens": 50, "completion_tokens": 10, "cost": 0.001}}
                a, b, op, cmp = re.search(r"\((\d+) \* (\d+)\) ([+-]) num ([<>]) 200", user).groups()
                num = int(re.search(r"int num = (\d+);", user).group(1))
                value = int(a) * int(b) + (num if op == "+" else -num)
                constant = value > 200 if cmp == ">" else value < 200
                file = re.search(r"^file: (.+)$", user, re.M).group(1)
                cited = re.search(r"^(\d+): \s*(\S.*num [<>] 200.*\S)", user, re.M)   # the condition
                line, quote = int(cited.group(1)), cited.group(2)
                return {"verdict": "false_positive" if constant else "true_positive",
                        "explanation": "Read the constant condition.",
                        "citations": [{"file": file, "line": line, "quote": quote}],
                        "guidance": []}
        return Caller()


# --- the pattern and the flip proof -----------------------------------------------------------

class PatternTest(unittest.TestCase):
    def test_the_pattern_is_found_with_its_constants_and_line(self):
        text = java_case("BenchmarkTest00004")
        found = mutation_set.find_pattern(text)
        self.assertEqual((found["a"], found["b"], found["op"], found["num"]), (7, 42, "-", 106))
        self.assertEqual(found["input"], "param")
        self.assertEqual(text.splitlines()[found["line"] - 1].strip(),
                         'bar = (7 * 42) - num > 200 ? "This should never happen" : param;')
        self.assertEqual(text[found["cmp_offset"]], ">")

    def test_a_commented_out_copy_does_not_count(self):
        # java_case() holds the pattern inside a block comment as well.
        self.assertEqual(mutation_set.find_pattern(java_case("T"))["line"], 16)

    def test_two_ternaries_are_rejected(self):
        second = '        bar = (7 * 42) - num > 200 ? "This should never happen" : param;\n'
        with self.assertRaisesRegex(mutation_set.MutationError, "2 ternaries"):
            mutation_set.find_pattern(java_case("T", extra=second))
        mutated_copy = second.replace(">", "<")              # one '>' and one '<': still two
        with self.assertRaisesRegex(mutation_set.MutationError, "2 ternaries"):
            mutation_set.find_pattern(java_case("T", extra=mutated_copy))

    def test_no_ternary_two_nums_or_another_comparison_are_rejected(self):
        with self.assertRaisesRegex(mutation_set.MutationError, "0 ternaries"):
            mutation_set.find_pattern("class T { int num = 5; String bar = param; }")
        with self.assertRaisesRegex(mutation_set.MutationError, "2 'int num"):
            mutation_set.find_pattern(java_case("T", extra="        int num = 7;\n"))
        with self.assertRaisesRegex(mutation_set.MutationError, "not 'num > 200'"):
            mutation_set.find_pattern(java_case("T").replace("num > 200", "num < 200", 2))

    def test_the_flip_proof(self):
        minus = mutation_set.flip_proof(mutation_set.find_pattern(java_case("T", "-", 7, 42, 106)))
        self.assertEqual((minus["value"], minus["original_condition"], minus["mutated_condition"]),
                         (188, False, True))
        self.assertEqual((minus["original_branch"], minus["mutated_branch"]), ("input", "constant"))
        plus = mutation_set.flip_proof(mutation_set.find_pattern(java_case("T", "+", 7, 18, 106)))
        self.assertEqual((plus["value"], plus["original_condition"], plus["mutated_condition"]),
                         (232, True, False))

    def test_a_tie_at_200_is_rejected(self):
        tie = mutation_set.find_pattern(java_case("T", "-", 7, 42, 94))      # 294 - 94 = 200
        with self.assertRaisesRegex(mutation_set.MutationError, "tied at exactly 200"):
            mutation_set.flip_proof(tie)

    def test_the_mutation_changes_one_character_and_no_line(self):
        text = java_case("T").replace("\n", "\r\n")                 # CRLF survives untouched
        found = mutation_set.describe(text)
        mutated = found["mutated_text"]
        self.assertEqual(len(mutated), len(text))
        self.assertEqual([i for i, (x, y) in enumerate(zip(text, mutated)) if x != y],
                         [found["pattern"]["cmp_offset"]])
        self.assertEqual(found["mutated"], '(7 * 42) - num < 200 ? "This should never happen" : param')
        self.assertEqual(mutated.count("\r\n"), text.count("\r\n"))


# --- eligibility --------------------------------------------------------------------------------

class EligibilityTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def alert(self, case_id, text=None):
        file = f"src/main/java/org/owasp/benchmark/testcode/{case_id}.java"
        if text is not None:
            write_benchmark(self.root, {file: text})
        return {"case_id": case_id, "file": file, "rule_id": "rule", "cwe": "CWE-78",
                "start_line": 8, "end_line": 8, "message": "m"}

    def test_the_condition_must_decide_the_answer(self):
        cases = {   # case id: (vulnerable, file text)
            "BenchmarkTest00001": (True, java_case("A", "-")),        # false: input flows -> real
            "BenchmarkTest00002": (False, java_case("B", "+", 7, 18)),  # true: constant -> safe
            "BenchmarkTest00003": (False, java_case("C", "-")),       # safe, but the input flows
            "BenchmarkTest00004": (True, java_case("D", "+", 7, 18)),  # real, but the constant is used
            "BenchmarkTest00005": (True, java_case("E", extra='        bar = (1 * 2) + num > 200 ? "x" : param;\n')),
            "BenchmarkTest00006": (True, java_case("F", "-", 7, 42, 94)),   # tied at 200
        }
        alerts = [self.alert(c, text) for c, (_, text) in cases.items()]
        key = {c: {"vulnerable": v, "cwe": "CWE-78", "category": "cmdi"} for c, (v, _) in cases.items()}
        split = dict.fromkeys(cases, "dev")
        eligible, rejected = mutation_set.screen(alerts, key, split, self.root)
        self.assertEqual([e["case_id"] for e in eligible["real_to_safe"]], ["BenchmarkTest00001"])
        self.assertEqual([e["case_id"] for e in eligible["safe_to_real"]], ["BenchmarkTest00002"])
        self.assertEqual(rejected, {
            "2 ternaries of the form (expected exactly one)": 1,
            "label does not match the branch (the answer depends on something else)": 2,
            "tied at exactly 200: neither '>' nor '<' holds, so the swap flips nothing": 1})
        entry = eligible["real_to_safe"][0]
        self.assertEqual(entry["mutated"], entry["original"].replace(">", "<"))
        self.assertEqual(entry["values"]["original_condition"], False)

    def test_a_test_half_case_is_never_opened(self):
        alert = self.alert("BenchmarkTest00009")                  # no file written: never read
        key = {"BenchmarkTest00009": {"vulnerable": True, "cwe": "CWE-78", "category": "cmdi"}}
        with self.assertRaisesRegex(mutation_set.MutationError, "not in the dev half"):
            mutation_set.screen([alert], key, {"BenchmarkTest00009": "test"}, self.root)

    def test_selection_draws_per_direction_with_the_seed(self):
        entries = {d: [{"case_id": f"{d}{n}"} for n in range(5)] for d in mutation_set.DIRECTIONS}
        first = mutation_set.select(entries, 3, 201)
        self.assertEqual(first, mutation_set.select(entries, 3, 201))
        self.assertTrue(all(len(v) == 3 for v in first.values()))
        short = mutation_set.select({"real_to_safe": entries["real_to_safe"][:2], "safe_to_real": []}, 3, 201)
        self.assertEqual((len(short["real_to_safe"]), len(short["safe_to_real"])), (2, 0))


# --- building the frozen set ----------------------------------------------------------------------

class BuildTest(unittest.TestCase):
    """mutation_set.build() over the ingest fixtures with a fake checkout."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.samples, self.bench = self.tmp / "samples", self.tmp / "BenchmarkJava"
        self.evidence = self.tmp / "evidence"
        (self.evidence / "old").mkdir(parents=True)
        (self.evidence / "old" / "selected_alerts.json").write_text(
            json.dumps({"alerts": [{"case_id": "BenchmarkTest00009"}]}), encoding="utf-8")
        self.alerts = {a["case_id"]: a for a in fixture_alerts()}
        build_fixture_set(self.bench, self.samples, self.evidence, self.alerts)

    def build(self):
        return mutation_set.build(FIXTURES / "semgrep.json", ANSWER_KEY, self.bench, self.evidence,
                                  samples_dir=self.samples)

    def test_the_set_holds_the_pairs_and_no_labels(self):
        files, report = self.build()
        data = json.loads(files["mutation.json"])
        manifest = json.loads(files["mutation.manifest.json"])
        self.assertEqual([e["case_id"] for e in data["mutations"]], ["BenchmarkTest00004", "BenchmarkTest00005"])
        self.assertEqual([a["case_id"] for a in data["alerts"]], ["BenchmarkTest00004", "BenchmarkTest00005"])
        self.assertEqual(keys_of(data) & LABEL_KEYS, set())
        self.assertNotIn("true_positive", files["mutation.json"])
        self.assertNotIn("false_positive", files["mutation.json"])
        entry = data["mutations"][0]
        self.assertEqual(sorted(entry), ["alert", "case_id", "file", "line", "mutant_sha256", "mutated",
                                         "original", "source_sha256", "values"])
        self.assertEqual(manifest["sample"]["sha256"], eval_sets.lf_sha256(files["mutation.json"].encode()))
        self.assertEqual(manifest["composition"]["CWE-78"]["real_to_safe"], 1)
        self.assertEqual(manifest["composition"]["CWE-79"]["safe_to_real"], 1)
        self.assertEqual(manifest["composition"]["CWE-78"]["shortfall"], 5)
        self.assertEqual(report["selected"]["CWE-78"]["real_to_safe"], ["BenchmarkTest00004"])
        self.assertEqual(files, self.build()[0])                 # deterministic
        eval_sets.write(files, self.samples)
        alerts, _ = eval_sets.load_set("mutation", self.samples)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(sorted(mutation_set.load_mutations(self.samples)), ["BenchmarkTest00004", "BenchmarkTest00005"])

    def test_a_case_in_the_comparison_set_is_left_out(self):
        write_set(self.samples, "comparison", [self.alerts["BenchmarkTest00004"]])
        files, _ = self.build()
        self.assertEqual([e["case_id"] for e in json.loads(files["mutation.json"])["mutations"]],
                         ["BenchmarkTest00005"])


def build_fixture_set(bench, samples, evidence, alerts):
    """Fake sources for every dev candidate (two with the pattern), empty pilot and comparison."""
    sources = {}
    for case_id, alert in alerts.items():
        if alert["file"].startswith("src/main/java/org/owasp/benchmark/testcode/"):
            sources[alert["file"]] = f"class {case_id} {{ String bar = param; }}\n"
    sources[alerts["BenchmarkTest00004"]["file"]] = java_case("BenchmarkTest00004", "-", pad=40)     # real
    sources[alerts["BenchmarkTest00005"]["file"]] = java_case("BenchmarkTest00005", "+", 7, 18, pad=40)  # safe
    write_benchmark(bench, sources)
    write_set(samples, "pilot", [])
    write_set(samples, "comparison", [])


# --- overlay roots and the same evidence -----------------------------------------------------------

class OverlayTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.file = "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00004.java"
        self.bench = write_benchmark(self.tmp / "BenchmarkJava", {
            self.file: java_case("BenchmarkTest00004"),
            "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00005.java": java_case("BenchmarkTest00005", "+"),
        })
        self.alert = {"case_id": "BenchmarkTest00004", "file": self.file,
                      "rule_id": "java.lang.security.command-injection", "cwe": "CWE-78",
                      "start_line": 8, "end_line": 8, "message": "Possible command injection."}
        key = {"BenchmarkTest00004": {"vulnerable": True, "cwe": "CWE-78", "category": "cmdi"}}
        eligible, _ = mutation_set.screen([self.alert], key, {"BenchmarkTest00004": "dev"}, self.bench)
        self.entry = eligible["real_to_safe"][0]
        self.overlays = self.tmp / "overlay"

    def test_the_overlay_root_changes_only_the_mutated_file(self):
        before = tree_bytes(self.bench)
        root = mutants.build_overlay(self.entry, self.bench, self.overlays)
        self.assertEqual(tree_bytes(self.bench), before)              # the checkout is only read
        copied = {k: v for k, v in tree_bytes(root).items() if k != mutants.MARKER}
        expected = {k: v for k, v in before.items()
                    if any(k.startswith(tree + "/") for tree in mutants.OVERLAY_TREES)}
        self.assertEqual(sorted(copied), sorted(expected))
        self.assertNotIn("src/main/webapp/index.html", copied)        # not read by the evidence code
        changed = [k for k in copied if copied[k] != expected[k]]
        self.assertEqual(changed, [self.file])
        diff = [i for i, (x, y) in enumerate(zip(expected[self.file], copied[self.file])) if x != y]
        self.assertEqual(len(diff), 1)
        self.assertEqual((expected[self.file][diff[0]:diff[0] + 1], copied[self.file][diff[0]:diff[0] + 1]),
                         (b">", b"<"))
        self.assertEqual(eval_sets.lf_sha256(copied[self.file]), self.entry["mutant_sha256"])
        self.assertFalse((root / self.file).samefile(self.bench / self.file))

    def test_overlays_are_reused_rebuilt_and_checked(self):
        roots = mutants.ensure_overlays({"BenchmarkTest00004": self.entry}, self.bench, self.overlays)
        root = roots["BenchmarkTest00004"]
        self.assertTrue(mutants.overlay_is_current(root, self.entry))
        (root / self.file).write_text("tampered", encoding="utf-8")
        self.assertFalse(mutants.overlay_is_current(root, self.entry))
        mutants.ensure_overlays({"BenchmarkTest00004": self.entry}, self.bench, self.overlays)
        self.assertTrue(mutants.overlay_is_current(root, self.entry))
        stale = {**self.entry, "source_sha256": "0" * 64}
        with self.assertRaisesRegex(mutants.OverlayError, "differs from the file the mutation set"):
            mutants.build_overlay(stale, self.bench, self.overlays)
        with self.assertRaisesRegex(mutants.OverlayError, "must not contain each other"):
            mutants.build_overlay(self.entry, self.bench, self.bench / "overlay")
        self.assertEqual(mutants.clean(self.overlays), 1)
        self.assertFalse(root.exists())

    def test_the_evidence_packs_differ_only_on_the_mutated_line(self):
        root = mutants.build_overlay(self.entry, self.bench, self.overlays)
        kb = StubKnowledgeBase()
        with profiles.applied(profiles.PROFILES["semantic"]):
            original = build_payload(self.alert, kb, self.bench)
            mutant = build_payload(self.alert, kb, root)
        self.assertEqual(kb.calls, ["CWE-78", "CWE-78"])
        # Related source (the helper and the script it names) and guidance match exactly.
        self.assertEqual([r["file"] for r in original["source"]["related"]],
                         ["src/main/java/org/owasp/benchmark/helpers/Utils.java",
                          "src/main/resources/insecureCmd.sh"])
        self.assertEqual(original["source"]["related"], mutant["source"]["related"])
        self.assertEqual(original["guidance"], mutant["guidance"])
        self.assertEqual(original["alert"], mutant["alert"])
        prefix = f"{self.entry['line']}: "
        for part in ("lines",):
            a, b = original["source"][part], mutant["source"][part]
            self.assertEqual(len(a), len(b))
            changed = [(x, y) for x, y in zip(a, b) if x != y]
            self.assertEqual(len(changed), 1)                         # the mutated line, visible
            self.assertTrue(changed[0][0].startswith(prefix))
            self.assertEqual(changed[0][1], changed[0][0].replace("num > 200", "num < 200"))
        for key in original["facts"]:
            for x, y in zip(original["facts"][key], mutant["facts"][key]):
                self.assertTrue(x == y or (x.startswith(prefix) and y.startswith(prefix)))
        # The prompts: every line equal except the mutated line.
        first, second = to_prompt_block(original).splitlines(), to_prompt_block(mutant).splitlines()
        self.assertEqual(len(first), len(second))
        differing = {x for x, y in zip(first, second) if x != y}
        self.assertTrue(differing)
        self.assertTrue(all(line.lstrip().startswith(prefix) for line in differing))
        # Comments are stripped: the giveaway comment never reaches the AI.
        for text in (json.dumps(original), json.dumps(mutant), "\n".join(first), "\n".join(second)):
            self.assertNotIn(GIVEAWAY, text)
            self.assertNotIn("block comment", text)


# --- the mutation score --------------------------------------------------------------------------

class ScoringTest(unittest.TestCase):
    def test_killed_survived_escalated_and_the_precondition(self):
        labels = {"R1": True, "R2": True, "R3": True, "R4": True, "S1": False, "S2": False, "S3": False}
        before = [("R1", "true_positive"), ("R2", "true_positive"), ("R3", "true_positive"),
                  ("R4", "false_positive"), ("S1", "false_positive"), ("S2", "human_review"),
                  ("S3", "false_positive")]
        after = [("R1", "false_positive"),       # killed
                 ("R2", "true_positive"),        # survived: unchanged
                 ("R3", "human_review"),         # escalated: not a kill
                 ("R4", "false_positive"),       # excluded: the original was wrong
                 ("S1", "true_positive"),        # killed
                 ("S2", "true_positive"),        # excluded: the original went to a human
                 ("S3", "not-a-verdict")]        # unreadable counts as sent to a human: escalated
        result = mutants.score_pairs(labels, labels, {
            "B-single-agent": [{"case_id": c, "verdict": v} for c, v in before],
            "only-before": []}, {"B-single-agent": [{"case_id": c, "verdict": v} for c, v in after]})
        self.assertEqual(list(result["configurations"]), ["B-single-agent"])
        row = result["configurations"]["B-single-agent"]
        self.assertEqual(row["overall"], {"pairs": 7, "precondition_met": 5, "excluded_original_wrong": 2,
                                          "killed": 2, "survived": 1, "escalated": 2, "mutation_score": 0.4})
        self.assertEqual(row["real_to_safe"], {"pairs": 4, "precondition_met": 3, "excluded_original_wrong": 1,
                                               "killed": 1, "survived": 1, "escalated": 1,
                                               "mutation_score": 0.3333})
        self.assertEqual(row["safe_to_real"], {"pairs": 3, "precondition_met": 2, "excluded_original_wrong": 1,
                                               "killed": 1, "survived": 0, "escalated": 1, "mutation_score": 0.5})
        outcomes = {p["case_id"]: p["outcome"] for p in row["pairs"]}
        self.assertEqual(outcomes, {"R1": "killed", "R2": "survived", "R3": "escalated",
                                    "R4": "excluded_original_wrong", "S1": "killed",
                                    "S2": "excluded_original_wrong", "S3": "escalated"})

    def test_no_pair_meeting_the_precondition_has_no_score(self):
        result = mutants.score_pairs(["R1"], {"R1": True},
                                     {"B": [{"case_id": "R1", "verdict": "false_positive"}]},
                                     {"B": [{"case_id": "R1", "verdict": "false_positive"}]})
        self.assertIsNone(result["configurations"]["B"]["overall"]["mutation_score"])


# --- a whole step 5 run, offline --------------------------------------------------------------------

class StepFiveRunTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.samples, self.bench = self.tmp / "samples", self.tmp / "BenchmarkJava"
        self.out, self.overlays = self.tmp / "experiments", self.tmp / "overlay"
        evidence = self.tmp / "evidence"
        (evidence / "old").mkdir(parents=True)
        (evidence / "old" / "selected_alerts.json").write_text(
            json.dumps({"alerts": [{"case_id": "BenchmarkTest00009"}]}), encoding="utf-8")
        build_fixture_set(self.bench, self.samples, evidence, {a["case_id"]: a for a in fixture_alerts()})
        files, _ = mutation_set.build(FIXTURES / "semgrep.json", ANSWER_KEY, self.bench, evidence,
                                      samples_dir=self.samples)
        eval_sets.write(files, self.samples)
        self.mutations = mutation_set.load_mutations(self.samples)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.multiple(
            config, SAMPLES_DIR=self.samples, EXPERIMENTS_OUT=self.out, ANSWER_KEY=ANSWER_KEY,
            BENCHMARK_ROOT=str(self.bench), MUTATION_OVERLAY_DIR=self.overlays))
        stack.enter_context(mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-v1-TEST",
                                                         "OPENROUTER_MODEL": "fixture-model"}))
        stack.enter_context(mock.patch.object(profiles, "missing_prerequisites", return_value=[]))
        stack.enter_context(mock.patch("triagebot.nodes.context.retrieval.KnowledgeBase", StubKnowledgeBase))
        self.git = stack.enter_context(mock.patch.object(experiments, "git_state", return_value=CLEAN))

    def run_cli(self, *args, answers=("y",), **kwargs):
        callers = ReadingCallers()
        result = capture(cli.experiment_run, "5", *args, answers=answers, caller_factory=callers,
                         benchmark_root=str(self.bench), **kwargs)
        return result, callers

    def test_step_5_runs_originals_then_mutants_and_scores_the_pairs(self):
        checkout = tree_bytes(self.bench)
        before, after = experiments.plan("5")
        self.assertEqual((before["source"], after["source"]), ("benchmark", "mutant"))
        self.assertEqual((before["labels"], after["labels"]), ("answer key", "flipped"))
        self.assertEqual(before["modes"], ["single", "council"])
        self.assertEqual((before["calls"], after["calls"]), (8, 8))      # 2 cases x (1 + 3)
        self.assertEqual(after["estimated_cost"], round(2 * (0.0043 + 0.0146), 4))

        (code, printed, errors, _), callers = self.run_cli()
        self.assertEqual((code, errors), (0, ""), printed)
        self.assertIn("overlay root per case", printed)
        self.assertEqual(callers.calls, 16)
        self.assertEqual(tree_bytes(self.bench), checkout)               # never written to
        self.assertTrue(all(GIVEAWAY not in prompt for prompt in callers.prompts))

        # Each side read the file it should: the original, then the mutant from its overlay.
        for name, key in (("5-before", "source_sha256"), ("5-after", "mutant_sha256")):
            records = [json.loads(line) for line in
                       (self.out / name / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual({r["case_id"]: r["source_sha256"] for r in records},
                             {c: e[key] for c, e in self.mutations.items()})
        manifests = {n: json.loads((self.out / n / "run_manifest.json").read_text(encoding="utf-8"))
                     for n in ("5-before", "5-after")}
        self.assertEqual(manifests["5-before"]["source"]["kind"], "benchmark")
        self.assertEqual((manifests["5-after"]["source"]["kind"], manifests["5-after"]["labels"]),
                         ("mutant", "flipped"))
        self.assertEqual({m["git"]["commit"] for m in manifests.values()}, {CLEAN["commit"]})

        # The mutants are scored against the flipped answers: a perfect reviewer is right on both.
        for name in ("5-before", "5-after"):
            rows = {r["configuration"]: r for r in json.loads(
                (self.out / name / "evaluation.json").read_text(encoding="utf-8"))["configurations"]}
            for config_name in ("B-single-agent", "C-council"):
                self.assertEqual(rows[config_name]["genuine_retained"] + rows[config_name]["fp_removed"], 2)
        score = json.loads((self.out / "5-after" / "mutation_score.json").read_text(encoding="utf-8"))
        self.assertTrue(score["same_commit"])
        for config_name in ("B-single-agent", "C-council"):
            overall = score["configurations"][config_name]["overall"]
            self.assertEqual((overall["killed"], overall["mutation_score"]), (2, 1.0))
            self.assertEqual(score["configurations"][config_name]["real_to_safe"]["killed"], 1)
            self.assertEqual(score["configurations"][config_name]["safe_to_real"]["killed"], 1)
        self.assertEqual(sorted(p.name for p in self.overlays.iterdir()), sorted(self.mutations))

        table = experiments.show_table("5")["mutation"]
        self.assertEqual(table["headers"][:4], ["Measure", "B All", "B real→safe", "B safe→real"])
        self.assertEqual(table["rows"][-1][1], "100.0%")
        code, shown, errors, _ = capture(cli.main, ["experiment", "show", "5"])
        self.assertEqual((code, errors), (0, ""))
        self.assertIn("Mutation score", shown)
        self.assertIn("flipped answers", shown)
        code, replayed, errors, _ = capture(cli.main, ["experiment", "replay", "5"])
        self.assertEqual((code, errors), (0, ""), replayed)
        self.assertEqual(replayed.count("matches"), 2)
        self.assertIn("mutation_score.json", replayed)
        code, listed, errors, _ = capture(cli.main, ["experiment", "list"])     # menu option 4
        self.assertRegex(listed, r"\n\s*5\s+Does the verdict follow the code\?\s+mutation\s+run")

    def test_both_sides_must_run_on_one_commit(self):
        dirty = {"commit": "a" * 40, "dirty": True, "dirty_paths": ["triagebot/config.py"]}
        self.git.return_value = dirty
        (code, _, errors, asked), callers = self.run_cli()
        self.assertEqual((code, asked, callers.calls), (1, 0, 0))
        self.assertIn("runs both sides on one commit: commit first", errors)
        self.assertFalse(self.out.exists())
        self.git.return_value = CLEAN
        (code, _, errors, _), _ = self.run_cli(side="before")
        self.assertEqual((code, errors), (0, ""))
        self.git.return_value = {"commit": "d" * 40, "dirty": False, "dirty_paths": []}
        (code, _, errors, asked), callers = self.run_cli(side="after")
        self.assertEqual((code, asked, callers.calls), (1, 0, 0))
        self.assertIn("5-before was run on cccccccccccc, not dddddddddddd", errors)
        self.assertIsNone(experiments.show_table("5")["mutation"])        # one side only: no score yet


if __name__ == "__main__":
    unittest.main()
