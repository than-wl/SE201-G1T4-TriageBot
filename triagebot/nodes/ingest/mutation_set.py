"""The mutation set for step 5 of EXPERIMENTS.md ("Does the verdict follow the code?"). EVALUATION SIDE.

    python -m triagebot.nodes.ingest.eval_sets mutation

Many OWASP Benchmark cases decide their answer with one constant condition:

    bar = (7 * 42) - num > 200 ? "This should never happen" : param;

``num`` is a constant set a few lines above. If the condition is true, ``bar`` is
the constant (safe); if false, ``bar`` is the user input (vulnerable). Swapping
``>`` for ``<`` (same length, so no line number moves) flips which branch runs,
so the right verdict flips. That one character is the whole mutation.

A case is eligible when all of these hold:

- it is in the dev half and not in the pilot, the comparison set or the retired
  list (so never in the final test, which is the test half);
- its type is CWE-22, 78, 79 or 89 and it has a CWE-matching Semgrep alert in the
  recorded scan (the same alert rule as the other sets);
- its file (comments stripped) holds exactly one ternary of the form
  ``(<int> * <int>) <+|-> num > 200 ? "<string>" : <identifier>`` and exactly one
  ``int num = <int>;``, declared before it;
- the flip proof passes: evaluated in Python with the file's own constants, the
  condition really flips and is not tied at exactly 200;
- the condition decides the answer (checked against the answer key): a real case
  whose condition is false (the input flows through), or a safe case whose
  condition is true (the constant is used). Any other case is safe or vulnerable
  for some other reason, and flipping the branch would not flip the answer.

From the eligible cases, 3 per direction (real -> safe, safe -> real) per type are
drawn with the split seed (201): 24 pairs. A short stratum gives what exists and
the shortfall is reported; the rules are never widened.

Only the dev-half candidates' source files are read, after the split filter, so no
final-test case is ever opened. The answer key is used only to keep and balance
cases: mutation.json holds case IDs, the alert, the file, the line, the original and
mutated expression and the evaluated values, never a label. Its manifest holds the
rules, seeds, fingerprints and aggregate counts per type and direction. No
timestamps are written, so building twice gives byte-identical files.
"""

import random
import re
from pathlib import Path

from triagebot import config
from triagebot.nodes.context.payload import strip_comments

NAME = "mutation"
DIRECTIONS = ("real_to_safe", "safe_to_real")
PER_DIRECTION = 3
THRESHOLD = 200
FROM, TO = ">", "<"

# The ternary, with either comparison, so a file holding a mutated copy as well
# counts as two. Matched on comment-stripped text (line-aligned with the file).
TERNARY = re.compile(
    r'\(\s*(?P<a>\d+)\s*\*\s*(?P<b>\d+)\s*\)\s*(?P<op>[+-])\s*num\s*(?P<cmp>[<>])\s*'
    r'(?P<threshold>\d+)\s*\?\s*"(?P<constant>(?:[^"\\\r\n]|\\.)*)"\s*:\s*'
    r'(?P<input>[A-Za-z_$][\w$]*)')
NUM = re.compile(r'\bint\s+num\s*=\s*(?P<value>-?\d+)\s*;')

ELIGIBILITY_RULE = (
    "dev half, not in pilot, comparison or the retired list; CWE-22, 78, 79 or 89 with a "
    "CWE-matching Semgrep alert (lowest start_line, then rule_id); exactly one "
    "'(<int> * <int>) <+|-> num > 200 ? \"<string>\" : <identifier>' and exactly one "
    "'int num = <int>;' before it (comments stripped); the condition flips and is not tied at "
    "200; the condition decides the answer (real: false, input flows; safe: true, constant used)")
SELECTION_RULE = (f"{PER_DIRECTION} per direction (real -> safe, safe -> real) per type, drawn "
                  "with random.Random(seed) per (type, direction) from the sorted eligible case IDs")


class MutationError(ValueError):
    """A file does not hold the pattern, or its flip cannot be proved."""


# --- the pattern and its flip ----------------------------------------------------------

def find_pattern(text: str) -> dict:
    """The one constant ternary in a Java file, with its constants; raises MutationError.

    ``start``/``end`` are offsets of the expression and ``cmp_offset`` of its ``>``,
    valid in ``text`` itself (comment stripping keeps every offset).
    """
    clean = strip_comments(text)
    ternaries = list(TERNARY.finditer(clean))
    if len(ternaries) != 1:
        raise MutationError(f"{len(ternaries)} ternaries of the form (expected exactly one)")
    nums = list(NUM.finditer(clean))
    if len(nums) != 1:
        raise MutationError(f"{len(nums)} 'int num = <int>;' declarations (expected exactly one)")
    match, num = ternaries[0], nums[0]
    if match["cmp"] != FROM or int(match["threshold"]) != THRESHOLD:
        raise MutationError(f"the condition is 'num {match['cmp']} {match['threshold']}', "
                            f"not 'num {FROM} {THRESHOLD}'")
    if num.start() > match.start():
        raise MutationError("num is declared after the condition")
    if text[match.start():match.end()] != match.group(0):
        raise MutationError("a comment sits inside the expression")
    a, b, value = int(match["a"]), int(match["b"]), int(num["value"])
    return {
        "a": a, "b": b, "op": match["op"], "num": value, "threshold": THRESHOLD,
        "constant": match["constant"], "input": match["input"],
        "start": match.start(), "end": match.end(), "cmp_offset": match.start("cmp"),
        "line": clean.count("\n", 0, match.start()) + 1,
        "expression": match.group(0),
    }


def flip_proof(pattern: dict) -> dict:
    """Evaluate the condition before and after the swap; raises unless it really flips."""
    product = pattern["a"] * pattern["b"]
    value = product + pattern["num"] if pattern["op"] == "+" else product - pattern["num"]
    threshold = pattern["threshold"]
    if value == threshold:
        raise MutationError(f"tied at exactly {threshold}: neither '>' nor '<' holds, so the swap "
                            "flips nothing")
    original, mutated = value > threshold, value < threshold
    if original == mutated:            # unreachable once the tie is excluded; kept as the proof
        raise MutationError("the condition does not flip")
    branch = {True: "constant", False: "input"}
    return {"a": pattern["a"], "b": pattern["b"], "op": pattern["op"], "num": pattern["num"],
            "value": value, "threshold": threshold,
            "original_condition": original, "mutated_condition": mutated,
            "original_branch": branch[original], "mutated_branch": branch[mutated]}


def mutate(text: str, pattern: dict) -> str:
    """The file with only the expression's '>' turned into '<' (same length, same lines)."""
    offset = pattern["cmp_offset"]
    if text[offset] != FROM:
        raise MutationError(f"expected {FROM!r} at offset {offset}, found {text[offset]!r}")
    mutated = text[:offset] + TO + text[offset + 1:]
    assert len(mutated) == len(text) and mutated.count("\n") == text.count("\n")
    return mutated


def branch_decides(vulnerable: bool, original_condition: bool) -> bool:
    """True when the label matches the branch: real with the input flowing, safe with the constant."""
    return (vulnerable and not original_condition) or (not vulnerable and original_condition)


def direction(vulnerable: bool) -> str:
    return "real_to_safe" if vulnerable else "safe_to_real"


def describe(text: str) -> dict:
    """Pattern, proof and mutated text for one file; raises MutationError."""
    pattern = find_pattern(text)
    proof = flip_proof(pattern)
    mutated = mutate(text, pattern)
    expression = pattern["expression"]
    relative = pattern["cmp_offset"] - pattern["start"]
    return {"pattern": pattern, "proof": proof, "mutated_text": mutated,
            "original": expression,
            "mutated": expression[:relative] + TO + expression[relative + 1:]}


# --- building the set (needs the answer key and the dev-half source files) --------------------

def _read_source(root: Path, alert: dict) -> str:
    path = (root / alert["file"]).resolve()
    if not path.is_relative_to(root):
        raise MutationError(f"alert file escapes the benchmark root: {alert['file']}")
    return path.read_bytes().decode("utf-8")


def screen(candidates, key, split, benchmark_root) -> tuple[dict, dict]:
    """({direction: [mutation entries]}, {reason: count}) for one type's candidate alerts.

    Every candidate must be in the dev half; its source is read only then.
    """
    from triagebot.nodes.ingest.eval_sets import lf_sha256

    root = Path(benchmark_root).resolve()
    eligible = {d: [] for d in DIRECTIONS}
    rejected = {}
    for alert in candidates:
        case_id = alert["case_id"]
        if split.get(case_id) != "dev":
            raise MutationError(f"{case_id} is not in the dev half; its source is not opened")
        text = _read_source(root, alert)
        try:
            found = describe(text)
        except MutationError as error:
            rejected[str(error)] = rejected.get(str(error), 0) + 1
            continue
        vulnerable = key[case_id]["vulnerable"]
        if not branch_decides(vulnerable, found["proof"]["original_condition"]):
            reason = "label does not match the branch (the answer depends on something else)"
            rejected[reason] = rejected.get(reason, 0) + 1
            continue
        eligible[direction(vulnerable)].append({
            "case_id": case_id,
            "file": alert["file"],
            "alert": alert,
            "line": found["pattern"]["line"],
            "original": found["original"],
            "mutated": found["mutated"],
            "values": found["proof"],
            "source_sha256": lf_sha256(text.encode("utf-8")),
            "mutant_sha256": lf_sha256(found["mutated_text"].encode("utf-8")),
        })
    for entries in eligible.values():
        entries.sort(key=lambda e: e["case_id"])
    return eligible, dict(sorted(rejected.items()))


def select(eligible: dict, per_direction: int, seed: int) -> dict:
    """{direction: chosen entries}, drawn with a fresh random.Random(seed) per direction."""
    chosen = {}
    for name in DIRECTIONS:
        entries = eligible[name]
        population = sorted(e["case_id"] for e in entries)
        ids = sorted(random.Random(seed).sample(population, min(per_direction, len(population))))
        by_id = {e["case_id"]: e for e in entries}
        chosen[name] = [by_id[c] for c in ids]
    return chosen


def build(semgrep_path=None, answer_key_path=None, benchmark_root=None, evidence_dir=None,
          samples_dir=None, cwes=None, per_direction=PER_DIRECTION, seed=None) -> tuple[dict, dict]:
    """Return ({file name: exact LF text}, report) for mutation.json and its manifest.

    The pilot and comparison sets are read from ``samples_dir`` (their fingerprints
    are checked) and excluded with the retired list. ``report`` holds the eligible
    counts per type and direction and the chosen IDs, for printing; it is not written.
    """
    from triagebot.nodes.ingest import eval_sets
    from triagebot.nodes.ingest.answer_key import load_answer_key
    from triagebot.nodes.ingest.normalise import load_semgrep, normalise
    from triagebot.nodes.ingest.run import assert_llm_safe
    from triagebot.nodes.ingest.split import assign_split, select_sample

    semgrep_path = Path(semgrep_path or config.RECORDED_SCAN)
    answer_key_path = Path(answer_key_path or config.ANSWER_KEY or "")
    evidence_dir = Path(evidence_dir or config.EVIDENCE_DIR)
    samples_dir = Path(samples_dir or config.SAMPLES_DIR)
    cwes = tuple(cwes or config.EVAL_SET_CWES)
    seed = config.SPLIT_SEED if seed is None else seed
    if not answer_key_path.is_file():
        raise eval_sets.EvalSetError("answer key not found; clone the OWASP Benchmark "
                                     "(python -m triagebot check) or pass --answer-key")
    if not benchmark_root or not Path(benchmark_root).is_dir():
        raise eval_sets.EvalSetError("OWASP Benchmark source not found; set BENCHMARK_ROOT "
                                     "or pass --benchmark")

    raw, scan_date = load_semgrep(semgrep_path)
    alerts, _ = normalise(raw, config.recorded_scan_date(semgrep_path) or scan_date)
    key = load_answer_key(answer_key_path)
    split = assign_split(key, config.SPLIT_SEED, config.TEST_FRACTION)
    retired = set(eval_sets.retired_cases(evidence_dir)["case_ids"])
    used = {name: {a["case_id"] for a in eval_sets.load_set(name, samples_dir)[0]}
            for name in ("pilot", "comparison")}
    excluded = retired | used["pilot"] | used["comparison"]

    composition, chosen_all, report = {}, [], {"eligible": {}, "selected": {}}
    for cwe in cwes:
        # Every eligible alert of the type (a size larger than the population takes all).
        candidates, _ = select_sample(alerts, key, split, cwe, 2 * len(alerts) + 2, seed,
                                      partition="dev", exclude_case_ids=excluded)
        eligible, rejected = screen(candidates, key, split, benchmark_root)
        chosen = select(eligible, per_direction, seed)
        composition[cwe] = {
            "screened": len(candidates),
            "rejected": rejected,
            **{f"eligible_{d}": len(eligible[d]) for d in DIRECTIONS},
            "requested": per_direction * len(DIRECTIONS),
            **{d: len(chosen[d]) for d in DIRECTIONS},
            "selected": sum(len(chosen[d]) for d in DIRECTIONS),
            "shortfall": sum(max(0, per_direction - len(chosen[d])) for d in DIRECTIONS),
        }
        report["eligible"][cwe] = {d: [e["case_id"] for e in eligible[d]] for d in DIRECTIONS}
        report["selected"][cwe] = {d: [e["case_id"] for e in chosen[d]] for d in DIRECTIONS}
        chosen_all += [e for d in DIRECTIONS for e in chosen[d]]

    chosen_all.sort(key=lambda e: e["case_id"])
    sample_alerts = [e["alert"] for e in chosen_all]
    assert_llm_safe(sample_alerts)
    overlap = {name: len({e["case_id"] for e in chosen_all} & ids)
               for name, ids in (("retired", retired), *used.items())}
    if any(overlap.values()):
        raise eval_sets.EvalSetError(f"mutation set overlaps {overlap}")
    if any(split[e["case_id"]] != "dev" for e in chosen_all):
        raise eval_sets.EvalSetError("mutation set holds a case outside the dev half")

    selection = {
        "set": NAME, "rule": ELIGIBILITY_RULE, "selection": SELECTION_RULE, "partition": "dev",
        "split_seed": config.SPLIT_SEED, "test_fraction": config.TEST_FRACTION,
        "sample_seed": seed, "per_direction": per_direction, "categories": list(cwes),
        "mutation": {"from": f"num {FROM} {THRESHOLD}", "to": f"num {TO} {THRESHOLD}"},
        "selected": len(chosen_all),
    }
    sample_text = eval_sets.to_text({"selection": selection, "alerts": sample_alerts,
                                     "mutations": chosen_all})
    manifest = {
        "set": NAME,
        "purpose": "step 5: originals (before) and their one-character mutants (after); "
                   "the right verdict of each mutant is the flip of its original's",
        "rule": ELIGIBILITY_RULE,
        "selection": SELECTION_RULE,
        "mutation": selection["mutation"],
        "partition": "dev",
        "split_seed": config.SPLIT_SEED,
        "test_fraction": config.TEST_FRACTION,
        "sample_seed": seed,
        "excludes": {"sets": ["pilot", "comparison", "retired"], "cases": len(excluded)},
        "overlap_with_excluded": overlap,
        "scan": {"file": eval_sets.repo_path(semgrep_path), "sha256": eval_sets.file_sha256(semgrep_path)},
        "answer_key_sha256": eval_sets.file_sha256(answer_key_path),
        "benchmark_commit": config.BENCHMARK_COMMIT,
        "sample": {"file": f"{eval_sets.repo_path(samples_dir)}/{NAME}.json",
                   "sha256": eval_sets.lf_sha256(sample_text.encode("utf-8"))},
        "cases": len(chosen_all),
        "composition": composition,
        "fingerprint_note": "SHA-256 of the file with LF line endings; source_sha256 and "
                            "mutant_sha256 in the set are of the Java files with LF line endings",
    }
    files = {f"{NAME}.json": sample_text, f"{NAME}.manifest.json": eval_sets.to_text(manifest)}
    return files, report


def load_mutations(samples_dir=None) -> dict[str, dict]:
    """{case_id: mutation entry} from the frozen set (its fingerprint is checked)."""
    import json

    from triagebot.nodes.ingest import eval_sets

    samples_dir = Path(samples_dir or config.SAMPLES_DIR)
    eval_sets.load_set(NAME, samples_dir)                  # raises if missing or changed
    data = json.loads((samples_dir / f"{NAME}.json").read_text(encoding="utf-8"))
    return {entry["case_id"]: entry for entry in data["mutations"]}
