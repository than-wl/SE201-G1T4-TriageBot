"""Frozen evaluation case sets for the experiments in EXPERIMENTS.md. EVALUATION SIDE.

    python -m triagebot.nodes.ingest.eval_sets build

builds, from the recorded Semgrep scan, the answer key and the fixed dev/test
split (seed 201, test fraction 0.5):

- pilot       dev   the checkpoint sample (100 CWE-89 cases, 50/50), checked
                    against archive/checkpoint/checkpoint-100/selected_alerts.json
- comparison  dev   CWE-22, 78, 79, 89 x 24 (12 real, 12 safe), no pilot case
- final-test  test  CWE-22, 78, 79, 89 x 30 (15 real, 15 safe), no retired case

and data/samples/retired_cases.json, every case an earlier run already used.

    python -m triagebot.nodes.ingest.eval_sets mutation

builds data/samples/mutation.json for step 5 (triagebot/nodes/ingest/mutation_set.py);
it also reads the Benchmark source of the dev-half candidates.

The answer key is used only to balance the draw. Each sample file holds only
NormalisedAlert fields (the shape of selected_alerts.json); its manifest holds
the rule, the seeds, the scan's fingerprint, the sample's own fingerprint and
aggregate counts per CWE, never a per-case label. No timestamps are written,
so building twice gives byte-identical files.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

from triagebot import config
from triagebot.nodes.ingest.answer_key import load_answer_key
from triagebot.nodes.ingest.normalise import load_semgrep, normalise
from triagebot.nodes.ingest.run import assert_llm_safe
from triagebot.nodes.ingest.split import assign_split, select_categories

SET_NAMES = ("pilot", "comparison", "final-test")
RETIRED_NAME = "retired_cases.json"
RETIRED_REASON = ("Used by an earlier run (checkpoint, original final 120, 66-case comparison, "
                  "fresh 120, or the OpenRouter smoke test); kept as a record, never used for a new claim.")
SELECTION_RULE = ("one CWE-matching Semgrep alert per case (lowest start_line, then rule_id); "
                  "cases drawn with the sample seed, balanced by label on the evaluation side")


class EvalSetError(ValueError):
    """A frozen set cannot be built as specified (fails loudly, writes nothing)."""


def default_rules() -> list[dict]:
    """The three sets, in build order (a set may exclude the sets before it)."""
    cwes = config.EVAL_SET_CWES
    return [
        {"name": "pilot", "partition": "dev",
         "sizes": {config.SAMPLE_CWE: config.SAMPLE_SIZE}, "exclude": [],
         "purpose": "exploration: the checkpoint sample; read failures and try ideas here"},
        {"name": "comparison", "partition": "dev",
         "sizes": {cwe: config.EVAL_COMPARISON_PER_CWE for cwe in cwes}, "exclude": ["pilot"],
         "purpose": "frozen: measured for steps 1 to 4, never tuned on"},
        {"name": "final-test", "partition": "test",
         "sizes": {cwe: config.EVAL_FINAL_TEST_PER_CWE for cwe in cwes}, "exclude": ["retired"],
         "purpose": "held out: run once, after the code freeze (step 6)"},
    ]


# --- fingerprints and file text ---------------------------------------------

def lf_sha256(raw: bytes) -> str:
    """SHA-256 of the bytes with CRLF turned into LF.

    Git may check text files out with CRLF on Windows; hashing the LF form gives
    the same fingerprint on every OS.
    """
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def file_sha256(path) -> str:
    return lf_sha256(Path(path).read_bytes())


def to_text(value) -> str:
    """The exact text written: two-space JSON, LF line endings, final newline."""
    return json.dumps(value, indent=2) + "\n"


def repo_path(path) -> str:
    """Repository-relative POSIX path, or the bare file name for a file outside it."""
    path = Path(path).resolve()
    try:
        return path.relative_to(config._REPO_ROOT).as_posix()
    except ValueError:
        return path.name


# --- retired cases --------------------------------------------------------------

def _case_ids(path) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data.get("alerts", data.get("cases")) if isinstance(data, dict) else data
    return {item["case_id"] if isinstance(item, dict) else item for item in items}


def _evidence_dirs(evidence_dir) -> list[Path]:
    """One folder or several (default: the archived evidence, config.RETIRED_EVIDENCE_DIRS)."""
    if evidence_dir is None:
        evidence_dir = config.RETIRED_EVIDENCE_DIRS
    if isinstance(evidence_dir, (str, Path)):
        evidence_dir = [evidence_dir]
    return [Path(d) for d in evidence_dir]


def retired_cases(evidence_dir) -> dict:
    """Every case in a selected_alerts file under the evidence folder(s), plus the fresh-120 audit list.

    Each file is named relative to the folder it was found in; the archive keeps
    the names the files had when they all sat under evidence/.
    """
    dirs = _evidence_dirs(evidence_dir)
    found = []
    for root in dirs:
        found += [(path.relative_to(root).as_posix(), path) for path in root.rglob("*selected_alerts.json")]
    sources = {name: _case_ids(path) for name, path in sorted(found)}
    for root in dirs:
        audit = root / "fresh-120" / "prior_case_audit.json"
        if audit.is_file():
            sources[audit.relative_to(root).as_posix()] = set(
                json.loads(audit.read_text(encoding="utf-8"))["prior_case_ids"])
    if not sources:
        raise EvalSetError("no earlier samples found under "
                           + ", ".join(repo_path(d) for d in dirs))
    union = sorted(set().union(*sources.values()))
    return {
        "reason": RETIRED_REASON,
        "count": len(union),
        "sources": {name: len(ids) for name, ids in sources.items()},
        "case_ids": union,
    }


# --- build ----------------------------------------------------------------------

def _composition(sample, key, summaries):
    rows = {}
    for cwe, summary in summaries.items():
        chosen = [a["case_id"] for a in sample if key[a["case_id"]]["cwe"] == cwe]
        rows[cwe] = {
            "requested": summary["requested"], "selected": summary["selected"],
            "real": sum(key[c]["vulnerable"] for c in chosen),
            "safe": sum(not key[c]["vulnerable"] for c in chosen),
            "eligible_real": summary["eligible_vulnerable"],
            "eligible_safe": summary["eligible_safe"],
        }
    return rows


def build(semgrep_path=None, answer_key_path=None, evidence_dir=None, pilot_reference=None,
          rules=None, samples_dir=None) -> dict[str, str]:
    """Return {file name: exact LF text} for every set, its manifest and the retired list.

    pilot_reference: a selected_alerts.json whose case list the pilot must equal
    (default: the checkpoint evidence); pass False to skip that check.
    Raises EvalSetError on a short set, a pilot mismatch or a retired overlap.
    """
    semgrep_path = Path(semgrep_path or config.RECORDED_SCAN)
    answer_key_path = Path(answer_key_path or config.ANSWER_KEY or "")
    evidence_dir = _evidence_dirs(evidence_dir)
    samples_dir = Path(samples_dir or config.SAMPLES_DIR)
    if pilot_reference is None:
        pilot_reference = config.CHECKPOINT_EVIDENCE_SAMPLE
    rules = rules or default_rules()
    if not answer_key_path.is_file():
        raise EvalSetError("answer key not found; clone the OWASP Benchmark "
                           "(python -m triagebot check) or pass --answer-key")

    raw, scan_date = load_semgrep(semgrep_path)
    alerts, _ = normalise(raw, config.recorded_scan_date(semgrep_path) or scan_date)
    key = load_answer_key(answer_key_path)
    split = assign_split(key, config.SPLIT_SEED, config.TEST_FRACTION)
    retired = retired_cases(evidence_dir)
    retired_ids = set(retired["case_ids"])

    files = {RETIRED_NAME: to_text(retired)}
    chosen = {"retired": retired_ids}
    for rule in rules:
        name = rule["name"]
        excluded = set().union(*(chosen[other] for other in rule["exclude"])) if rule["exclude"] else set()
        sample, summaries = select_categories(
            alerts, key, split, rule["sizes"], config.SPLIT_SEED,
            partition=rule["partition"], exclude_case_ids=excluded)
        assert_llm_safe(sample)
        ids = [a["case_id"] for a in sample]
        short = {cwe: s["shortfall"] for cwe, s in summaries.items() if s["shortfall"]}
        if short:
            raise EvalSetError(f"{name}: not enough eligible cases {short}")
        if name == "pilot" and pilot_reference:
            reference = sorted(_case_ids(pilot_reference))
            if ids != reference:
                raise EvalSetError(
                    f"pilot does not equal {repo_path(pilot_reference)}: "
                    f"{len(set(ids) - set(reference))} extra, {len(set(reference) - set(ids))} missing")
        overlap = len(set(ids) & retired_ids)
        if name == "final-test" and overlap:
            raise EvalSetError(f"final-test overlaps {overlap} retired case(s)")
        if name == "comparison" and overlap:
            # Today the only retired dev cases are the pilot's, which are excluded.
            raise EvalSetError(f"comparison overlaps {overlap} retired case(s) outside the pilot")
        chosen[name] = set(ids)

        selection = {
            "set": name, "rule": SELECTION_RULE, "partition": rule["partition"],
            "split_seed": config.SPLIT_SEED, "test_fraction": config.TEST_FRACTION,
            "sample_seed": config.SPLIT_SEED, "categories": dict(sorted(rule["sizes"].items())),
            "selected": len(sample),
        }
        sample_text = to_text({"selection": selection, "alerts": sample})
        files[f"{name}.json"] = sample_text
        files[f"{name}.manifest.json"] = to_text({
            "set": name,
            "purpose": rule["purpose"],
            "rule": SELECTION_RULE,
            "partition": rule["partition"],
            "split_seed": config.SPLIT_SEED,
            "test_fraction": config.TEST_FRACTION,
            "sample_seed": config.SPLIT_SEED,
            "excludes": {"sets": list(rule["exclude"]), "cases": len(excluded)},
            "overlap_with_retired": overlap,
            "scan": {"file": repo_path(semgrep_path), "sha256": file_sha256(semgrep_path)},
            "answer_key_sha256": file_sha256(answer_key_path),
            "sample": {"file": f"{repo_path(samples_dir)}/{name}.json",
                       "sha256": lf_sha256(sample_text.encode("utf-8"))},
            "cases": len(sample),
            "composition": _composition(sample, key, summaries),
            "fingerprint_note": "SHA-256 of the file with LF line endings",
        })
    return files


def write(files: dict[str, str], out_dir) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in files.items():
        target = out / name
        with target.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        written.append(target)
    return written


# --- reading a set (model side) --------------------------------------------------

def load_set(name, samples_dir=None) -> tuple[list[dict], dict]:
    """(label-free alerts, manifest) for a frozen set; raises if its fingerprint changed."""
    samples_dir = Path(samples_dir or config.SAMPLES_DIR)
    sample, manifest = samples_dir / f"{name}.json", samples_dir / f"{name}.manifest.json"
    if not sample.is_file() or not manifest.is_file():
        raise EvalSetError(f"case set {name!r} not found in {repo_path(samples_dir)}; "
                           "run: python -m triagebot.nodes.ingest.eval_sets build")
    meta = json.loads(manifest.read_text(encoding="utf-8"))
    if file_sha256(sample) != meta["sample"]["sha256"]:
        raise EvalSetError(f"case set {name!r} no longer matches its manifest fingerprint")
    alerts = json.loads(sample.read_text(encoding="utf-8"))["alerts"]
    assert_llm_safe(alerts)
    return alerts, meta


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triagebot.nodes.ingest.eval_sets",
                                     description="Build the frozen experiment case sets.")
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="build data/samples/ (pilot, comparison, final-test, retired)")
    b.add_argument("--semgrep", type=Path, default=config.RECORDED_SCAN)
    b.add_argument("--answer-key", type=Path, default=config.ANSWER_KEY)
    b.add_argument("--evidence", type=Path, nargs="+", default=list(config.RETIRED_EVIDENCE_DIRS),
                   help="folder(s) of earlier samples for the retired list (default: archive/checkpoint archive/evidence)")
    b.add_argument("--out", type=Path, default=config.SAMPLES_DIR)
    m = sub.add_parser("mutation", help="build data/samples/mutation.json for step 6, the mutation test "
                                        "(needs the Benchmark source; reads the pilot and comparison sets)")
    m.add_argument("--semgrep", type=Path, default=config.RECORDED_SCAN)
    m.add_argument("--answer-key", type=Path, default=config.ANSWER_KEY)
    m.add_argument("--benchmark", type=Path, default=config.BENCHMARK_ROOT,
                   help="the OWASP Benchmark checkout (default BENCHMARK_ROOT); only read")
    m.add_argument("--evidence", type=Path, nargs="+", default=list(config.RETIRED_EVIDENCE_DIRS),
                   help="folder(s) of earlier samples for the retired list (default: archive/checkpoint archive/evidence)")
    m.add_argument("--out", type=Path, default=config.SAMPLES_DIR)
    args = parser.parse_args(argv)
    if args.command == "mutation":
        return _main_mutation(args)
    try:
        files = build(args.semgrep, args.answer_key, args.evidence, samples_dir=args.out)
    except (EvalSetError, OSError, KeyError, json.JSONDecodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    write(files, args.out)
    for name in SET_NAMES:
        manifest = json.loads(files[f"{name}.manifest.json"])
        parts = ", ".join(f"{cwe} {row['real']}+{row['safe']}"
                          for cwe, row in manifest["composition"].items())
        print(f"{name:<11} {manifest['cases']:>4} cases  sha256 {manifest['sample']['sha256'][:12]}  ({parts})")
    retired = json.loads(files[RETIRED_NAME])
    print(f"{'retired':<11} {retired['count']:>4} cases")
    print(f"Written to {repo_path(args.out)}/")
    return 0


def _main_mutation(args) -> int:
    """`mutation`: build and write mutation.json and its manifest (step 5)."""
    from triagebot.nodes.ingest import mutation_set

    try:
        files, report = mutation_set.build(args.semgrep, args.answer_key, args.benchmark,
                                           args.evidence, samples_dir=args.out)
    except (EvalSetError, mutation_set.MutationError, OSError, KeyError,
            UnicodeDecodeError, json.JSONDecodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    write(files, args.out)
    manifest = json.loads(files[f"{mutation_set.NAME}.manifest.json"])
    print(f"{'Type':<7} {'screened':>8}  {'eligible real->safe':>19}  {'eligible safe->real':>19}  selected")
    for cwe, row in manifest["composition"].items():
        print(f"{cwe:<7} {row['screened']:>8}  {row['eligible_real_to_safe']:>19}  "
              f"{row['eligible_safe_to_real']:>19}  {row['real_to_safe']}+{row['safe_to_real']}"
              + (f"  (short by {row['shortfall']})" if row["shortfall"] else ""))
    for cwe, chosen in report["selected"].items():
        for direction, ids in chosen.items():
            print(f"  {cwe} {direction.replace('_to_', ' -> ').replace('_', ' ')}: {', '.join(ids)}")
    print(f"{mutation_set.NAME:<11} {manifest['cases']:>4} cases  sha256 {manifest['sample']['sha256'][:12]}")
    print(f"Written to {repo_path(args.out)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
