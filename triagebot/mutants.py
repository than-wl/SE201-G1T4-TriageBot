"""Step 5 (EXPERIMENTS.md): overlay roots for the mutants, and the mutation score.

Overlay roots. A mutant is run from its own root: a copy of the trees of the
Benchmark checkout that the evidence code reads (OVERLAY_TREES: the Java source,
which holds the case and every helper class, and src/main/resources, which holds
the scripts a helper names), with only the mutated file replaced. So related
source, helpers and resources resolve exactly as in a normal run, and the original
and its mutant are judged on the same evidence except the mutated line. The
checkout itself is only read: files are copied, never linked, so nothing written to
an overlay can reach it. Overlays are built under Context/tmp/mutation-overlay/
(git-ignored), from the frozen set, before the after side runs:

    python -m triagebot.mutants build      (about 18 MB per case)
    python -m triagebot.mutants clean

Mutation score (evaluation side, needs the answer key). A pair counts only if the
reviewer got the original right (the precondition). Then the mutant is

- killed:    its verdict is the flipped right answer;
- survived:  its verdict is unchanged;
- escalated: it was sent to a human (reported separately; not a kill).

mutation score = killed / pairs that meet the precondition, per configuration and
per direction (real -> safe, safe -> real). Pairs whose original was wrong are
counted as excluded.
"""

import argparse
import json
from pathlib import Path
import shutil
import sys

from triagebot import config
from triagebot.nodes.ingest import mutation_set
from triagebot.nodes.ingest.eval_sets import lf_sha256, repo_path

OVERLAY_TREES = ("src/main/java", "src/main/resources")
MARKER = ".overlay.json"
VERDICTS = ("true_positive", "false_positive", "human_review")
OUTCOMES = ("killed", "survived", "escalated")


class OverlayError(ValueError):
    """An overlay root cannot be built or no longer matches the set."""


# --- overlay roots ---------------------------------------------------------------------------

def overlay_dir() -> Path:
    return Path(config.MUTATION_OVERLAY_DIR)


def _check_apart(benchmark_root: Path, out_dir: Path) -> None:
    if out_dir.is_relative_to(benchmark_root) or benchmark_root.is_relative_to(out_dir):
        raise OverlayError(f"the overlay folder {out_dir} and the Benchmark checkout "
                           f"{benchmark_root} must not contain each other")


def _marker(entry) -> dict:
    return {"case_id": entry["case_id"], "file": entry["file"], "line": entry["line"],
            "source_sha256": entry["source_sha256"], "mutant_sha256": entry["mutant_sha256"],
            "trees": list(OVERLAY_TREES)}


def overlay_is_current(root, entry) -> bool:
    """True when ``root`` was built for this entry and its mutated file is intact."""
    root = Path(root)
    try:
        marker = json.loads((root / MARKER).read_text(encoding="utf-8"))
        mutant = (root / entry["file"]).read_bytes()
    except (OSError, json.JSONDecodeError):
        return False
    return marker == _marker(entry) and lf_sha256(mutant) == entry["mutant_sha256"]


def build_overlay(entry, benchmark_root, out_dir=None) -> Path:
    """(Re)build the overlay root for one mutation entry; return it.

    Copies OVERLAY_TREES from the checkout, then writes the mutant over the case's
    file. Raises OverlayError if the checkout's file differs from the one the set
    was built from.
    """
    benchmark_root = Path(benchmark_root).resolve()
    out_dir = Path(out_dir or overlay_dir()).resolve()
    _check_apart(benchmark_root, out_dir)
    source = (benchmark_root / entry["file"]).resolve()
    if not source.is_relative_to(benchmark_root) or not any(
            Path(entry["file"]).is_relative_to(tree) for tree in OVERLAY_TREES):
        raise OverlayError(f"{entry['case_id']}: {entry['file']} is outside {', '.join(OVERLAY_TREES)}")
    raw = source.read_bytes()
    if lf_sha256(raw) != entry["source_sha256"]:
        raise OverlayError(f"{entry['case_id']}: {entry['file']} in the checkout differs from the "
                           "file the mutation set was built from")
    text = raw.decode("utf-8")
    mutated = mutation_set.mutate(text, mutation_set.find_pattern(text))
    if lf_sha256(mutated.encode("utf-8")) != entry["mutant_sha256"]:
        raise OverlayError(f"{entry['case_id']}: the mutant does not match the set")

    root = out_dir / entry["case_id"]
    if root.exists():
        shutil.rmtree(root)
    for tree in OVERLAY_TREES:
        if (benchmark_root / tree).is_dir():
            shutil.copytree(benchmark_root / tree, root / tree)
    target = root / entry["file"]
    target.unlink()                     # a fresh file, never a write through to a copied one
    target.write_bytes(mutated.encode("utf-8"))
    with (root / MARKER).open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(_marker(entry), indent=2) + "\n")
    return root


def ensure_overlays(mutations, benchmark_root, out_dir=None, progress=None) -> dict[str, Path]:
    """{case_id: overlay root} for every entry, building the ones missing or out of date."""
    out_dir = Path(out_dir or overlay_dir())
    roots = {}
    for number, (case_id, entry) in enumerate(sorted(mutations.items()), 1):
        root = out_dir / case_id
        if not overlay_is_current(root, entry):
            build_overlay(entry, benchmark_root, out_dir)
            if progress:
                progress(number, len(mutations), case_id)
        roots[case_id] = root
    return roots


def clean(out_dir=None) -> int:
    """Remove every overlay root; return how many were removed."""
    out_dir = Path(out_dir or overlay_dir())
    if not out_dir.is_dir():
        return 0
    removed = 0
    for root in sorted(out_dir.iterdir()):
        if root.is_dir() and (root / MARKER).is_file():
            shutil.rmtree(root)
            removed += 1
    return removed


# --- the mutation score (evaluation side) -------------------------------------------------------

def _verdicts(results) -> dict[str, str]:
    """{case_id: verdict}; a missing or unreadable verdict counts as sent to a human."""
    out = {}
    for result in results:
        verdict = result.get("verdict")
        out[result["case_id"]] = verdict if verdict in VERDICTS else "human_review"
    return out


def score_pairs(case_ids, labels, before, after) -> dict:
    """The mutation score per configuration and direction.

    labels: {case_id: original is vulnerable} (the answer key); before/after:
    {configuration: [results]} for the originals and the mutants. Returns
    {"configurations": {name: {"overall": row, "real_to_safe": row, "safe_to_real": row,
    "pairs": [per-pair outcome]}}}; a row holds pairs, precondition_met,
    excluded_original_wrong, killed, survived, escalated and mutation_score.
    """
    out = {}
    for name in sorted(set(before) & set(after)):
        original, mutant = _verdicts(before[name]), _verdicts(after[name])
        rows = {key: dict.fromkeys(("pairs", "precondition_met", "excluded_original_wrong",
                                    *OUTCOMES), 0) for key in ("overall", *mutation_set.DIRECTIONS)}
        pairs = []
        for case_id in sorted(case_ids):
            right = "true_positive" if labels[case_id] else "false_positive"
            flipped = "false_positive" if labels[case_id] else "true_positive"
            direction = mutation_set.direction(labels[case_id])
            first = original.get(case_id, "human_review")
            second = mutant.get(case_id, "human_review")
            if first != right:
                outcome = "excluded_original_wrong"
            elif second == flipped:
                outcome = "killed"
            elif second == "human_review":
                outcome = "escalated"
            else:
                outcome = "survived"
            for key in ("overall", direction):
                rows[key]["pairs"] += 1
                rows[key][outcome] += 1
                rows[key]["precondition_met"] += outcome != "excluded_original_wrong"
            pairs.append({"case_id": case_id, "direction": direction, "original": first,
                          "mutant": second, "outcome": outcome})
        for row in rows.values():
            met = row["precondition_met"]
            row["mutation_score"] = round(row["killed"] / met, 4) if met else None
        out[name] = {**rows, "pairs": pairs}
    return {"note": "A pair counts only if the original was judged right; escalated is not a kill.",
            "configurations": out}


# --- command line ----------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m triagebot.mutants",
                                     description="Overlay roots for the step 6 mutants (the mutation test).")
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="build the overlay roots from data/samples/mutation.json")
    b.add_argument("--benchmark", type=Path, default=config.BENCHMARK_ROOT,
                   help="the OWASP Benchmark checkout (default BENCHMARK_ROOT); only read")
    sub.add_parser("clean", help="remove the overlay roots")
    args = parser.parse_args(argv)
    if args.command == "clean":
        print(f"Removed {clean()} overlay root(s) from {repo_path(overlay_dir())}/")
        return 0
    if not args.benchmark or not Path(args.benchmark).is_dir():
        print("Error: OWASP Benchmark source not found; set BENCHMARK_ROOT or pass --benchmark",
              file=sys.stderr)
        return 1
    try:
        roots = ensure_overlays(mutation_set.load_mutations(), args.benchmark,
                                progress=lambda n, total, case: print(f"  [{n}/{total}] {case}"))
    except (OverlayError, mutation_set.MutationError, ValueError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"{len(roots)} overlay roots ready in {repo_path(overlay_dir())}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
