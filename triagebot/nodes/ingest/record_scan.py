"""One-off: turn a local Semgrep scan into the committed recorded scan.

Semgrep stores each path as it was given on the command line: absolute
(user name, folders) or relative to wherever the scan ran (for example
"Context\\tmp\\BenchmarkJava\\src\\main\\java\\..."). This tool rewrites ONLY
those path strings so they are relative to the benchmark root
("src/main/java/..." with forward slashes); every other field, value and
ordering is left untouched. A path embedded in a longer string (Semgrep's
fixpoint-timeout messages) has just the path part rewritten.

Usage, from the repository root:
    python -m triagebot.nodes.ingest.record_scan [--in PATH] [--out PATH]

Defaults: --in config.LOCAL_SCAN, --out config.RECORDED_SCAN. Exits with
code 1 if any absolute path is left afterwards, so nothing machine-specific
is committed by accident. See data/semgrep/README.md.
"""

import argparse
import json
from pathlib import Path
import re
import sys

from triagebot import config

# A path token (absolute: drive letter, UNC or "/"; or relative) up to and
# including the benchmark source tree; group 1 is the part from
# "src/main/java/" onward. A token starts at the beginning of the string or
# after whitespace, a quote or "(".
_BENCHMARK_PATH = re.compile(
    r"(?<![^\s\"'(])(?:[A-Za-z]:[\\/]|\\\\|/)?(?:[^\s\"'<>|*?\\/]+[\\/])*?"
    r"(src[\\/]main[\\/]java[\\/][^\s\"'<>|*?:]*)")
# Any absolute path left over (checked after rewriting).
_ABSOLUTE_PATH = re.compile(r"(?:\b[A-Za-z]:\\|\\\\[^\\\s]|(?:^|\s)/(?:Users|home)/)")


def relative_path(text: str) -> str:
    """text with each benchmark path made relative to the benchmark root."""
    return _BENCHMARK_PATH.sub(lambda m: m.group(1).replace("\\", "/"), text)


def normalise_paths(value):
    """A copy of the Semgrep JSON value with only benchmark paths rewritten."""
    if isinstance(value, dict):
        return {key: normalise_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalise_paths(item) for item in value]
    if isinstance(value, str):
        return relative_path(value)
    return value


def count_rewritten(before, after) -> int:
    """Number of strings that differ between two same-shaped JSON values."""
    if isinstance(before, dict):
        return sum(count_rewritten(before[key], after[key]) for key in before)
    if isinstance(before, list):
        return sum(count_rewritten(a, b) for a, b in zip(before, after))
    return int(before != after)


def leftover_absolute_paths(value) -> list[str]:
    """Every string (or key) that still looks like an absolute path."""
    found = []

    def walk(item):
        if isinstance(item, dict):
            for key, child in item.items():
                walk(key)
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
        elif isinstance(item, str) and _ABSOLUTE_PATH.search(item):
            found.append(item)

    walk(value)
    return found


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Make a Semgrep scan's paths relative to the benchmark root.")
    parser.add_argument("--in", dest="source", default=str(config.LOCAL_SCAN), help="local Semgrep JSON")
    parser.add_argument("--out", default=str(config.RECORDED_SCAN), help="recorded scan to write")
    args = parser.parse_args(argv)

    data = json.loads(Path(args.source).read_text(encoding="utf-8"))
    recorded = normalise_paths(data)
    leftover = leftover_absolute_paths(recorded)
    if leftover:
        print(f"Not written: {len(leftover)} absolute path(s) left, e.g. {leftover[0][:120]}", file=sys.stderr)
        return 1
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # Same layout as Semgrep's own --json output (one line, compact separators).
    out.write_text(json.dumps(recorded, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"Wrote {out} ({len(recorded.get('results', []))} findings; "
          f"{count_rewritten(data, recorded)} string(s) rewritten)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
