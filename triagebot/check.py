"""Setup check: is this machine ready to run TriageBot?

Run with `python -m triagebot check`; the menu runs it on start and before
option 1. Standard library only, so it still reports a missing `rich`.

Each check is a Check(name, status, detail, fix, required):
  OK       ready
  MISSING  required for option 1; `fix` is the exact command to run
  WARNING  optional (a re-scan needs Semgrep) or worth knowing (benchmark
           at a different commit than the recorded evidence)
The benchmark-commit check is left out when git is unavailable or the
benchmark is missing.
"""

from dataclasses import dataclass
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys

from triagebot import config

OK, MISSING, WARNING = "OK", "MISSING", "WARNING"
MIN_PYTHON = (3, 10)
ANSWER_KEY_NAME = "expectedresults-1.2.csv"
TESTCODE = Path("src/main/java/org/owasp/benchmark/testcode")


@dataclass
class Check:
    name: str
    status: str
    detail: str
    fix: str = ""
    required: bool = True


def benchmark_dir() -> Path:
    """Where the benchmark is, or should be cloned to."""
    return Path(config.BENCHMARK_ROOT or config.BENCHMARK_CLONE_DIR)


def _rel(path) -> str:
    """Path relative to the repository root when inside it, with forward slashes."""
    path = Path(path)
    try:
        return path.resolve().relative_to(config._REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def clone_commands(target=None) -> list[list[str]]:
    target = str(target or benchmark_dir())
    return [["git", "clone", config.BENCHMARK_URL, target],
            ["git", "-C", target, "checkout", config.BENCHMARK_COMMIT]]


def _clone_fix(target) -> str:
    return "\n".join(" ".join(command) for command in clone_commands(_rel(target)))


def semgrep_exe() -> Path | None:
    """Semgrep next to this Python (Scripts\\ on Windows, bin/ elsewhere), then on PATH."""
    name = "semgrep.exe" if os.name == "nt" else "semgrep"
    here = Path(sys.executable).parent
    for candidate in (here / name, here / ("Scripts" if os.name == "nt" else "bin") / name):
        if candidate.is_file():
            return candidate
    found = shutil.which("semgrep")
    return Path(found) if found else None


def check_python(version=None) -> Check:
    version = tuple(version or sys.version_info[:3])
    text = ".".join(map(str, version))
    if version[:2] >= MIN_PYTHON:
        return Check("Python version", OK, f"{text} (3.10 or newer needed)")
    return Check("Python version", MISSING, f"{text}; 3.10 or newer needed",
                 "Install Python 3.10+ from https://www.python.org/downloads/, then recreate .venv")


def check_rich(find_spec=importlib.util.find_spec) -> Check:
    if find_spec("rich") is not None:
        return Check("rich installed", OK, "terminal output library")
    return Check("rich installed", MISSING, "not installed in this Python",
                 "pip install -r requirements.txt   (with .venv activated)")


def check_benchmark(root=None) -> Check:
    root = Path(root or benchmark_dir())
    missing = [part for part, ok in ((f"{TESTCODE.as_posix()}/", (root / TESTCODE).is_dir()),
                                     (ANSWER_KEY_NAME, (root / ANSWER_KEY_NAME).is_file())) if not ok]
    if not missing:
        return Check("OWASP Benchmark folder", OK, _rel(root))
    detail = f"{_rel(root)} not found" if not root.is_dir() else f"{_rel(root)}: missing {', '.join(missing)}"
    return Check("OWASP Benchmark folder", MISSING, detail, _clone_fix(root))


def check_commit(root=None, run=subprocess.run) -> Check | None:
    """None (left out) when git is unavailable or the folder is not a git checkout."""
    root = Path(root or benchmark_dir())
    try:
        done = run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    head = (done.stdout or "").strip()
    if done.returncode != 0 or not head:
        return None
    if head == config.BENCHMARK_COMMIT:
        return Check("Benchmark at pinned commit", OK, head[:12], required=False)
    return Check("Benchmark at pinned commit", WARNING,
                 f"at {head[:12]}, recorded evidence uses {config.BENCHMARK_COMMIT[:12]}",
                 f"git -C {_rel(root)} checkout {config.BENCHMARK_COMMIT}", required=False)


def check_scan(local=None, recorded=None) -> Check:
    path, source = config.effective_scan(local, recorded)
    if path.is_file():
        return Check("Semgrep scan available", OK, f"{source} ({_rel(path)})")
    return Check("Semgrep scan available", MISSING, f"neither {_rel(config.LOCAL_SCAN)} nor {_rel(path)} found",
                 f"git restore {_rel(path)}   (restores the recorded scan)")


def check_semgrep(find=semgrep_exe) -> Check:
    exe = find()
    if exe:
        return Check("Semgrep installed", OK, f"for re-scans ({exe.name})", required=False)
    return Check("Semgrep installed", WARNING, "not installed; needed for re-scans only",
                 "pip install -r requirements-scan.txt", required=False)


def run_checks(run=subprocess.run) -> list[Check]:
    """Every check, in display order (the commit check only when it applies)."""
    bench = check_benchmark()
    checks = [check_python(), check_rich(), bench]
    if bench.status == OK:
        commit = check_commit(run=run)
        if commit:
            checks.append(commit)
    return checks + [check_scan(), check_semgrep()]


def blocking(checks) -> list[Check]:
    """Required checks that are MISSING (option 1 refuses to run while any are)."""
    return [c for c in checks if c.required and c.status == MISSING]


def benchmark_missing(checks) -> bool:
    return any(c.name == "OWASP Benchmark folder" and c.status == MISSING for c in checks)


def print_plain(checks=None, out=sys.stdout) -> int:
    """Plain-text report for when rich itself is missing; exit code 1 if anything blocks."""
    checks = run_checks() if checks is None else checks
    print("TriageBot setup check", file=out)
    for c in checks:
        print(f"  {c.status:<8} {c.name}: {c.detail}", file=out)
        for line in c.fix.splitlines():
            print(f"           fix: {line}", file=out)
    return 1 if blocking(checks) else 0
