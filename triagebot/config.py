"""Single place for runtime constants: model slugs, budget caps, paths.

No other module may hardcode these values; they are read from here
(and, where appropriate, from environment variables).
"""

import os
from pathlib import Path

# --- KB / retrieval -----------------------------------------------------
KB_DIR = Path(__file__).resolve().parent / "nodes" / "context" / "kb"
RETRIEVAL_TOP_K = 6            # guidance chunks returned per payload
GUIDANCE_MAX_CHARS = 4000      # ~1000-token guidance budget per payload

# --- source context -----------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _benchmark_root(environ=os.environ, repo_root=_REPO_ROOT):
    # A non-empty env var wins; else Context/tmp/BenchmarkJava if cloned; else None.
    if environ.get("BENCHMARK_ROOT"):
        return environ["BENCHMARK_ROOT"]
    local = Path(repo_root) / "Context" / "tmp" / "BenchmarkJava"
    return str(local) if local.is_dir() else None


# Local benchmark checkout (not committed); None -> payload build raises.
BENCHMARK_ROOT = _benchmark_root()
SOURCE_WINDOW_LINES = 100      # alert lines +/- this many lines of context
                               # (25 cut helper methods off mid-body in the
                               # recorded run; 100 keeps whole methods)

BENCHMARK_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
BENCHMARK_COMMIT = "8b67a88d73b2594570fc21150705283de884620b"   # pinned for all recorded evidence
BENCHMARK_CLONE_DIR = _REPO_ROOT / "Context" / "tmp" / "BenchmarkJava"

# --- Semgrep scan ----------------------------------------------------------
# The committed scan everyone scores (data/semgrep/README.md), and a user's
# own re-scan (git-ignored). A local re-scan, when present, takes precedence.
RECORDED_SCAN = _REPO_ROOT / "data" / "semgrep" / "semgrep-owasp-p-java-1.178.0.json"
RECORDED_SCAN_DATE = "2026-10-17T20:11:28+00:00"   # when it ran; the file's mtime is checkout time
LOCAL_SCAN = _REPO_ROOT / "Context" / "tmp" / "semgrep-owasp.json"
RECORDED, LOCAL = "recorded scan", "local re-scan"


def _same_file(a, b) -> bool:
    return Path(a).resolve() == Path(b).resolve()


def effective_scan(local=None, recorded=None) -> tuple[Path, str]:
    """(path, source): the local re-scan if it exists, else the recorded scan."""
    local, recorded = Path(local or LOCAL_SCAN), Path(recorded or RECORDED_SCAN)
    return (local, LOCAL) if local.is_file() else (recorded, RECORDED)


def scan_source(path) -> str:
    """How the screen names a scan file: recorded, local re-scan, or the file name."""
    if _same_file(path, RECORDED_SCAN):
        return RECORDED
    if _same_file(path, LOCAL_SCAN):
        return LOCAL
    return f"scan file {Path(path).name}"


def recorded_scan_date(path) -> str | None:
    """RECORDED_SCAN_DATE for the recorded scan, else None (use the file's mtime)."""
    return RECORDED_SCAN_DATE if _same_file(path, RECORDED_SCAN) else None


# --- ingest, split and checkpoint sample -----------------------------------
CHECKPOINT_OUT = _REPO_ROOT / "Context" / "tmp" / "checkpoint"
# Answer key: EVALUATION SIDE ONLY (never reaches a payload or prompt).
ANSWER_KEY = (Path(BENCHMARK_ROOT) / "expectedresults-1.2.csv"
              if BENCHMARK_ROOT else None)
SPLIT_SEED = 201
TEST_FRACTION = 0.5            # share of each (category, label) stratum held out
SAMPLE_SIZE = 100              # checkpoint sample, drawn from the dev split
SAMPLE_CWE = "CWE-89"

# --- review (model-call) limits ------------------------------------------
REVIEW_MAX_TOKENS = 900        # short JSON answer; headroom over the 700
                               # that the live run showed truncating chatty replies
REVIEW_TEMPERATURE = 0.0       # recorded runs must be reproducible
