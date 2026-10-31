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

# "map": the curated CWE -> cheat-sheet gate (the default until the dev-split
#        measurement is reviewed). "semantic": embed the MITRE text for the
#        alert's CWE and rank every cheat-sheet chunk by cosine similarity.
RETRIEVAL_MODE = "map"
SEMANTIC_MIN_SCORE = 0.0       # cosine threshold; a placeholder until chosen on the dev split
SEMANTIC_QUERY_MAX_CHARS = 1000  # cap on the CWE text used as the query
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"   # local ONNX model via fastembed; no server
EMBEDDING_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "

# Official MITRE CWE catalogue, fetched once by `python -m triagebot.nodes.context.cwe_catalogue`.
# The pinned hash makes a changed or truncated download fail loudly; bump it with the URL.
CWE_CATALOGUE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_CATALOGUE_SHA256 = "bcda44c9abf61ff977f50c3c6649eea5a97a7b0626b0396c2c3ec4bfb973a3dc"  # CWE 5.0
_LOCAL_TMP = Path(__file__).resolve().parents[1] / "Context" / "tmp"   # git-ignored
CWE_CATALOGUE_DIR = _LOCAL_TMP / "cwe"
CWE_CATALOGUE_XML = CWE_CATALOGUE_DIR / "cwec_v5.0.xml"
KB_VECTOR_DB = _LOCAL_TMP / "kb_vectors.sqlite"   # derived from the KB; chunks added or changed are re-embedded

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
SOURCE_WINDOW_LINES = 60       # reaches benchmark helpers while keeping prompts bounded
                               # (decision 19 widened this to 100 on main; PR #14's
                               # 66-case experiment was measured at 60 together with the
                               # related-file context below, so 60 is kept until the team
                               # compares the two on the same cases)
SOURCE_RELATED_MAX_FILES = 4   # bounded direct/transitive project helper context
SOURCE_RELATED_MAX_LINES = 120
SOURCE_RELATED_MAX_LINES_PER_FILE = 60

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
FINAL_OUT = _REPO_ROOT / "Context" / "tmp" / "final"
FINAL_PARTITION = "test"
FINAL_SAMPLE_SIZES = {
    "CWE-22": 24,
    "CWE-78": 24,
    "CWE-79": 24,
    "CWE-89": 24,
    "CWE-90": 24,
}
COMPARISON_SAMPLE_SIZES = {
    "CWE-22": 16,
    "CWE-78": 16,
    "CWE-79": 16,
    "CWE-89": 16,
    "CWE-90": 2,  # only one unused safe and vulnerable test case remain
}

# --- review (model-call) limits ------------------------------------------
REVIEW_MAX_TOKENS = 900        # short JSON answer; headroom over the 700
                               # that the live run showed truncating chatty replies
REVIEW_TEMPERATURE = 0.0       # recorded runs must be reproducible

# --- durable council execution (opt-in; not the historical course checkpoint) ---
COUNCIL_DB = _REPO_ROOT / ".triagebot" / "checkpoints.sqlite"
COUNCIL_CHECKPOINT_SCHEMA = 2   # 2: adds the repair node's state; schema-1 runs cannot resume
