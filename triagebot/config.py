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

# "semantic" (the default, design decision 29): look up the alert's CWE in the MITRE
#        catalogue, attach its record, and rank the cheat-sheet chunks by similarity to it.
#        Needs two one-time, local prepare steps (README, Quick start); a normal run stops
#        and names both while either is missing.
# "map": the curated CWE -> cheat-sheet table (steps 1 to 3; the base, evidence and
#        worksheet profiles set it explicitly).
RETRIEVAL_MODE = "semantic"
# Used only when SEMANTIC_GROUNDING = "min_score" (the decision 21 set-up). It is NOT a
# relevance gate: at 0.0 every chunk passes, and cosine scores of relevant and irrelevant
# chunks overlap here, so no threshold separates them (decision 21, decision 28).
SEMANTIC_MIN_SCORE = 0.0
SEMANTIC_QUERY_MAX_CHARS = 1000  # cap on the CWE text used as the query

# The semantic set-up rules (EXPERIMENTS.md step 4, design decisions 28 and 29). Read at
# call time. The defaults are the improved set-up step 4 measured, the same as the
# "semantic" profile (triagebot/profiles.py). The decision 21 set-up (all five off) is
# profiles.SEMANTIC_SETUPS["original"]; anything that needs it sets it explicitly.
# Map mode ignores them.
SEMANTIC_QUERY_ALT_TERMS = True    # R1: add MITRE Alternate_Terms ("XSS", "path traversal") to the query
SEMANTIC_MITRE_GUIDANCE = True     # R2: attach the MITRE record (by CWE ID, never searched) as the first chunk
MITRE_GUIDANCE_MAX_CHARS = 1500    #     its cap; it shares GUIDANCE_MAX_CHARS with the OWASP chunks
SEMANTIC_KB_SCOPE = True           # R3: search only the sheets kb/scope.json keeps for KB_TARGET_PLATFORM
KB_TARGET_PLATFORM = "java"        #     platform of the code being scanned (the OWASP Benchmark is Java)
KB_SCOPE_FILE = KB_DIR / "scope.json"
SEMANTIC_MAX_CHUNK_CHARS = 1800    # R4: split chunks longer than this at load time; 0 = off (original)
SEMANTIC_GROUNDING = "mitre_record"  # R5: "mitre_record" (grounded iff the CWE has a valid MITRE record)
                                     #     or "min_score" (a chunk clears SEMANTIC_MIN_SCORE; the original)
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
# Step 5: one overlay root per mutant (a copy of the Benchmark source with only the mutated
# file replaced), built from data/samples/mutation.json before a run (triagebot/mutants.py).
MUTATION_OVERLAY_DIR = _LOCAL_TMP / "mutation-overlay"

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
# Related source: same-file methods the window calls, other project files it
# references, and scripts those files name. Off = the window only (profile "base").
SOURCE_RELATED_ENABLED = True
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
REVIEW_MAX_TOKENS = 2000       # the answer itself is ~400-600 tokens, but the model's
                               # hidden reasoning counts against this limit too: in the
                               # step 1 smoke test (8 Nov) a Skeptic call spent 746 of
                               # 900 tokens reasoning and its JSON was cut off. Only
                               # tokens actually generated are billed.
REVIEW_TEMPERATURE = 0.0       # recorded runs must be reproducible
# Reasoning worksheet: ask for the structured "analysis" object (and require it in
# the strict JSON schema), then repair a verdict that contradicts it. Read at call
# time, so a profile (triagebot/profiles.py) can switch it on. Off by default: the
# final version runs without it (design decision 27); the "worksheet" profile turns it on.
REVIEW_WORKSHEET_ENABLED = False

# --- experiments (EXPERIMENTS.md) ------------------------------------------
# The profile applied by profiles.use_profile(); None outside an experiment.
ACTIVE_PROFILE = None
SAMPLES_DIR = _REPO_ROOT / "data" / "samples"          # frozen case sets (committed)
EXPERIMENT_REGISTRY = _REPO_ROOT / "experiments" / "registry.json"
EXPERIMENTS_OUT = _REPO_ROOT / "evidence" / "experiments"
EVIDENCE_DIR = _REPO_ROOT / "evidence"
ARCHIVE_DIR = _REPO_ROOT / "archive"                  # superseded runs, kept as the record
# Folders whose earlier samples make up the retired list (data/samples/retired_cases.json).
# Each case file is named relative to its folder, as when they all sat under evidence/.
RETIRED_EVIDENCE_DIRS = (ARCHIVE_DIR / "checkpoint", ARCHIVE_DIR / "evidence")
CHECKPOINT_EVIDENCE_SAMPLE = ARCHIVE_DIR / "checkpoint" / "checkpoint-100" / "selected_alerts.json"
EVAL_SET_CWES = ("CWE-22", "CWE-78", "CWE-79", "CWE-89")
EVAL_COMPARISON_PER_CWE = 24   # 12 real + 12 safe per category, dev half
EVAL_FINAL_TEST_PER_CWE = 30   # 15 real + 15 safe per category, test half
# Planning estimates only (US$ per case, before consistency repairs); the
# real spend is read from each call's usage and saved in run_manifest.json.
EXPERIMENT_COST_PER_CASE = {"single": 0.004, "council": 0.016}
EXPERIMENT_CALLS_PER_CASE = {"single": 1, "council": 3}

# --- durable council execution (opt-in; not the historical course checkpoint) ---
COUNCIL_DB = _REPO_ROOT / ".triagebot" / "checkpoints.sqlite"
COUNCIL_CHECKPOINT_SCHEMA = 2   # 2: adds the repair node's state; schema-1 runs cannot resume
