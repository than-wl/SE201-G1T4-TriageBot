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
SOURCE_WINDOW_LINES = 25       # alert lines +/- this many lines of context

# --- ingest, split and checkpoint sample -----------------------------------
SEMGREP_JSON = _REPO_ROOT / "Context" / "tmp" / "semgrep-owasp.json"
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
