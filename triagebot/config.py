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
# Local benchmark checkout (not committed); unset -> payload build raises.
BENCHMARK_ROOT = os.environ.get("BENCHMARK_ROOT")
SOURCE_WINDOW_LINES = 25       # alert lines +/- this many lines of context

# --- review (model-call) limits ------------------------------------------
REVIEW_MAX_TOKENS = 900        # short JSON answer; headroom over the 700
                               # that the live run showed truncating chatty replies
REVIEW_TEMPERATURE = 0.0       # recorded runs must be reproducible
