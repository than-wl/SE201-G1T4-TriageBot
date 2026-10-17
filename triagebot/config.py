"""Single place for runtime constants: model slugs, budget caps, paths.

No other module may hardcode these values; they are read from here
(and, where appropriate, from environment variables).
"""

from pathlib import Path

# --- KB / retrieval -----------------------------------------------------
KB_DIR = Path(__file__).resolve().parent / "nodes" / "context" / "kb"
RETRIEVAL_TOP_K = 6            # guidance chunks returned per payload
GUIDANCE_MAX_CHARS = 4000      # ~1000-token guidance budget per payload
