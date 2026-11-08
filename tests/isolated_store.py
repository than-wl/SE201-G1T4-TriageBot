"""Keeps every test off the real knowledge-base vector store (Context/tmp/kb_vectors.sqlite).

Every test module imports this first. It points config.KB_VECTOR_DB at a file in a
fresh temporary folder (removed at exit), and sets TRIAGEBOT_TEST_VECTOR_DB so a
worker process started by a test does the same. On 8 Nov a test synced the real
store with a one-chunk fixture knowledge base and left it with 1 row (design
decision 30); with this, a test that reaches the default store gets a throwaway one.
A test that needs the store path patches it as before.
"""

import atexit
import os
from pathlib import Path
import shutil
import tempfile

from triagebot import config

REAL_STORE = Path(config.KB_VECTOR_DB)

if "TRIAGEBOT_TEST_VECTOR_DB" not in os.environ:
    _folder = tempfile.mkdtemp(prefix="triagebot-test-store-")
    atexit.register(shutil.rmtree, _folder, ignore_errors=True)
    os.environ["TRIAGEBOT_TEST_VECTOR_DB"] = str(Path(_folder) / "kb_vectors.sqlite")
TEST_STORE = Path(os.environ["TRIAGEBOT_TEST_VECTOR_DB"])
config.KB_VECTOR_DB = TEST_STORE
