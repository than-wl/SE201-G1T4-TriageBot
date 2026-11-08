"""Experiment profiles: one named group of settings per experiment step.

Each step in EXPERIMENTS.md changes one group of settings and keeps the rest.
A profile names that group, and use_profile() applies it to triagebot.config
for one run, then restores what was there before:

    with use_profile("evidence"):
        ...   # every payload, prompt and schema built here uses the profile

| Setting                              | base  | evidence | worksheet | semantic |
| ------------------------------------ | ----- | -------- | --------- | -------- |
| Source window, lines either side     | 25    | 60       | 60        | 60       |
| Related source                       | off   | on       | on        | on       |
| Reasoning worksheet + repair         | off   | off      | on        | off      |
| Guidance retrieval                   | map   | map      | map       | semantic |
| Semantic set-up (rules R1 to R5)     | -     | -        | -         | improved |

The semantic set-up is fixed before step 4 is measured (design decision 28). The
`semantic` profile turns on all five rules; the other profiles use map retrieval,
which ignores them. SEMANTIC_SETUPS names the two set-ups `--explain` compares:

| Switch                               | original (decision 21) | improved (`semantic`) |
| ------------------------------------ | ---------------------- | --------------------- |
| R1 SEMANTIC_QUERY_ALT_TERMS          | off                    | on                    |
| R2 SEMANTIC_MITRE_GUIDANCE           | off                    | on (cap 1,500 chars)  |
| R3 SEMANTIC_KB_SCOPE                 | off                    | on (platform java)    |
| R4 SEMANTIC_MAX_CHUNK_CHARS          | 0 (off)                | 1,800                 |
| R5 SEMANTIC_GROUNDING                | min_score              | mitre_record          |

The engineering fixes in ENGINEERING_FIXES are not switches: they stay on in
every profile. The settings are read at call time by the code that uses them
(source_context, prompts.report_contract, openrouter.report_schema,
execution.repair_if_inconsistent, retrieval.KnowledgeBase), so nothing has to be
re-imported. Build the KnowledgeBase inside the `with` block: it reads
RETRIEVAL_MODE when it is created.
"""

from contextlib import contextmanager
import hashlib
from pathlib import Path
import sqlite3

from triagebot import config

# The semantic set-up rules (R1 to R5) and their parameters. "original" is the
# decision 21 set-up (all off, the config defaults); "improved" is what the
# semantic profile runs.
SEMANTIC_SETUPS = {
    "original": {
        "SEMANTIC_QUERY_ALT_TERMS": False,
        "SEMANTIC_MITRE_GUIDANCE": False,
        "MITRE_GUIDANCE_MAX_CHARS": 1500,
        "SEMANTIC_KB_SCOPE": False,
        "KB_TARGET_PLATFORM": "java",
        "SEMANTIC_MAX_CHUNK_CHARS": 0,
        "SEMANTIC_GROUNDING": "min_score",
    },
    "improved": {
        "SEMANTIC_QUERY_ALT_TERMS": True,
        "SEMANTIC_MITRE_GUIDANCE": True,
        "MITRE_GUIDANCE_MAX_CHARS": 1500,
        "SEMANTIC_KB_SCOPE": True,
        "KB_TARGET_PLATFORM": "java",
        "SEMANTIC_MAX_CHUNK_CHARS": 1800,
        "SEMANTIC_GROUNDING": "mitre_record",
    },
}
SEMANTIC_SETTINGS = tuple(SEMANTIC_SETUPS["original"])

PROFILES = {
    "base": {
        "SOURCE_WINDOW_LINES": 25,
        "SOURCE_RELATED_ENABLED": False,
        "REVIEW_WORKSHEET_ENABLED": False,
        "RETRIEVAL_MODE": "map",
    },
    "evidence": {
        "SOURCE_WINDOW_LINES": 60,
        "SOURCE_RELATED_ENABLED": True,
        "REVIEW_WORKSHEET_ENABLED": False,
        "RETRIEVAL_MODE": "map",
    },
    "worksheet": {
        "SOURCE_WINDOW_LINES": 60,
        "SOURCE_RELATED_ENABLED": True,
        "REVIEW_WORKSHEET_ENABLED": True,
        "RETRIEVAL_MODE": "map",
    },
    "semantic": {          # builds on "evidence": the worksheet was dropped after step 3
        "SOURCE_WINDOW_LINES": 60,
        "SOURCE_RELATED_ENABLED": True,
        "REVIEW_WORKSHEET_ENABLED": False,
        "RETRIEVAL_MODE": "semantic",
        **SEMANTIC_SETUPS["improved"],      # decision 28: fixed before step 4 is measured
    },
}
SETTINGS = tuple(PROFILES["base"])          # the switches every profile sets, in table order
# Every switch any profile sets; use_profile() saves and restores all of them.
ALL_SETTINGS = tuple(dict.fromkeys(key for p in PROFILES.values() for key in p))
LABELS = {
    "SOURCE_WINDOW_LINES": "Source window, lines either side",
    "SOURCE_RELATED_ENABLED": "Related source (other files, called methods, referenced scripts)",
    "REVIEW_WORKSHEET_ENABLED": "Reasoning worksheet (analysis field) and consistency repair",
    "RETRIEVAL_MODE": "Guidance retrieval",
}
# On in every profile; recorded in each run manifest so a reader sees they were not varied.
ENGINEERING_FIXES = (
    "strict JSON schema output",
    "guidance-label normalisation in the validator",
    "LangGraph council (Analyst || Skeptic -> Chair)",
    "output token limit with room for hidden reasoning (2000)",
)

CATALOGUE_COMMAND = "python -m triagebot.nodes.context.cwe_catalogue"
VECTOR_STORE_COMMAND = "python -m triagebot.nodes.context.vector_store"


class ProfileError(RuntimeError):
    """A profile is unknown, or its prerequisites are missing (the message says how to fix it)."""


def get(name: str) -> dict:
    if name not in PROFILES:
        raise ProfileError(f"unknown profile {name!r}; choose from {', '.join(PROFILES)}")
    return dict(PROFILES[name])


def current_settings() -> dict:
    """The live value of every profile switch (whether or not a profile is active).

    The semantic set-up switches are included only while retrieval is semantic:
    map retrieval ignores them, so map provenance is unchanged by them.
    """
    names = SETTINGS + (SEMANTIC_SETTINGS if config.RETRIEVAL_MODE == "semantic" else ())
    return {name: getattr(config, name) for name in names}


def provenance() -> dict:
    """The active profile's name and settings, for run manifests and checkpoints."""
    return {"name": config.ACTIVE_PROFILE, "settings": current_settings()}


def _sha256(path) -> str | None:
    path = Path(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def retrieval_provenance(settings: dict) -> dict | None:
    """For a semantic run: the fixed retrieval parameters and the SHA-256 of kb/scope.json.

    The set-up switches themselves are in the profile settings. None for map runs.
    """
    if settings.get("RETRIEVAL_MODE") != "semantic":
        return None
    scope = Path(config.KB_SCOPE_FILE)
    try:
        scope_name = scope.resolve().relative_to(config._REPO_ROOT).as_posix()
    except ValueError:
        scope_name = str(scope)
    return {
        "embedding_model": config.EMBEDDING_MODEL,
        "cwe_catalogue_sha256": config.CWE_CATALOGUE_SHA256,
        "query_max_chars": config.SEMANTIC_QUERY_MAX_CHARS,
        "min_score": config.SEMANTIC_MIN_SCORE,
        "top_k": config.RETRIEVAL_TOP_K,
        "guidance_max_chars": config.GUIDANCE_MAX_CHARS,
        "kb_scope_file": scope_name,
        "kb_scope_sha256": _sha256(scope),
    }


def _vector_store_ready(path) -> bool:
    path = Path(path)
    if not path.is_file():
        return False
    try:
        conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            return conn.execute("SELECT count(*) FROM kb_chunks").fetchone()[0] > 0
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def missing_prerequisites(name: str) -> list[str]:
    """What must be prepared before a run under this profile (empty when ready)."""
    if get(name)["RETRIEVAL_MODE"] != "semantic":
        return []
    missing = []
    if not Path(config.CWE_CATALOGUE_XML).is_file():
        missing.append(f"the MITRE CWE catalogue is missing; prepare it with: {CATALOGUE_COMMAND}")
    if not _vector_store_ready(config.KB_VECTOR_DB):
        missing.append(f"the knowledge-base vector store is missing; prepare it with: "
                       f"{VECTOR_STORE_COMMAND}")
    return missing


def require_ready(name: str) -> None:
    missing = missing_prerequisites(name)
    if missing:
        raise ProfileError(f"profile {name!r} cannot run yet: " + "; ".join(missing))


@contextmanager
def use_profile(name: str, *, check_ready: bool = True):
    """Apply a profile to config for the duration of the block; restore afterwards.

    Yields the applied settings. With check_ready (the default) a semantic profile
    stops with ProfileError, naming the command to run, when the MITRE catalogue
    or the vector store is missing. Settings are restored even if the block raises.
    """
    settings = get(name)
    if check_ready:
        require_ready(name)
    with applied({**settings, "ACTIVE_PROFILE": name}):
        yield settings


@contextmanager
def applied(settings: dict):
    """Set config values for the block (any profile switch, or ACTIVE_PROFILE), then restore
    every profile switch, even if the block raises."""
    keys = dict.fromkeys((*ALL_SETTINGS, "ACTIVE_PROFILE", *settings))
    saved = {key: getattr(config, key) for key in keys}
    try:
        for key, value in settings.items():
            setattr(config, key, value)
        yield
    finally:
        for key, value in saved.items():
            setattr(config, key, value)
