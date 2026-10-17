"""CWE-keyed, keyword-ranked guidance retrieval over the local KB.

Stage 1: gate on the alert's CWE. Gate hit -> chunks from the matched
documents only. Gate miss -> the curated common chunks are the
fallback, and the result is flagged cwe_matched=False (the validator
routes those alerts to human review).

Stage 2: rank the pool by terms derived from the alert (rule id,
message, plus any caller-supplied terms such as source/sink APIs) and
return the top-ranked chunks within the guidance budget.

No runtime web fetching; reads only the committed JSON in kb/.
"""

import json
import re
from pathlib import Path

from triagebot.config import GUIDANCE_MAX_CHARS, KB_DIR, RETRIEVAL_TOP_K
from triagebot.schemas import Guidance, NormalisedAlert

_SOURCE = "OWASP Cheat Sheet Series"

# Just enough function words to keep query noise down.
_STOPWORDS = frozenset(
    """a an and are as at be by do for from has have how in is it its may
    of on or that the this to use was we what when will with you your
    detected false positive true review should would could not no but if
    then also there here""".split()
)
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    """Split identifiers and prose into simple lowercase tokens."""
    words = _CAMEL.sub(" ", text)                 # executeQuery -> execute Query
    words = _NON_ALNUM.sub(" ", words.lower())    # stmt.execute -> stmt execute
    return [w for w in words.split() if len(w) > 1 and w not in _STOPWORDS]


def _normalise_cwe(raw: str) -> str:
    """"CWE-89" / "cwe_89" / "89" -> "CWE-89"; anything else -> ""."""
    digits = re.findall(r"\d+", raw or "")
    return f"CWE-{digits[0]}" if digits else ""


class KnowledgeBase:
    """Load-once view over the committed KB (indexes eagerly, docs lazily)."""

    def __init__(self, kb_dir: Path | None = None) -> None:
        self.kb_dir = Path(kb_dir) if kb_dir else KB_DIR
        self.cwe_map: dict[str, list[str]] = _read_json(self.kb_dir / "cwe_map.json")
        self.common: list[dict] = _read_json(self.kb_dir / "common.json")["chunks"]
        self._docs: dict[str, list[dict]] = {}

    def _doc_chunks(self, doc: str) -> list[dict]:
        if doc not in self._docs:
            path = self.kb_dir / "docs" / f"{doc}.json"
            if path.exists():
                self._docs[doc] = _read_json(path)["chunks"]
            else:
                print(f"WARNING: KB is missing {path.name}; skipped")
                self._docs[doc] = []
        return self._docs[doc]

    def retrieve(
        self,
        alert: NormalisedAlert,
        extra_terms: list[str] | None = None,
    ) -> Guidance:
        """Return the guidance for one alert: top-k chunks + match flag."""
        cwe = _normalise_cwe(alert.get("cwe", ""))
        matched_docs = self.cwe_map.get(cwe, [])

        # Two mutually exclusive branches: matched docs when the gate
        # hits, the common fallback when it misses.
        if matched_docs:
            pool = [c for doc in matched_docs for c in self._doc_chunks(doc)]
        else:
            pool = list(self.common)

        # Query terms: rule id + message, plus caller-supplied extras
        # (facts extraction passes source/sink APIs here later).
        terms = set(_tokenize(alert.get("rule_id", ""))) | set(
            _tokenize(alert.get("message", ""))
        )
        for extra in extra_terms or []:
            terms.update(_tokenize(extra))

        ranked = sorted(pool, key=lambda c: (-self._score(c, terms), c["chunk_id"]))

        # Top-k, trimmed to the character budget (one chunk always kept).
        chunks: list[dict] = []
        used = 0
        for chunk in ranked[:RETRIEVAL_TOP_K]:
            if chunks and used + len(chunk["text"]) > GUIDANCE_MAX_CHARS:
                break
            chunks.append(chunk)
            used += len(chunk["text"])

        return {
            "source": _SOURCE,
            "cwe_matched": bool(matched_docs),
            "chunks": chunks,
        }

    @staticmethod
    def _score(chunk: dict, terms: set[str]) -> int:
        """Occurrence count of each term; section-path hits weigh double."""
        text = chunk["text"].lower()
        section = chunk["section"].lower()
        return sum(text.count(t) + 2 * section.count(t) for t in terms)


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))
