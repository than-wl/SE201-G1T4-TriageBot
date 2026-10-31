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

from triagebot import config
from triagebot.config import KB_DIR
from triagebot.nodes.context.cwe_catalogue import CweCatalogue
from triagebot.nodes.context.embeddings import FastEmbedder
from triagebot.nodes.context.vector_store import VectorStore
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
    """Load-once view over the committed KB (indexes eagerly, docs lazily).

    ``mode`` picks the ranker: "map" (curated CWE gate, the default) or
    "semantic" (MITRE text for the CWE, ranked against every chunk). The
    embedder and catalogue are created on first use unless passed in, so
    tests can supply fakes and the default mode never loads a model.
    """

    def __init__(self, kb_dir: Path | None = None, *, mode: str | None = None,
                 embedder=None, catalogue: CweCatalogue | None = None,
                 vector_db: str | Path | None = None) -> None:
        self.kb_dir = Path(kb_dir) if kb_dir else KB_DIR
        self.mode = mode or config.RETRIEVAL_MODE
        if self.mode not in ("map", "semantic"):
            raise ValueError(f"unknown retrieval mode: {self.mode!r}")
        self.cwe_map: dict[str, list[str]] = _read_json(self.kb_dir / "cwe_map.json")
        self.common: list[dict] = _read_json(self.kb_dir / "common.json")["chunks"]
        self._docs: dict[str, list[dict]] = {}
        self._embedder = embedder
        self._catalogue = catalogue
        # Default: the file-backed store. An injected embedder (tests, measurement
        # with a fake) gets a throwaway in-memory store unless a path is given.
        self._vector_db = vector_db if vector_db is not None else (
            config.KB_VECTOR_DB if embedder is None else ":memory:")
        self._index: tuple[list[str], object] | None = None
        self._by_id: dict[str, dict] = {}

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
        if self.mode == "semantic":
            return self._retrieve_semantic(alert)
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
        return {
            "source": _SOURCE,
            "cwe_matched": bool(matched_docs),
            "chunks": _within_budget(ranked),
        }

    def _retrieve_semantic(self, alert: NormalisedAlert) -> Guidance:
        """Rank every chunk by similarity to the MITRE text of the alert's CWE.

        No CWE, or a CWE the catalogue does not know (or has deprecated), gives
        no grounded guidance. So does a best score below SEMANTIC_MIN_SCORE.
        The validator turns cwe_matched=False into human review.
        """
        cwe = _normalise_cwe(alert.get("cwe", ""))
        entry = self._cwe_catalogue().lookup(cwe) if cwe else None
        if entry is None:
            return {"source": _SOURCE, "cwe_matched": False, "chunks": []}

        ids, vectors = self._semantic_index()
        query = CweCatalogue.query_text(entry)[: config.SEMANTIC_QUERY_MAX_CHARS]
        scores = vectors @ self._get_embedder().embed_query(query)
        order = sorted(range(len(ids)), key=lambda i: (-scores[i], ids[i]))
        eligible = [self._by_id[ids[i]] for i in order
                    if scores[i] >= config.SEMANTIC_MIN_SCORE]
        chunks = _within_budget(eligible)
        return {"source": _SOURCE, "cwe_matched": bool(chunks), "chunks": chunks}

    def _get_embedder(self):
        if self._embedder is None:
            self._embedder = FastEmbedder()
        return self._embedder

    def _cwe_catalogue(self) -> CweCatalogue:
        if self._catalogue is None:
            self._catalogue = CweCatalogue()
        return self._catalogue

    def _all_chunks(self) -> list[dict]:
        """Every chunk in the KB (common set plus every cheat sheet), without exact repeats.

        The committed JSON repeats 22 chunks verbatim. The semantic store needs
        one row per chunk_id, so exact repeats are dropped here. The map path reads
        the raw JSON and is unchanged. A chunk_id that appears with different
        content is an error, not something to pick from silently.
        """
        docs = sorted(p.stem for p in (self.kb_dir / "docs").glob("*.json"))
        seen: dict[str, dict] = {}
        for chunk in list(self.common) + [c for doc in docs for c in self._doc_chunks(doc)]:
            prior = seen.get(chunk["chunk_id"])
            if prior is None:
                seen[chunk["chunk_id"]] = chunk
            elif prior != chunk:
                raise ValueError(f"chunk_id {chunk['chunk_id']} appears with different content")
        return list(seen.values())

    def _semantic_index(self) -> tuple[list[str], object]:
        """Sync the store with the KB (embedding only new or changed chunks), then load it."""
        if self._index is None:
            store = VectorStore(self._vector_db)
            try:
                store.sync(self._all_chunks(), self._get_embedder())
                chunks, matrix = store.load()
            finally:
                store.close()
            self._index = ([c["chunk_id"] for c in chunks], matrix)
            self._by_id = {c["chunk_id"]: c for c in chunks}
        return self._index

    @staticmethod
    def _score(chunk: dict, terms: set[str]) -> int:
        """Occurrence count of each term; section-path hits weigh double."""
        text = chunk["text"].lower()
        section = chunk["section"].lower()
        return sum(text.count(t) + 2 * section.count(t) for t in terms)


def _within_budget(ranked: list[dict]) -> list[dict]:
    """Top-k, trimmed to the character budget (one chunk always kept)."""
    chunks: list[dict] = []
    used = 0
    for chunk in ranked[:config.RETRIEVAL_TOP_K]:
        if chunks and used + len(chunk["text"]) > config.GUIDANCE_MAX_CHARS:
            break
        chunks.append(chunk)
        used += len(chunk["text"])
    return chunks


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))
