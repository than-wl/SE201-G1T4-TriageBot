"""CWE-keyed, keyword-ranked guidance retrieval over the local KB.

Stage 1: gate on the alert's CWE. Gate hit -> chunks from the matched
documents only. Gate miss -> the curated common chunks are the
fallback, and the result is flagged cwe_matched=False (the validator
routes those alerts to human review).

Stage 2: rank the pool by terms derived from the alert (rule id,
message, plus any caller-supplied terms such as source/sink APIs) and
return the top-ranked chunks within the guidance budget.

No runtime web fetching; reads only the committed JSON in kb/.

Semantic mode (RETRIEVAL_MODE = "semantic", design decisions 21 and 28) ranks
chunks by similarity to the MITRE text of the alert's CWE instead. Its five
set-up rules (R1 to R5) are config switches read at call time; all off is the
decision 21 set-up. See which chunks one CWE gets, without any model call
(only the local embedder):

    python -m triagebot.nodes.context.retrieval --explain CWE-89 [--setup original|improved]
"""

import argparse
import json
import re
import sys
from pathlib import Path

from triagebot import config, profiles
from triagebot.config import KB_DIR
from triagebot.nodes.context.cwe_catalogue import CweCatalogue
from triagebot.nodes.context.embeddings import FastEmbedder
from triagebot.nodes.context.vector_store import VectorStore
from triagebot.schemas import Guidance, NormalisedAlert

_SOURCE = "OWASP Cheat Sheet Series"
_SOURCE_WITH_MITRE = "MITRE CWE and OWASP Cheat Sheet Series"
GROUNDING_RULES = ("min_score", "mitre_record")
SCOPE_RULES = ("retired", "attack_catalogue", "platform")

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
        # Default: the file-backed store, which is derived from the committed KB only. An
        # injected embedder (tests, measurement with a fake) or any other KB folder (a test
        # fixture) gets a throwaway in-memory store unless a path is given: syncing the real
        # store against another KB deletes its rows (the 8 Nov wipe, design decision 30).
        committed_kb = self.kb_dir.resolve() == Path(KB_DIR).resolve()
        self._vector_db = vector_db if vector_db is not None else (
            config.KB_VECTOR_DB if embedder is None and committed_kb else ":memory:")
        self._index: tuple[list[str], object] | None = None
        self._index_cap: int | None = None
        self._by_id: dict[str, dict] = {}
        self._pools: dict[tuple, frozenset[str]] = {}
        self._scope: dict | None = None

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
        """Rank the searched chunks by similarity to the MITRE text of the alert's CWE.

        No CWE, or a CWE the catalogue does not know (or has deprecated), gives
        no grounded guidance. Under SEMANTIC_GROUNDING = "min_score" neither does
        a best score below SEMANTIC_MIN_SCORE. The validator turns
        cwe_matched=False into human review.
        """
        plan = self.semantic_plan(alert)
        mitre = any(c["doc"] == "MITRE_CWE" for c in plan["chunks"])
        return {"source": _SOURCE_WITH_MITRE if mitre else _SOURCE,
                "cwe_matched": plan["grounded"], "chunks": plan["chunks"]}

    def semantic_plan(self, alert: NormalisedAlert) -> dict:
        """Everything semantic retrieval decides for one alert, for retrieve() and --explain.

        Keys: cwe, entry (the MITRE record or None), query, grounded, reason,
        mitre (the MITRE chunk or None), ranked ([(chunk, cosine)] over the
        searched pool, best first, after the grounding rule), chunks (what is
        returned) and taken (how many of ranked made it into chunks).
        """
        rule = config.SEMANTIC_GROUNDING
        if rule not in GROUNDING_RULES:
            raise ValueError(f"SEMANTIC_GROUNDING must be one of {GROUNDING_RULES}, not {rule!r}")
        cwe = _normalise_cwe(alert.get("cwe", ""))
        entry = self._cwe_catalogue().lookup(cwe) if cwe else None
        plan = {"cwe": cwe, "entry": entry, "query": None, "grounded": False, "mitre": None,
                "ranked": [], "chunks": [], "taken": 0}
        if entry is None:
            plan["reason"] = ("the alert names no CWE" if not cwe else
                              f"{cwe} has no valid MITRE record (unknown or deprecated)")
            return plan

        plan["query"], ranked = self._rank(entry)
        if config.SEMANTIC_MITRE_GUIDANCE:
            cap = min(config.MITRE_GUIDANCE_MAX_CHARS, config.GUIDANCE_MAX_CHARS)
            plan["mitre"] = CweCatalogue.guidance_chunk(entry, cap)
        if rule == "mitre_record":
            plan["grounded"] = True
            plan["reason"] = f"{cwe} has a valid, non-deprecated MITRE record"
        else:
            ranked = [(c, s) for c, s in ranked if s >= config.SEMANTIC_MIN_SCORE]
            plan["grounded"] = bool(ranked)
            best = f"; best cosine {ranked[0][1]:.3f}" if ranked else ""
            plan["reason"] = (f"{len(ranked)} searched chunk(s) score at least SEMANTIC_MIN_SCORE "
                              f"{config.SEMANTIC_MIN_SCORE}{best}")
        plan["ranked"] = ranked
        if plan["grounded"]:
            lead = [plan["mitre"]] if plan["mitre"] else []
            plan["chunks"], plan["taken"] = _fill([c for c, _ in ranked], lead)
        return plan

    def _rank(self, entry: dict) -> tuple[str, list[tuple[dict, float]]]:
        """The query for a MITRE record, and the searched chunks ranked by cosine (ties by chunk_id)."""
        ids, vectors = self._semantic_index()
        query = CweCatalogue.query_text(entry, alternate_terms=config.SEMANTIC_QUERY_ALT_TERMS)
        query = query[: config.SEMANTIC_QUERY_MAX_CHARS]
        scores = vectors @ self._get_embedder().embed_query(query)
        pool = self._search_pool()
        order = sorted((i for i in range(len(ids)) if ids[i] in pool),
                       key=lambda i: (-scores[i], ids[i]))
        return query, [(self._by_id[ids[i]], float(scores[i])) for i in order]

    def _search_pool(self) -> frozenset[str]:
        """The chunk_ids searched under the current set-up (rules R3 and R4).

        R4 replaces each chunk longer than SEMANTIC_MAX_CHUNK_CHARS by its pieces.
        R3 drops the chunks of sheets scope.json excludes for KB_TARGET_PLATFORM;
        the common set is always kept.
        """
        cap = config.SEMANTIC_MAX_CHUNK_CHARS
        target = config.KB_TARGET_PLATFORM if config.SEMANTIC_KB_SCOPE else None
        key = (cap, target)
        if key not in self._pools:
            excluded = excluded_docs(self._kb_scope(), target) if target is not None else {}
            common = {c["chunk_id"] for c in self.common}
            ids: set[str] = set()
            for chunk in self._all_chunks():
                if chunk["doc"] in excluded and chunk["chunk_id"] not in common:
                    continue
                ids.update(p["chunk_id"] for p in split_chunk(chunk, cap))
            self._pools[key] = frozenset(ids)
        return self._pools[key]

    def _kb_scope(self) -> dict:
        if self._scope is None:
            path = self.kb_dir / "scope.json"
            if not path.is_file():
                raise FileNotFoundError(f"SEMANTIC_KB_SCOPE is on but {path} is missing")
            self._scope = load_scope(path)
        return self._scope

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

    def _store_chunks(self, cap: int) -> list[dict]:
        """What the vector store holds: every chunk, plus the pieces of those longer than ``cap``.

        Keeping both lets the original set-up (whole chunks) and the improved one
        (pieces) search the same store without re-embedding when switching.
        """
        rows = []
        for chunk in self._all_chunks():
            rows.append(chunk)
            if cap and len(chunk["text"]) > cap:
                rows.extend(split_chunk(chunk, cap))
        return rows

    def _semantic_index(self, allow_large_delete: bool = False) -> tuple[list[str], object]:
        """Sync the store with the KB (embedding only new or changed chunks), then load it.

        The store also holds the R4 pieces at the current cap, or at the semantic
        profile's cap while splitting is off, so preparing the store once covers both
        set-ups. A sync that would delete more than half of the stored rows is
        refused (VectorStore.sync) unless ``allow_large_delete`` (the prepare command).
        """
        cap = config.SEMANTIC_MAX_CHUNK_CHARS or improved_chunk_cap()
        if self._index is None or self._index_cap != cap:
            store = VectorStore(self._vector_db)
            try:
                store.sync(self._store_chunks(cap), self._get_embedder(),
                           allow_large_delete=allow_large_delete)
                chunks, matrix = store.load()
            finally:
                store.close()
            self._index = ([c["chunk_id"] for c in chunks], matrix)
            self._index_cap = cap
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
    return _fill(ranked)[0]


def _fill(ranked: list[dict], lead: list[dict] = ()) -> tuple[list[dict], int]:
    """``lead`` first, then ranked chunks in order until RETRIEVAL_TOP_K chunks or the
    GUIDANCE_MAX_CHARS budget is reached (stopping at the first that does not fit; the
    first chunk overall is always kept). Returns the chunks and how many of ``ranked``
    were taken. The lead (the MITRE chunk) counts against both limits.
    """
    chunks: list[dict] = list(lead)
    used = sum(len(c["text"]) for c in chunks)
    taken = 0
    for chunk in ranked[: max(config.RETRIEVAL_TOP_K - len(chunks), 0)]:
        if chunks and used + len(chunk["text"]) > config.GUIDANCE_MAX_CHARS:
            break
        chunks.append(chunk)
        used += len(chunk["text"])
        taken += 1
    return chunks, taken


# --- R4: split oversized chunks ---------------------------------------------------------

_SPLITTERS = (
    re.compile(r"\n[ \t]*\n\s*"),       # blank lines
    re.compile(r"\n\s*"),               # line breaks
    re.compile(r"(?<=[.!?])\s+"),       # sentence ends
    re.compile(r"\s+"),                 # last resort: spaces (a single over-long sentence)
)


def _segments(text: str, pattern: re.Pattern) -> list[str]:
    """Cut ``text`` after each match of ``pattern``; the segments join back to ``text`` exactly."""
    segments, start = [], 0
    for match in pattern.finditer(text):
        if match.end() > start:
            segments.append(text[start:match.end()])
            start = match.end()
    if start < len(text):
        segments.append(text[start:])
    return segments


def _split_text(text: str, cap: int, level: int = 0) -> list[str]:
    """Raw pieces of at most ``cap`` characters (before stripping) that join back to ``text``."""
    if len(text) <= cap:
        return [text]
    if level == len(_SPLITTERS):                      # no space at all: cut at the cap
        return [text[i:i + cap] for i in range(0, len(text), cap)]
    atoms: list[str] = []
    for segment in _segments(text, _SPLITTERS[level]):
        atoms.extend(_split_text(segment, cap, level + 1) if len(segment) > cap else [segment])
    pieces, current = [], ""
    for atom in atoms:                                # pack neighbours greedily up to the cap
        if current and len(current) + len(atom) > cap:
            pieces.append(current)
            current = atom
        else:
            current += atom
    pieces.append(current)
    return pieces


def split_chunk(chunk: dict, max_chars: int) -> list[dict]:
    """Rule R4: a chunk longer than ``max_chars`` becomes pieces of at most ``max_chars``.

    Split at blank lines first, then line breaks, then sentence ends. Each piece
    keeps doc, section and url and gets the ID "{chunk_id}.1", "{chunk_id}.2", ...
    Joining the pieces gives the original text apart from whitespace at the split
    points. A chunk within the cap (or ``max_chars`` 0) is returned unchanged.
    """
    if not max_chars or len(chunk["text"]) <= max_chars:
        return [chunk]
    texts = [t.strip() for t in _split_text(chunk["text"], max_chars)]
    return [dict(chunk, chunk_id=f"{chunk['chunk_id']}.{n}", text=t)
            for n, t in enumerate((t for t in texts if t), 1)]


def improved_chunk_cap() -> int:
    """The R4 cap of the semantic profile: the vector store always holds these pieces."""
    return profiles.PROFILES["semantic"].get("SEMANTIC_MAX_CHUNK_CHARS", 0)


# --- R3: which sheets are searched ------------------------------------------------------

def load_scope(path: Path) -> dict:
    """Read kb/scope.json and check its shape: excluded {doc: rule, reason},
    platform {doc: platform, reason}, general [doc, ...]."""
    scope = _read_json(Path(path))
    for doc, entry in scope.get("excluded", {}).items():
        if entry.get("rule") not in SCOPE_RULES[:2] or not entry.get("reason"):
            raise ValueError(f"scope.json: {doc} needs a rule ({' or '.join(SCOPE_RULES[:2])}) "
                             "and a reason")
    for doc, entry in scope.get("platform", {}).items():
        if not entry.get("platform") or not entry.get("reason"):
            raise ValueError(f"scope.json: {doc} needs a platform and a reason")
    return scope


def excluded_docs(scope: dict, target: str) -> dict[str, str]:
    """Sheets not searched for code on ``target``, each with "rule: reason".

    Rules a (retired) and b (attack catalogue) always exclude; rule c excludes
    sheets tagged with a platform other than ``target``. Untagged sheets are general.
    """
    excluded = {doc: f"{entry['rule']}: {entry['reason']}"
                for doc, entry in scope.get("excluded", {}).items()}
    for doc, entry in scope.get("platform", {}).items():
        if entry["platform"] != target:
            excluded[doc] = f"platform {entry['platform']}, not {target}: {entry['reason']}"
    return excluded


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


# --- --explain: what one CWE gets, without any model call -----------------------------

def _preview(text: str, limit: int = 300) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit].rsplit(" ", 1)[0] + " ..."


def _describe_setup(settings: dict) -> str:
    on = lambda key: "on" if settings[key] else "off"
    cap = settings["SEMANTIC_MAX_CHUNK_CHARS"]
    return (f"R1 alternate terms {on('SEMANTIC_QUERY_ALT_TERMS')}; "
            f"R2 MITRE record {on('SEMANTIC_MITRE_GUIDANCE')}"
            + (f" (cap {settings['MITRE_GUIDANCE_MAX_CHARS']})" if settings["SEMANTIC_MITRE_GUIDANCE"] else "")
            + f"; R3 sheet scope {on('SEMANTIC_KB_SCOPE')}"
            + (f" (platform {settings['KB_TARGET_PLATFORM']})" if settings["SEMANTIC_KB_SCOPE"] else "")
            + f"; R4 split chunks {'at ' + str(cap) if cap else 'off'}"
            + f"; R5 grounding {settings['SEMANTIC_GROUNDING']}")


def _row(rank, chunk, score, total=None) -> str:
    cosine = "-" if score is None else f"{score:.3f}"
    running = "" if total is None else f"{total:>7}"
    return f"  {rank:>4}  {chunk['chunk_id']:<58} {cosine:>7} {len(chunk['text']):>6}{running}"


def explain(cwe: str, setup: str = "improved", kb: "KnowledgeBase | None" = None) -> str:
    """A plain-text account of how semantic retrieval builds one CWE's guidance pack.

    Prints the query, whether the CWE is grounded and why, the start of the MITRE
    chunk, the guidance returned (rank, chunk_id, cosine, chars, running total) and
    the next five results that did not fit. Uses only the local embedder.
    """
    if setup not in profiles.SEMANTIC_SETUPS:
        raise ValueError(f"setup must be one of {', '.join(profiles.SEMANTIC_SETUPS)}")
    settings = profiles.SEMANTIC_SETUPS[setup]
    if kb is None:
        missing = []
        if not Path(config.CWE_CATALOGUE_XML).is_file():
            missing.append(f"the MITRE CWE catalogue is missing ({config.CWE_CATALOGUE_XML}); "
                           f"prepare it with: {profiles.CATALOGUE_COMMAND}")
        if not profiles._vector_store_ready(config.KB_VECTOR_DB):
            missing.append(f"the knowledge-base vector store is missing ({config.KB_VECTOR_DB}); "
                           f"prepare it with: {profiles.VECTOR_STORE_COMMAND}")
        if missing:
            raise profiles.ProfileError("cannot explain yet: " + "; ".join(missing))
    with profiles.applied({"RETRIEVAL_MODE": "semantic", **settings}):
        kb = kb or KnowledgeBase(mode="semantic")
        plan = kb.semantic_plan({"cwe": cwe})
        budget, top_k = config.GUIDANCE_MAX_CHARS, config.RETRIEVAL_TOP_K

    name = plan["entry"]["name"] if plan["entry"] else "no MITRE record"
    lines = [f"Semantic retrieval for {plan['cwe'] or cwe!r} ({name}), {setup} set-up",
             f"  {_describe_setup(settings)}", ""]
    if plan["query"] is None:
        lines.append("Query: none (no MITRE record to build it from)")
    else:
        lines += [f"Query ({len(plan['query'])} chars, cap {config.SEMANTIC_QUERY_MAX_CHARS}):",
                  f"  {plan['query']}"]
    verdict = "yes" if plan["grounded"] else "no; the validator sends the alert to human review"
    lines += ["", f"Grounded: {verdict}", f"  why: {plan['reason']}", ""]
    if plan["mitre"]:
        lines += [f"MITRE chunk ({plan['mitre']['chunk_id']}, {len(plan['mitre']['text'])} chars, "
                  f"{plan['mitre']['url']}):", f"  {_preview(plan['mitre']['text'])}"]
    else:
        lines.append("MITRE chunk: " + ("none (no record)" if not plan["entry"]
                                        else "not attached (R2 off)"))
    lines += ["", f"Guidance returned (budget {budget} chars, at most {top_k} chunks):",
              f"  {'rank':>4}  {'chunk_id':<58} {'cosine':>7} {'chars':>6} {'total':>6}"]
    total = 0
    scores = {c["chunk_id"]: s for c, s in plan["ranked"]}
    for chunk in plan["chunks"]:
        total += len(chunk["text"])
        is_mitre = chunk is plan["mitre"]
        rank = "-" if is_mitre else str(next(i for i, (c, _) in enumerate(plan["ranked"], 1)
                                             if c["chunk_id"] == chunk["chunk_id"]))
        lines.append(_row(rank, chunk, None if is_mitre else scores[chunk["chunk_id"]], total))
    if not plan["chunks"]:
        lines.append("  (none)")
    rest = plan["ranked"][plan["taken"]: plan["taken"] + 5] if plan["grounded"] else []
    lines += ["", "Next 5 results that did not fit:"]
    lines += [_row(str(plan["taken"] + i), c, s) for i, (c, s) in enumerate(rest, 1)] or ["  (none)"]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m triagebot.nodes.context.retrieval",
        description="Show how semantic retrieval builds one CWE's guidance (no model calls).")
    parser.add_argument("--explain", metavar="CWE", required=True, help="for example CWE-89")
    parser.add_argument("--setup", choices=tuple(profiles.SEMANTIC_SETUPS), default="improved",
                        help="original: all five rules off (decision 21); "
                             "improved: the semantic profile (decision 28). Default: improved")
    args = parser.parse_args(argv)
    try:
        print(explain(args.explain, args.setup))
    except (profiles.ProfileError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
