"""Offline retrieval comparison for CWE-89 alerts: keyword vs BM25 vs dense vs hybrid.

Makes no model-review calls and never reads the answer key. The only labels
are a fixed relevance proxy for CWE-89 guidance, chosen in advance:
SQL_Injection_Prevention and Query_Parameterization are the primary sheets.
Every method uses the same pool, top-k and character budget as production.

Run:  python verification/retrieval_comparison.py
"""
import math
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
from fastembed import TextEmbedding  # noqa: E402

from triagebot import config  # noqa: E402
from triagebot.nodes.context.retrieval import KnowledgeBase, _tokenize  # noqa: E402

MODEL_NAME = "BAAI/bge-small-en-v1.5"
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "  # BGE query instruction
PRIMARY = {"SQL_Injection_Prevention_Cheat_Sheet", "Query_Parameterization_Cheat_Sheet"}
RRF_K = 60
BM25_K1, BM25_B = 1.5, 0.75
CWE = "CWE-89"


def trim(ranked):
    """Production behaviour: top-k, then the character budget (one chunk always kept)."""
    chunks, used = [], 0
    for chunk in ranked[: config.RETRIEVAL_TOP_K]:
        if chunks and used + len(chunk["text"]) > config.GUIDANCE_MAX_CHARS:
            break
        chunks.append(chunk)
        used += len(chunk["text"])
    return chunks


def chunk_doc(chunk):
    """Ranking text: section path and body, as the keyword ranker sees them."""
    return f"{chunk['section']} {chunk['text']}"


class Bm25:
    def __init__(self, chunks):
        self.docs = [Counter(_tokenize(chunk_doc(c))) for c in chunks]
        self.lengths = [sum(d.values()) for d in self.docs]
        self.avg = sum(self.lengths) / len(self.lengths)
        df = Counter(t for d in self.docs for t in d)
        n = len(self.docs)
        self.idf = {t: math.log((n - f + 0.5) / (f + 0.5) + 1) for t, f in df.items()}

    def scores(self, query_terms):
        out = np.zeros(len(self.docs))
        for i, doc in enumerate(self.docs):
            norm = BM25_K1 * (1 - BM25_B + BM25_B * self.lengths[i] / self.avg)
            s = 0.0
            for term in query_terms:
                tf = doc.get(term, 0)
                if tf:
                    s += self.idf[term] * tf * (BM25_K1 + 1) / (tf + norm)
            out[i] = s
        return out


def rank_by(scores, chunks):
    """Indices sorted by score (desc), ties broken by chunk_id for determinism."""
    order = sorted(range(len(chunks)), key=lambda i: (-scores[i], chunks[i]["chunk_id"]))
    return order


def rrf(orders, n):
    fused = np.zeros(n)
    for order in orders:
        for rank, i in enumerate(order):
            fused[i] += 1.0 / (RRF_K + rank + 1)
    return fused


def relevant_share(chunks):
    if not chunks:
        return 0.0
    return sum(c["doc"] in PRIMARY for c in chunks) / len(chunks)


def main():
    kb = KnowledgeBase()
    alerts = json.loads((config.CHECKPOINT_OUT / "selected_alerts.json").read_text(encoding="utf-8"))["alerts"]
    alerts = [a for a in alerts if a["cwe"] == CWE]
    pool = [c for doc in kb.cwe_map[CWE] for c in kb._doc_chunks(doc)]
    print(f"Alerts: {len(alerts)} x {CWE}; pool: {len(pool)} chunks from {len(kb.cwe_map[CWE])} documents")

    print(f"Embedding pool with {MODEL_NAME} ...")
    embedder = TextEmbedding(MODEL_NAME)
    doc_vecs = np.array(list(embedder.embed([chunk_doc(c) for c in pool])))
    doc_vecs /= np.linalg.norm(doc_vecs, axis=1, keepdims=True)
    bm25 = Bm25(pool)

    methods = {"random (chance)": [], "keyword (production)": [], "bm25": [], "dense": [], "hybrid (RRF)": []}
    rng = random.Random(201)  # the project's split seed, reused for the chance baseline
    for alert in alerts:
        query = f"{alert['rule_id']}. {alert['message']}"
        terms = set(_tokenize(alert["rule_id"])) | set(_tokenize(alert["message"]))

        shuffled = list(range(len(pool)))
        rng.shuffle(shuffled)
        methods["random (chance)"].append(trim([pool[i] for i in shuffled]))

        methods["keyword (production)"].append(kb.retrieve(alert)["chunks"])

        bm_scores = bm25.scores(terms)
        bm_order = rank_by(bm_scores, pool)
        methods["bm25"].append(trim([pool[i] for i in bm_order]))

        q_vec = np.array(next(embedder.embed([QUERY_PREFIX + query])))
        q_vec /= np.linalg.norm(q_vec)
        dense_scores = doc_vecs @ q_vec
        dense_order = rank_by(dense_scores, pool)
        methods["dense"].append(trim([pool[i] for i in dense_order]))

        fused = rrf([bm_order, dense_order], len(pool))
        methods["hybrid (RRF)"].append(trim([pool[i] for i in rank_by(fused, pool)]))

    print()
    print(f"{'method':<22}{'hit@budget':>12}{'primary share':>16}{'chunks':>9}{'chars':>9}")
    for name, results in methods.items():
        hits = sum(any(c["doc"] in PRIMARY for c in chunks) for chunks in results)
        share = sum(relevant_share(chunks) for chunks in results) / len(results)
        chunks_avg = sum(len(chunks) for chunks in results) / len(results)
        chars = sum(sum(len(c["text"]) for c in chunks) for chunks in results) / len(results)
        print(f"{name:<22}{hits:>6}/{len(results):<5}{share:>15.2f}{chunks_avg:>9.1f}{chars:>9.0f}")

    print()
    print("hit@budget = alerts whose returned chunks include a primary CWE-89 sheet.")
    print("primary share = mean fraction of returned chunks from primary sheets.")
    print("Proxy relevance only: not the OWASP answer key, and not a verdict-accuracy measure.")


if __name__ == "__main__":
    main()
