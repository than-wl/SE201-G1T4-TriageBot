"""Score retrieval methods against hand-graded chunk relevance.

Reads verification/relevance_labels.json: for each CWE in the recorded scan, the
candidate chunks (the union of the top dense and top BM25 results) with a grade from
reading the cheat-sheet text: 2 = guidance about this weakness, 1 = adjacent, 0 = not
relevant. The grades are one reader's judgement and have not been independently
reviewed. Precision counts grade 2 only. Every method ranks the same candidate pool.
Makes no review-model calls and never reads the answer key.

Run:  python verification/relevance_eval.py [--rerank]
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from retrieval_comparison import Bm25  # noqa: E402  (sits next to this script)
from triagebot import config  # noqa: E402
from triagebot.nodes.context.cwe_catalogue import CweCatalogue  # noqa: E402
from triagebot.nodes.context.embeddings import FastEmbedder, chunk_text  # noqa: E402
from triagebot.nodes.context.retrieval import KnowledgeBase, _tokenize  # noqa: E402
from triagebot.nodes.context.vector_store import VectorStore  # noqa: E402
from triagebot.nodes.ingest.normalise import load_semgrep, normalise  # noqa: E402

RRF_K = 60
RERANKERS = ("Xenova/ms-marco-MiniLM-L-6-v2", "BAAI/bge-reranker-base")


def fuse(orders, weights):
    score = {}
    for weight, order in zip(weights, orders):
        for rank, cid in enumerate(order):
            score[cid] = score.get(cid, 0.0) + weight / (RRF_K + rank + 1)
    return sorted(score, key=lambda cid: (-score[cid], cid))


def precision(order, labels, k):
    return sum(labels.get(cid, 0) == 2 for cid in order[:k]) / k


def report(name, orders, labels):
    p2 = np.mean([precision(orders[c], labels[c], 2) for c in orders])
    p6 = np.mean([precision(orders[c], labels[c], 6) for c in orders])
    print(f"{name:<30}{p2:>7.2f}{p6:>7.2f}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rerank", action="store_true", help="also score two cross-encoder rerankers")
    args = parser.parse_args()

    labels = json.loads((ROOT / "verification" / "relevance_labels.json").read_text(encoding="utf-8"))
    kb = KnowledgeBase(mode="map")
    catalogue = CweCatalogue()
    embedder = FastEmbedder()
    store = VectorStore(config.KB_VECTOR_DB)
    store.sync(kb._all_chunks(), embedder)
    chunks, matrix = store.load()
    store.close()
    ids = [c["chunk_id"] for c in chunks]
    row = {cid: i for i, cid in enumerate(ids)}
    by_id = {c["chunk_id"]: c for c in chunks}
    bm25 = Bm25(chunks)

    orders = {"dense (MITRE text)": {}, "bm25": {}, "dense + bm25, 1:1": {}, "dense + bm25, 0.7:0.3": {}}
    queries = {}
    for cwe, graded in labels.items():
        pool = list(graded)
        queries[cwe] = CweCatalogue.query_text(catalogue.lookup(cwe))[: config.SEMANTIC_QUERY_MAX_CHARS]
        dense_scores = matrix @ embedder.embed_query(queries[cwe])
        bm25_scores = bm25.scores(set(_tokenize(queries[cwe])))
        dense = sorted(pool, key=lambda c: (-dense_scores[row[c]], c))
        lexical = sorted(pool, key=lambda c: (-bm25_scores[row[c]], c))
        orders["dense (MITRE text)"][cwe] = dense
        orders["bm25"][cwe] = lexical
        orders["dense + bm25, 1:1"][cwe] = fuse([dense, lexical], [1, 1])
        orders["dense + bm25, 0.7:0.3"][cwe] = fuse([dense, lexical], [0.7, 0.3])

    if args.rerank:
        from fastembed.rerank.cross_encoder import TextCrossEncoder
        for model in RERANKERS:
            encoder = TextCrossEncoder(model)
            orders[f"rerank {model.split('/')[-1]}"] = {}
            for cwe, graded in labels.items():
                pool = list(graded)
                scores = list(encoder.rerank(queries[cwe], [chunk_text(by_id[c]) for c in pool]))
                orders[f"rerank {model.split('/')[-1]}"][cwe] = [
                    c for _, c in sorted(zip(scores, pool), key=lambda pair: -pair[0])]

    print(f"{'method':<30}{'P@2':>7}{'P@6':>7}   (macro over {len(labels)} CWEs, grade 2 = relevant)")
    for name, per_cwe in orders.items():
        report(name, per_cwe, labels)

    # The curated map, scored on the alerts it answers for. A CWE with no map entry gets no
    # grounded guidance, so it scores 0 in the all-CWE figure.
    alerts, _ = normalise(load_semgrep(config.RECORDED_SCAN)[0])
    map_p2, unlabelled = {}, 0
    for cwe, graded in labels.items():
        if cwe not in kb.cwe_map:
            map_p2[cwe] = 0.0
            continue
        per_alert = []
        for alert in (a for a in alerts if a["cwe"] == cwe):
            top = [c["chunk_id"] for c in kb.retrieve(alert)["chunks"]][:2]
            unlabelled += sum(c not in graded for c in top)
            per_alert.append(sum(graded.get(c, 0) == 2 for c in top) / 2)
        map_p2[cwe] = float(np.mean(per_alert))
    mapped = [c for c in labels if c in kb.cwe_map]
    dense_p2 = {c: precision(orders["dense (MITRE text)"][c], labels[c], 2) for c in labels}
    print()
    print(f"{'curated map, P@2':<30}{np.mean([map_p2[c] for c in mapped]):>7.2f}   {len(mapped)} CWEs it covers")
    print(f"{'dense, P@2 (same CWEs)':<30}{np.mean([dense_p2[c] for c in mapped]):>7.2f}")
    print(f"{'curated map, P@2':<30}{np.mean(list(map_p2.values())):>7.2f}   all {len(labels)} CWEs (ungrounded = 0)")
    print(f"{'dense, P@2':<30}{np.mean(list(dense_p2.values())):>7.2f}   all {len(labels)} CWEs")
    if unlabelled:
        print(f"note: {unlabelled} map-returned chunks were not graded and count as not relevant")


if __name__ == "__main__":
    main()
