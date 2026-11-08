"""Dev-split measurement for semantic retrieval: map vs MITRE-text query vs MITRE text + alert message.

Uses only the dev sample (CWE-89, selected_alerts.json). Relevance is the same
fixed proxy as verification/retrieval_comparison.py: SQL_Injection_Prevention and
Query_Parameterization are the primary sheets. Makes no model-review calls and
never reads the answer key. The threshold sweep is for choosing
SEMANTIC_MIN_SCORE on dev; the held-out test half is not touched here.

Run:  python verification/semantic_measurement.py
"""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from triagebot import config  # noqa: E402
from triagebot.nodes.context.cwe_catalogue import CweCatalogue  # noqa: E402
from triagebot.nodes.context.embeddings import FastEmbedder  # noqa: E402
from triagebot.nodes.context.retrieval import KnowledgeBase, _normalise_cwe  # noqa: E402
from triagebot.nodes.context.vector_store import VectorStore  # noqa: E402

PRIMARY = {"SQL_Injection_Prevention_Cheat_Sheet", "Query_Parameterization_Cheat_Sheet"}
THRESHOLDS = (0.0, 0.5, 0.55, 0.6, 0.65, 0.7)


def within_budget(ranked):
    chunks, used = [], 0
    for chunk in ranked[: config.RETRIEVAL_TOP_K]:
        if chunks and used + len(chunk["text"]) > config.GUIDANCE_MAX_CHARS:
            break
        chunks.append(chunk)
        used += len(chunk["text"])
    return chunks


def main():
    kb = KnowledgeBase(mode="map")
    catalogue = CweCatalogue()
    embedder = FastEmbedder()
    store = VectorStore(config.KB_VECTOR_DB)
    store.sync(kb._all_chunks(), embedder)
    chunks, vectors = store.load()
    store.close()
    ids = [c["chunk_id"] for c in chunks]
    by_id = {c["chunk_id"]: c for c in chunks}

    alerts = [a for a in json.loads((config.CHECKPOINT_OUT / "selected_alerts.json")
                                    .read_text(encoding="utf-8"))["alerts"]
              if _normalise_cwe(a["cwe"]) == "CWE-89"]
    entry = catalogue.lookup("CWE-89")
    mitre_query = CweCatalogue.query_text(entry)[: config.SEMANTIC_QUERY_MAX_CHARS]
    mitre_vec = embedder.embed_query(mitre_query)

    rows = {"A map (current)": [], "B MITRE text": [], "C MITRE + message": []}
    top_scores = []
    for alert in alerts:
        map_chunks = kb.retrieve(alert)["chunks"]
        rows["A map (current)"].append((map_chunks, True))

        scores_b = vectors @ mitre_vec
        order_b = sorted(range(len(ids)), key=lambda i: (-scores_b[i], ids[i]))
        top_scores.append(float(scores_b[order_b[0]]))
        rows["B MITRE text"].append((within_budget([by_id[ids[i]] for i in order_b]),
                                     scores_b[order_b[0]]))

        combo = f"{mitre_query} Alert: {alert['message']}"[: config.SEMANTIC_QUERY_MAX_CHARS]
        scores_c = vectors @ embedder.embed_query(combo)
        order_c = sorted(range(len(ids)), key=lambda i: (-scores_c[i], ids[i]))
        rows["C MITRE + message"].append((within_budget([by_id[ids[i]] for i in order_c]),
                                          scores_c[order_c[0]]))

    print(f"Dev alerts: {len(alerts)} x CWE-89 | pool: {len(chunks)} chunks | model: {config.EMBEDDING_MODEL}")
    print()
    print(f"{'variant':<20}{'hit@budget':>12}{'primary share':>16}{'chunks':>9}")
    for name, results in rows.items():
        chunk_lists = [r[0] if isinstance(r, tuple) else r for r in results]
        hits = sum(any(c["doc"] in PRIMARY for c in cs) for cs in chunk_lists)
        share = np.mean([sum(c["doc"] in PRIMARY for c in cs) / max(1, len(cs)) for cs in chunk_lists])
        size = np.mean([len(cs) for cs in chunk_lists])
        print(f"{name:<20}{hits:>6}/{len(alerts):<5}{share:>15.2f}{size:>9.1f}")

    print()
    print("Top-1 cosine score for variant B (MITRE text query):")
    print(f"  min {min(top_scores):.3f}  median {np.median(top_scores):.3f}  max {max(top_scores):.3f}")
    print()
    print("Threshold sweep on variant B (grounded = best chunk clears the threshold):")
    print(f"{'threshold':>10}{'grounded':>10}{'primary share (grounded)':>28}")
    for threshold in THRESHOLDS:
        grounded = [r for r in rows["B MITRE text"] if r[1] >= threshold and r[0]]
        share = (np.mean([sum(c["doc"] in PRIMARY for c in cs) / max(1, len(cs)) for cs, _ in grounded])
                 if grounded else float("nan"))
        print(f"{threshold:>10.2f}{len(grounded):>5}/{len(alerts):<4}{share:>28.2f}")
    print()
    print("Proxy relevance only: not the OWASP answer key, not a verdict-accuracy measure.")


if __name__ == "__main__":
    main()
