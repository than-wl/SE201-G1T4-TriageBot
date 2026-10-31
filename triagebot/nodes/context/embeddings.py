"""Local embeddings for the knowledge base (fastembed: ONNX, no server, no network at query time).

Only semantic retrieval imports fastembed, so the default "map" mode and the
offline tests never load a model. Chunk vectors are stored by vector_store.py.
"""

import numpy as np

from triagebot import config


def chunk_text(chunk: dict) -> str:
    """What gets embedded for a chunk: its heading path, then its body."""
    return f"{chunk['section']}\n{chunk['text']}"


def _unit_rows(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    return matrix / np.where(norms == 0, 1.0, norms)


class FastEmbedder:
    """Wraps a fastembed text model; query text gets the model's retrieval prefix."""

    def __init__(self, model_name: str | None = None) -> None:
        from fastembed import TextEmbedding  # imported lazily: only semantic mode needs it

        self._model = TextEmbedding(model_name or config.EMBEDDING_MODEL)

    def embed_documents(self, texts: list[str]) -> np.ndarray:
        return _unit_rows(np.array(list(self._model.embed(texts)), dtype=np.float32))

    def embed_query(self, text: str) -> np.ndarray:
        prefixed = config.EMBEDDING_QUERY_PREFIX + text
        return _unit_rows(np.array(list(self._model.embed([prefixed])), dtype=np.float32))[0]
