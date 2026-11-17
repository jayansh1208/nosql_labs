from __future__ import annotations

import functools
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Sequence

import numpy as np

from backend.app.config import EMBEDDING_CACHE_DIR, EMBEDDING_DEVICE, EMBEDDING_MODEL, EMBEDDING_PROVIDER


class EmbeddingProvider(ABC):
    """Provider contract consumed by ingestion and retrieval, independent of storage."""

    @property
    @abstractmethod
    def model_name(self) -> str: ...

    @property
    @abstractmethod
    def dimension(self) -> int: ...

    @abstractmethod
    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class SentenceTransformerProvider(EmbeddingProvider):
    def __init__(self, model_name: str = EMBEDDING_MODEL, device: str = EMBEDDING_DEVICE,
                 cache_dir: str = EMBEDDING_CACHE_DIR):
        # This provider is PyTorch based; avoid loading an unrelated TensorFlow/Keras stack.
        os.environ["USE_TF"] = "0"
        from sentence_transformers import SentenceTransformer
        import torch

        if device.startswith("cuda") and not torch.cuda.is_available():
            raise RuntimeError("CUDA was requested for embeddings, but CUDA is not available.")
        cache_path = Path(cache_dir).expanduser()
        if not cache_path.is_absolute():
            cache_path = Path(__file__).resolve().parents[3] / cache_path
        cache_path.mkdir(parents=True, exist_ok=True)
        self._model_name = model_name
        self._model = SentenceTransformer(model_name, device=device, cache_folder=str(cache_path))
        self._dimension = int(self._model.get_sentence_embedding_dimension())
        if self._dimension <= 0:
            raise RuntimeError("Embedding model returned an invalid vector dimension.")

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimension(self) -> int:
        return self._dimension

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        vectors = np.asarray(self._model.encode(
            list(texts), convert_to_numpy=True, show_progress_bar=False, batch_size=32,
        ), dtype=np.float32)
        if vectors.ndim == 1:
            vectors = vectors.reshape(1, -1)
        if vectors.shape[1] != self.dimension:
            raise RuntimeError(f"Embedding dimension changed: expected {self.dimension}, got {vectors.shape[1]}.")
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        if np.any(norms == 0):
            raise RuntimeError("Embedding model returned a zero vector.")
        normalized = vectors / norms
        return normalized.astype(np.float32, copy=False).tolist()


@functools.lru_cache(maxsize=1)
def get_embedding_provider() -> EmbeddingProvider:
    if EMBEDDING_PROVIDER != "sentence_transformers":
        raise ValueError(f"Unsupported embedding provider: {EMBEDDING_PROVIDER}")
    # The provider and its model remain resident and are reused across requests.
    return SentenceTransformerProvider()
