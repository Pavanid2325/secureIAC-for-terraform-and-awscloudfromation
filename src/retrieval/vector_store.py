"""Vector-store abstraction with a persistent local implementation."""

from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from src.models import DocumentChunk


@dataclass(frozen=True)
class SearchResult:
    chunk: DocumentChunk
    score: float


class VectorStore(Protocol):
    def create_collection(self) -> None:
        """Create or initialize the backing collection."""

    def upsert_chunks(self, vectors: list[tuple[DocumentChunk, list[float]]]) -> None:
        """Insert or update chunk vectors."""

    def similarity_search(
        self, query_embedding: list[float], top_k: int, filters: dict[str, str] | None = None
    ) -> list[SearchResult]:
        """Return the nearest chunks."""

    def delete_collection(self) -> None:
        """Delete indexed vectors."""

    def persist(self) -> None:
        """Persist the store if applicable."""


class LocalVectorStore:
    """JSON-backed cosine-similarity vector store for development and tests."""

    def __init__(self, path: str | Path = "reports/vector_store.json") -> None:
        self.path = Path(path)
        self._records: dict[str, dict[str, object]] = {}
        self.metadata = {}
        self._load()

    def create_collection(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def upsert_chunks(self, vectors: list[tuple[DocumentChunk, list[float]]]) -> None:
        self.create_collection()
        for chunk, vector in vectors:
            self._records[chunk.chunk_id] = {"chunk": asdict(chunk), "embedding": vector}

    def similarity_search(
        self, query_embedding: list[float], top_k: int, filters: dict[str, str] | None = None
    ) -> list[SearchResult]:
        results: list[SearchResult] = []
        for record in self._records.values():
            chunk_data = record["chunk"]
            if not isinstance(chunk_data, dict):
                continue
            chunk = DocumentChunk(**chunk_data)
            if filters and not _matches_filters(chunk, filters):
                continue
            embedding = record["embedding"]
            if not isinstance(embedding, list):
                continue
            results.append(SearchResult(chunk=chunk, score=cosine_similarity(query_embedding, embedding)))
        return sorted(results, key=lambda item: item.score, reverse=True)[:top_k]

    def delete_collection(self) -> None:
        self._records.clear()
        if self.path.exists():
            self.path.unlink()

    def persist(self) -> None:
        self.create_collection()
        self.path.write_text(json.dumps({"metadata": self.metadata, "records": self._records}, indent=2, sort_keys=True), encoding="utf-8")

    def _load(self) -> None:
        if not self.path.exists():
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            self._records = data.get("records", data)
            self.metadata = data.get("metadata", {})

    def configure(self, model, dimensions, chunking_version=None, corpus_version=None, reindex=False):
        expected = {"embedding_model": model, "dimensions": dimensions}
        if not reindex and self._records and any(self.metadata.get(k) != v for k, v in expected.items()):
            raise ValueError("Incompatible or legacy index; run ingest to reindex")
        if reindex:
            self._records.clear()
            self.metadata = {**expected, "chunking_version": chunking_version, "corpus_version": corpus_version}

    def hybrid_search(self, query, embedding, top_k, resource_type):
        candidates = []
        words = set(re.findall(r"[a-z0-9_:]+", query.lower()))
        for record in self._records.values():
            chunk = DocumentChunk(**record["chunk"])
            if chunk.resource_type and chunk.resource_type != resource_type:
                continue
            tokens = set(re.findall(r"[a-z0-9_:]+", chunk.text.lower()))
            keyword = len(words & tokens) / max(1, len(words))
            semantic = cosine_similarity(embedding, record["embedding"])
            candidates.append(SearchResult(chunk, 0.7 * semantic + 0.3 * keyword))
        return sorted(candidates, key=lambda x: (-x.score, x.chunk.chunk_id))[:top_k]


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return dot / (left_norm * right_norm)


def _matches_filters(chunk: DocumentChunk, filters: dict[str, str]) -> bool:
    values = {**chunk.metadata, "source": chunk.source, "title": chunk.title, "resource_type": chunk.resource_type}
    return all(str(values.get(key)) == str(value) for key, value in filters.items())
