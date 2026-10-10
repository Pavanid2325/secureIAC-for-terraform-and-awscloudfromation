"""Knowledge ingestion pipeline: load, clean, chunk, embed, and index."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.embeddings.titan_embeddings import EmbeddingClient
from src.knowledge.chunker import DocumentChunker
from src.knowledge.loader import KnowledgeLoader
from src.retrieval.vector_store import VectorStore


@dataclass(frozen=True)
class IngestionStats:
    documents_discovered: int
    documents_loaded: int
    chunks_indexed: int
    vector_store: str


class KnowledgeIngestionPipeline:
    """Runnable ingestion workflow used by CLI and CI."""

    def __init__(
        self,
        loader: KnowledgeLoader,
        chunker: DocumentChunker,
        embedder: EmbeddingClient,
        vector_store: VectorStore,
    ) -> None:
        self.loader = loader
        self.chunker = chunker
        self.embedder = embedder
        self.vector_store = vector_store

    def ingest(self, path: str | Path) -> IngestionStats:
        discovered = self.loader.discover(path)
        documents = [self.loader.load_path(item) for item in discovered]
        chunks = [chunk for document in documents for chunk in self.chunker.chunk(document)]
        embeddings = self.embedder.embed_texts([chunk.text for chunk in chunks]) if chunks else []
        self.vector_store.create_collection()
        self.vector_store.upsert_chunks(list(zip(chunks, embeddings)))
        self.vector_store.persist()
        return IngestionStats(
            documents_discovered=len(discovered),
            documents_loaded=len(documents),
            chunks_indexed=len(chunks),
            vector_store=type(self.vector_store).__name__,
        )
