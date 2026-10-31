"""RAG retrieval agent for Phase 1."""

from __future__ import annotations

from dataclasses import asdict

from src.embeddings.titan_embeddings import EmbeddingClient
from src.models import RetrievalContext, RetrievalResult, TemplateSummary
from src.retrieval.query_builder import build_resource_descriptors
from src.retrieval.vector_store import VectorStore


class RetrievalAgent:
    """First logical agent: build resource queries and retrieve security context."""

    def __init__(self, embedder: EmbeddingClient, vector_store: VectorStore, top_k: int = 5) -> None:
        self.embedder = embedder
        self.vector_store = vector_store
        self.top_k = top_k
        if top_k <= 0:
            raise ValueError("top_k must be positive")

    def retrieve(self, template_summary: TemplateSummary) -> list[RetrievalResult]:
        results: list[RetrievalResult] = []
        for descriptor in build_resource_descriptors(template_summary):
            query_embedding = self.embedder.embed_text(descriptor.query)
            if hasattr(self.vector_store, "configure"):
                self.vector_store.configure(getattr(self.embedder, "model_id", type(self.embedder).__name__), len(query_embedding))
            if hasattr(self.vector_store, "hybrid_search"):
                matches = self.vector_store.hybrid_search(descriptor.query, query_embedding, self.top_k, descriptor.resource_type)
            else:
                matches = self.vector_store.similarity_search(query_embedding, self.top_k)
            seen: set[str] = set()
            contexts: list[RetrievalContext] = []
            for match in matches:
                if match.chunk.chunk_id in seen:
                    continue
                seen.add(match.chunk.chunk_id)
                contexts.append(
                    RetrievalContext(
                        chunk_id=match.chunk.chunk_id,
                        text=match.chunk.text,
                        source=match.chunk.source,
                        score=match.score,
                        metadata=match.chunk.metadata,
                    )
                )
            results.append(
                RetrievalResult(
                    resource=descriptor.resource,
                    resource_type=descriptor.resource_type,
                    query=descriptor.query,
                    retrieved_context=contexts,
                )
            )
        return results


def retrieval_results_to_dict(results: list[RetrievalResult]) -> list[dict[str, object]]:
    return [asdict(result) for result in results]
