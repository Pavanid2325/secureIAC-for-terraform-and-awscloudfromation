"""Deterministic security-document chunking."""

from __future__ import annotations

import hashlib
import re

from src.models import DocumentChunk, KnowledgeDocument


class DocumentChunker:
    """Chunk text deterministically with overlap and metadata preservation."""

    def __init__(self, chunk_size: int = 1200, overlap: int = 150) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if overlap < 0 or overlap >= chunk_size:
            raise ValueError("overlap must be non-negative and smaller than chunk_size")
        self.chunk_size = chunk_size
        self.overlap = overlap

    def chunk(self, document: KnowledgeDocument) -> list[DocumentChunk]:
        paragraphs = [part.strip() for part in re.split(r"\n\s*\n", document.text) if part.strip()]
        chunks: list[str] = []
        current = ""
        for paragraph in paragraphs or [document.text]:
            if len(paragraph) > self.chunk_size:
                if current:
                    chunks.append(current.strip())
                    current = ""
                chunks.extend(self._split_long_text(paragraph))
                continue
            candidate = f"{current}\n\n{paragraph}".strip() if current else paragraph
            if len(candidate) <= self.chunk_size:
                current = candidate
            else:
                chunks.append(current.strip())
                current = self._overlap_text(current) + paragraph
                if len(current) > self.chunk_size:
                    chunks.append(current[: self.chunk_size].strip())
                    current = self._overlap_text(current)
        if current.strip():
            chunks.append(current.strip())

        result: list[DocumentChunk] = []
        for index, text in enumerate(chunks):
            result.append(
                DocumentChunk(
                    chunk_id=_chunk_id(document.document_id, index, text),
                    text=text,
                    source=document.source,
                    title=document.title,
                    service=document.metadata.get("service"),
                    resource_type=document.metadata.get("resource_type"),
                    metadata={**document.metadata, "document_id": document.document_id, "chunk_index": index},
                )
            )
        return result

    def _split_long_text(self, text: str) -> list[str]:
        chunks: list[str] = []
        start = 0
        while start < len(text):
            end = min(start + self.chunk_size, len(text))
            if end < len(text):
                boundary = max(text.rfind(". ", start, end), text.rfind("\n", start, end))
                if boundary > start + int(self.chunk_size * 0.5):
                    end = boundary + 1
            chunks.append(text[start:end].strip())
            if end >= len(text):
                break
            start = max(end - self.overlap, start + 1)
        return chunks

    def _overlap_text(self, text: str) -> str:
        if self.overlap == 0 or not text:
            return ""
        return text[-self.overlap :].lstrip() + "\n\n"


def _chunk_id(document_id: str, index: int, text: str) -> str:
    digest = hashlib.sha256(f"{document_id}:{index}:{text}".encode("utf-8")).hexdigest()[:16]
    return f"chunk-{digest}"
