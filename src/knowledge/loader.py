"""Local knowledge-base document loader."""

from __future__ import annotations

import hashlib
import html
import json
import logging
import re
from pathlib import Path

from src.knowledge.metadata import infer_metadata
from src.models import KnowledgeDocument

logger = logging.getLogger(__name__)


class KnowledgeLoadError(ValueError):
    """Raised when a knowledge document cannot be loaded."""


class KnowledgeLoader:
    """Load local security documents without fabricating source content."""

    SUPPORTED_SUFFIXES = {".txt", ".md", ".json", ".html", ".htm", ".pdf"}

    def discover(self, root: str | Path) -> list[Path]:
        base = Path(root)
        if not base.exists():
            raise KnowledgeLoadError(f"Knowledge path does not exist: {base}")
        if base.is_file():
            return [base] if base.suffix.lower() in self.SUPPORTED_SUFFIXES else []
        return sorted(
            path
            for path in base.rglob("*")
            if path.is_file() and path.suffix.lower() in self.SUPPORTED_SUFFIXES
        )

    def load_path(self, path: str | Path) -> KnowledgeDocument:
        doc_path = Path(path)
        suffix = doc_path.suffix.lower()
        if suffix not in self.SUPPORTED_SUFFIXES:
            raise KnowledgeLoadError(f"Unsupported knowledge document type: {suffix}")
        text = self._read(doc_path, suffix)
        cleaned = clean_text(text)
        title = _extract_title(cleaned, doc_path)
        metadata = infer_metadata(doc_path, cleaned)
        return KnowledgeDocument(
            document_id=_document_id(doc_path, cleaned),
            text=cleaned,
            source=str(doc_path),
            title=title,
            metadata=metadata,
        )

    def load_all(self, root: str | Path) -> list[KnowledgeDocument]:
        documents: list[KnowledgeDocument] = []
        for path in self.discover(root):
            try:
                documents.append(self.load_path(path))
            except Exception as exc:
                logger.warning("Skipping %s: %s", path, exc)
        return documents

    def _read(self, path: Path, suffix: str) -> str:
        if suffix == ".pdf":
            try:
                from pypdf import PdfReader
            except ImportError as exc:
                raise KnowledgeLoadError("PDF support requires pypdf") from exc
            reader = PdfReader(str(path))
            return "\n".join(page.extract_text() or "" for page in reader.pages)
        raw = path.read_text(encoding="utf-8")
        if suffix == ".json":
            data = json.loads(raw)
            return json.dumps(data, indent=2, sort_keys=True)
        if suffix in {".html", ".htm"}:
            return re.sub(r"<[^>]+>", " ", html.unescape(raw))
        return raw


def clean_text(text: str) -> str:
    """Normalize whitespace while preserving paragraph boundaries."""

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"[ \t]+", " ", normalized)
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    return normalized.strip()


def _extract_title(text: str, path: Path) -> str:
    for line in text.splitlines():
        stripped = line.strip(" #\t")
        if stripped:
            return stripped[:120]
    return path.stem


def _document_id(path: Path, text: str) -> str:
    digest = hashlib.sha256(f"{path.as_posix()}\n{text}".encode("utf-8")).hexdigest()[:16]
    return f"doc-{digest}"
