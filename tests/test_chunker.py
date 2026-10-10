from src.knowledge.chunker import DocumentChunker
from src.models import KnowledgeDocument


def test_chunking_is_deterministic_and_preserves_metadata():
    document = KnowledgeDocument(
        document_id="doc-1",
        text="Title\n\nS3 encryption guidance.\n\nSecurity group ingress guidance.",
        source="kb.md",
        title="Title",
        metadata={"service": "Amazon S3"},
    )
    chunker = DocumentChunker(chunk_size=35, overlap=5)

    first = chunker.chunk(document)
    second = chunker.chunk(document)

    assert [chunk.chunk_id for chunk in first] == [chunk.chunk_id for chunk in second]
    assert first[0].source == "kb.md"
    assert first[0].service == "Amazon S3"
    assert len(first) >= 2
