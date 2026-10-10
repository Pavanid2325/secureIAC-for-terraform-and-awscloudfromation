from src.knowledge.loader import KnowledgeLoader


def test_loader_reads_markdown_and_infers_metadata(tmp_path):
    path = tmp_path / "aws-s3.md"
    path.write_text("# S3 Security\n\nUse encryption.", encoding="utf-8")

    document = KnowledgeLoader().load_path(path)

    assert document.title == "S3 Security"
    assert document.metadata["service"] == "Amazon S3"
    assert "Use encryption" in document.text
