from src.embeddings.titan_embeddings import LocalHashEmbeddingClient
from src.knowledge.chunker import DocumentChunker
from src.models import KnowledgeDocument
from src.parser.cloudformation_parser import CloudFormationParser
from src.parser.normalizer import normalize_template
from src.retrieval.query_builder import build_resource_descriptors
from src.retrieval.retriever import RetrievalAgent
from src.retrieval.vector_store import LocalVectorStore


def test_query_generation_uses_resource_context():
    parsed = CloudFormationParser().parse_text(
        """
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
""",
        suffix=".yaml",
    )
    descriptors = build_resource_descriptors(normalize_template(parsed))

    assert "security group" in descriptors[0].query
    assert "unrestricted" in descriptors[0].query


def test_retrieval_deduplicates_results(tmp_path):
    embedder = LocalHashEmbeddingClient()
    store = LocalVectorStore(tmp_path / "vectors.json")
    document = KnowledgeDocument(
        document_id="doc-1",
        text="Security groups should avoid unrestricted ingress from 0.0.0.0/0 on SSH port 22.",
        source="kb.md",
        title="Security Groups",
    )
    chunk = DocumentChunker().chunk(document)[0]
    vector = embedder.embed_text(chunk.text)
    store.upsert_chunks([(chunk, vector), (chunk, vector)])

    parsed = CloudFormationParser().parse_text(
        """
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
""",
        suffix=".yaml",
    )
    results = RetrievalAgent(embedder, store, top_k=5).retrieve(normalize_template(parsed))

    assert results[0].retrieved_context
    assert len({item.chunk_id for item in results[0].retrieved_context}) == len(
        results[0].retrieved_context
    )
