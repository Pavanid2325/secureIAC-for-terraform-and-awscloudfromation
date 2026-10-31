import json
from datetime import date
from unittest.mock import Mock
import pytest
from src.parser.cloudformation_parser import CloudFormationParser, CloudFormationParseError
from src.policies import load_policies, evaluate_policies
from src.scanning import Scanner, ScanResult, bounded_run
from src.remediation import remediate
from src.cli import main
from src.retrieval.vector_store import LocalVectorStore
from src.embeddings.titan_embeddings import LocalHashEmbeddingClient
from src.knowledge.ingestion import KnowledgeIngestionPipeline
from src.knowledge.loader import KnowledgeLoader
from src.knowledge.chunker import DocumentChunker


@pytest.mark.parametrize("text", ["x: &x [*x]", "Resources: {}\nResources: {}", "x: .nan", "x: " + "["*70 + "0" + "]"*70])
def test_parser_complexity_and_ambiguity(text):
    with pytest.raises(CloudFormationParseError):
        CloudFormationParser().parse_text(text)


def test_policy_fail_unknown_and_exception():
    doc, _ = load_policies("policies/example.yaml")
    parsed = CloudFormationParser().parse_file("examples/vulnerable/rds_unencrypted.json")
    results = evaluate_policies(parsed, doc, "production")
    assert next(r for r in results if r["policy_id"] == "ORG-RDS-ENCRYPTION")["outcome"] == "failed"
    assert next(r for r in results if r["policy_id"] == "ORG-REGION")["outcome"] == "unknown"
    doc["policies"][0]["exceptions"] = [{"resource": "Database", "reason": "approved test", "expires": "2030-01-01"}]
    assert evaluate_policies(parsed, doc, "production", today=date(2026,1,1))[0]["outcome"] == "excepted"
    assert evaluate_policies(parsed, doc, "production", today=date(2031,1,1))[0]["outcome"] == "failed"
    unresolved = CloudFormationParser().parse_text('Resources: {DB: {Type: "AWS::RDS::DBInstance", Properties: {StorageEncrypted: !Ref Flag}}}')
    assert evaluate_policies(unresolved, doc, "production")[0]["outcome"] == "unknown"


def test_scanner_missing_timeout_and_shape(monkeypatch, tmp_path):
    monkeypatch.setattr("src.scanning.shutil.which", lambda name: None)
    assert Scanner().scan("anything").status == "unavailable"
    monkeypatch.setattr("src.scanning.shutil.which", lambda name: "checkov")
    source = tmp_path / "input.yaml"
    source.write_text("Resources: {}")
    runner = Mock(side_effect=TimeoutError())
    assert Scanner(runner=runner).scan(source).error == "timeout"
    runner = Mock(return_value=(1, json.dumps({"results": {"failed_checks": [{"check_id": "CKV_1", "resource": "DB", "check_name": "Encryption"}]}})))
    result = Scanner(runner=runner).scan(source)
    assert result.status == "completed" and result.findings[0]["outcome"] == "failed"
    assert "--skip-download" in runner.call_args.args[0]


def test_candidate_preserves_input_and_rejects_unrelated(tmp_path):
    source = tmp_path / "input.json"
    source.write_text('{"Resources":{"DB":{"Type":"AWS::RDS::DBInstance","Properties":{"StorageEncrypted":false}}}}')
    before = source.read_bytes()
    path = "/Resources/DB/Properties/StorageEncrypted"
    patch = tmp_path / "patch.json"
    patch.write_text(json.dumps([{"op": "replace", "path": path, "value": True}]))
    scanner = Mock()
    scanner.scan.return_value = ScanResult("checkov", "test", "completed")
    linter = Mock()
    linter.scan.return_value = ScanResult("cfn-lint", "test", "completed")
    output = tmp_path / "reports" / "candidate.json"
    with pytest.raises(ValueError, match="Unrelated"):
        remediate(source, patch, output, [], output.parent)
    result, diff = remediate(source, patch, output, [path], output.parent, scanner=scanner, linter=linter)
    assert result["status"] == "passed_checks" and "StorageEncrypted" in diff
    assert source.read_bytes() == before
    assert json.loads(output.read_text())["Resources"]["DB"]["Properties"]["StorageEncrypted"] is True
    with pytest.raises(ValueError):
        remediate(source, patch, source, [path], tmp_path)


def test_deterministic_cli_and_path_traversal(monkeypatch, tmp_path):
    monkeypatch.setenv("REPORTS_PATH", str(tmp_path / "reports"))
    assert main(["analyze", "examples/vulnerable/rds_unencrypted.json", "--deterministic-only", "--policy", "policies/example.yaml"]) == 0
    report = json.loads(next((tmp_path / "reports").glob("*.json")).read_text())
    assert any(r["outcome"] == "failed" for r in report["analysis_metadata"]["policies"])
    assert main(["analyze", "examples/vulnerable/open_ssh.yaml", "--deterministic-only", "--output", "../../escape.md"]) == 1


def test_ingestion_index_manifest_and_incompatibility(tmp_path):
    store = LocalVectorStore(tmp_path / "index.json")
    pipeline = KnowledgeIngestionPipeline(KnowledgeLoader(), DocumentChunker(), LocalHashEmbeddingClient(), store)
    pipeline.ingest("knowledge_base")
    assert store.metadata["dimensions"] == 64 and store.metadata["corpus_version"]
    with pytest.raises(ValueError, match="reindex"):
        store.configure("different-model", 64)


def test_failed_llm_report_retains_policy_findings(tmp_path):
    from src.workflow import SecurityAnalysisWorkflow
    from src.agents import VulnerabilityDetectionAgent
    from src.llm.base import LLMError
    llm = Mock(model_id="test")
    llm.generate.side_effect = LLMError("quota")
    workflow = SecurityAnalysisWorkflow(None, VulnerabilityDetectionAgent(llm), reports_dir=tmp_path,
        policy_path="policies/example.yaml")
    result = workflow.analyze("examples/vulnerable/rds_unencrypted.json")
    assert result.analysis.analysis_metadata["status"] == "failed"
    assert any(r["outcome"] == "failed" for r in result.analysis.analysis_metadata["policies"])
    assert "Contextual analysis failed" in result.report_markdown


def test_all_policy_types_and_trusted_environment():
    doc, _ = load_policies("policies/example.yaml")
    parsed = CloudFormationParser().parse_text('''
Metadata: {Environment: development}
Resources:
  DB:
    Type: AWS::RDS::DBInstance
    Properties: {StorageEncrypted: false, PubliclyAccessible: true, Tags: []}
  Bucket:
    Type: AWS::S3::Bucket
    Properties: {LoggingConfiguration: {DestinationBucketName: other}, Tags: []}
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress: [{IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0}]
''')
    results = evaluate_policies(parsed, doc, "production", "unapproved-region")
    assert {r["policy_id"] for r in results if r["outcome"] == "failed"} == {p["id"] for p in doc["policies"]}
