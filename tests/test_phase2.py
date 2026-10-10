import io
import json
import re
from dataclasses import replace

import pytest
import yaml

from src.agents.detection_prompt import SYSTEM_PROMPT, build_detection_prompt, citation_id
from src.agents.report_generation_agent import ReportGenerationAgent
from src.agents.vulnerability_detection_agent import VulnerabilityDetectionAgent
from src.cli import main
from src.llm.bedrock_claude import BedrockClaudeClient
from src.models import RetrievalContext, RetrievalResult
from src.models.validation import AnalysisValidationError, parse_analysis_response
from src.parser.cloudformation_parser import CloudFormationParser
from src.parser.normalizer import normalize_template
from src.workflow import SecurityAnalysisWorkflow


class FakeLLM:
    model_id = "mock-claude-sonnet"

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate(self, system_prompt, user_prompt):
        self.calls.append((system_prompt, user_prompt))
        return self.responses.pop(0)


class StaticRetrieval:
    def __init__(self, results):
        self.results = results

    def retrieve(self, summary):
        return self.results


def analysis_json(template_name="<memory>", resource="Sg", resource_type="AWS::EC2::SecurityGroup", source=None):
    sources = [source] if source else []
    return json.dumps(
        {
            "template_name": template_name,
            "resources_analyzed": 1,
            "findings": [
                {
                    "finding_id": "F-001",
                    "resource_logical_id": resource,
                    "resource_type": resource_type,
                    "title": "Unrestricted SSH ingress",
                    "description": "SSH is open to the internet.",
                    "severity": "HIGH",
                    "evidence": "CidrIp 0.0.0.0/0 permits TCP port 22.",
                    "security_impact": "Internet hosts can attempt remote access.",
                    "retrieved_guidance": ["Restrict administrative ingress."],
                    "guidance_sources": sources,
                    "remediation": {
                        "explanation": "Limit SSH to an approved network.",
                        "recommended_change": "Replace the public CIDR.",
                        "cloudformation_snippet": "CidrIp: 10.0.0.0/24",
                        "assumptions": ["10.0.0.0/24 is an example trusted range."],
                    },
                    "confidence": 0.98,
                    "related_resources": [],
                }
            ],
            "summary": "One high-severity finding.",
        }
    )


def parsed_sg(source="<memory>"):
    return CloudFormationParser().parse_text(
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
        source=source,
    )


def retrieval():
    context = RetrievalContext("chunk-1", "Restrict SSH ingress.", "kb/security.md", 0.9)
    return [RetrievalResult("Sg", "AWS::EC2::SecurityGroup", "ssh security", [context])]


def test_bedrock_client_builds_anthropic_request():
    class Runtime:
        def __init__(self):
            self.kwargs = None

        def invoke_model(self, **kwargs):
            self.kwargs = kwargs
            return {"body": io.BytesIO(json.dumps({"content": [{"type": "text", "text": "{}"}]}).encode())}

    runtime = Runtime()
    client = BedrockClaudeClient("us-east-1", "profile/model", client=runtime, temperature=0.2)
    assert client.generate("system", "user") == "{}"
    body = json.loads(runtime.kwargs["body"])
    assert runtime.kwargs["modelId"] == "profile/model"
    assert body["system"] == "system"
    assert body["messages"][0]["content"] == "user"


def test_prompt_separates_untrusted_data_and_cross_resource_context():
    parsed = CloudFormationParser().parse_text(
        """
Resources:
  Role:
    Type: AWS::IAM::Role
  Policy:
    Type: AWS::IAM::Policy
    DependsOn: Role
    Properties:
      Roles: [!Ref Role]
      PolicyDocument: {Statement: []}
"""
    )
    prompt = build_detection_prompt(parsed, normalize_template(parsed), [])
    assert all(f"<{name}>" in prompt for name in ["TEMPLATE", "NORMALIZED_CONTEXT", "RESOURCE_CONTEXT", "SECURITY_GUIDANCE", "INSTRUCTIONS"])
    assert '"DependsOn": [' in prompt
    assert '"Ref": [' in prompt
    assert "untrusted DATA" in SYSTEM_PROMPT


def test_schema_rejects_hallucinated_resource_and_source():
    source = citation_id("chunk-1", "kb/security.md")
    with pytest.raises(AnalysisValidationError, match="unknown resource"):
        parse_analysis_response(analysis_json(resource="Invented", source=source), "<memory>", {"Sg": "AWS::EC2::SecurityGroup"}, {source})
    with pytest.raises(AnalysisValidationError, match="was not retrieved"):
        parse_analysis_response(analysis_json(source="invented-source"), "<memory>", {"Sg": "AWS::EC2::SecurityGroup"}, {source})


def test_detection_agent_retries_malformed_output_and_preserves_citation():
    source = citation_id("chunk-1", "kb/security.md")
    llm = FakeLLM(["not-json", analysis_json(source=source)])
    parsed = parsed_sg()
    result = VulnerabilityDetectionAgent(llm).analyze(parsed, normalize_template(parsed), retrieval())
    assert len(llm.calls) == 2
    assert result.findings[0].guidance_sources == [source]


def test_detection_agent_handles_empty_findings():
    response = json.dumps({"template_name": "<memory>", "resources_analyzed": 1, "findings": [], "summary": "No findings."})
    parsed = parsed_sg()
    result = VulnerabilityDetectionAgent(FakeLLM([response])).analyze(parsed, normalize_template(parsed), [])
    assert result.findings == []


def test_report_formats_only_validated_findings():
    source = citation_id("chunk-1", "kb/security.md")
    analysis = parse_analysis_response(analysis_json(source=source), "<memory>", {"Sg": "AWS::EC2::SecurityGroup"}, {source})
    report = ReportGenerationAgent().generate(analysis, normalize_template(parsed_sg()))
    assert "### [HIGH] Unrestricted SSH ingress" in report
    assert source in report
    assert "CidrIp: 10.0.0.0/24" in report


def test_multiple_findings_are_validated_and_reported():
    payload = json.loads(analysis_json())
    second = dict(payload["findings"][0])
    second["finding_id"] = "F-002"
    second["title"] = "Second finding"
    payload["findings"].append(second)
    analysis = parse_analysis_response(json.dumps(payload), "<memory>", {"Sg": "AWS::EC2::SecurityGroup"}, set())
    report = ReportGenerationAgent().generate(analysis, normalize_template(parsed_sg()))
    assert len(analysis.findings) == 2
    assert "Total findings: 2" in report


def test_workflow_runs_complete_pipeline_and_writes_report(tmp_path):
    template = tmp_path / "template.yaml"
    template.write_text(yaml.safe_dump(parsed_sg().raw), encoding="utf-8")
    source = citation_id("chunk-1", "kb/security.md")
    detection = VulnerabilityDetectionAgent(FakeLLM([analysis_json(str(template), source=source)]))
    workflow = SecurityAnalysisWorkflow(StaticRetrieval(retrieval()), detection, reports_dir=tmp_path / "reports")
    result = workflow.analyze(template)
    assert result.report_path.exists()
    assert result.analysis.analysis_metadata["retrieved_chunks"] == 1
    assert result.analysis.analysis_metadata["model_id"] == "mock-claude-sonnet"


@pytest.mark.parametrize(
    "path,resource,resource_type,title",
    [
        ("examples/vulnerable/open_ssh.yaml", "WebSecurityGroup", "AWS::EC2::SecurityGroup", "Open SSH"),
        ("examples/vulnerable/rds_unencrypted.json", "Database", "AWS::RDS::DBInstance", "Unencrypted RDS"),
        ("examples/vulnerable/iam_wildcard.yaml", "AppRole", "AWS::IAM::Role", "Wildcard IAM"),
        ("examples/vulnerable/s3_bucket_weak.yaml", "DataBucket", "AWS::S3::Bucket", "Weak S3 controls"),
    ],
)
def test_example_templates_accept_correct_mocked_findings(path, resource, resource_type, title):
    parsed = CloudFormationParser().parse_file(path)
    payload = json.loads(analysis_json(parsed.path, resource, resource_type))
    payload["findings"][0]["title"] = title
    result = VulnerabilityDetectionAgent(FakeLLM([json.dumps(payload)])).analyze(parsed, normalize_template(parsed), [])
    assert result.findings[0].resource_logical_id == resource


def test_secure_example_accepts_empty_findings():
    parsed = CloudFormationParser().parse_file("examples/secure/secure_baseline.yaml")
    response = json.dumps({"template_name": parsed.path, "resources_analyzed": len(parsed.resources), "findings": [], "summary": "No validated findings."})
    result = VulnerabilityDetectionAgent(FakeLLM([response])).analyze(parsed, normalize_template(parsed), [])
    assert result.findings == []


def test_cli_analyze_command_with_mocked_claude(monkeypatch, tmp_path, capsys):
    class PromptAwareLLM:
        model_id = "mock-cli"

        def __init__(self, **kwargs):
            pass

        def generate(self, system_prompt, user_prompt):
            name = json.loads(re.search(r'"template_name":("(?:[^"\\]|\\.)*")', user_prompt).group(1))
            count = int(re.search(r'"resources_analyzed":(\d+)', user_prompt).group(1))
            return json.dumps({"template_name": name, "resources_analyzed": count, "findings": [], "summary": "No findings."})

    monkeypatch.setattr("src.cli.BedrockClaudeClient", PromptAwareLLM)
    monkeypatch.setenv("REPORTS_PATH", str(tmp_path / "reports"))
    monkeypatch.setenv("LOCAL_VECTOR_STORE_PATH", str(tmp_path / "vectors.json"))
    code = main(["analyze", "examples/secure/secure_baseline.yaml", "--local-embeddings"])
    assert code == 0
    assert "Analysis complete" in capsys.readouterr().out
