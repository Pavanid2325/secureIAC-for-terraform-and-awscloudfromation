import json
import subprocess
import sys
from types import SimpleNamespace as NS
from unittest.mock import Mock
import pytest
from src.llm.openai_provider import OpenAIProvider
from src.llm.base import LLMError
from src.llm.factory import create_provider
from src.config import Settings
from src.agents.vulnerability_detection_agent import VulnerabilityDetectionAgent
from src.parser.cloudformation_parser import CloudFormationParser
from src.parser.normalizer import normalize_template
from src.models.validation import AnalysisValidationError, parse_analysis_response
from test_phase2 import analysis_json, parsed_sg


def response(**kwargs):
    return NS(**({"status": "completed", "output": [], "output_text": "{}", "usage": None,
                  "model": "exact-snapshot", "id": "response-1"} | kwargs))


def test_openai_shape_and_metadata():
    sdk = Mock()
    sdk.responses.create.return_value = response()
    result = OpenAIProvider("configured", client=sdk).generate("trusted", "untrusted")
    request = sdk.responses.create.call_args.kwargs
    assert request["store"] is False
    assert request["instructions"] == "trusted"
    assert request["text"]["format"]["strict"] is True
    assert "temperature" not in request and "reasoning" not in request
    assert result.model == "exact-snapshot"


@pytest.mark.parametrize("payload,code", [(response(status="incomplete"), "incomplete"),
    (response(output=[NS(content=[NS(type="refusal")])]), "refusal"),
    (response(output_text=""), "empty_output")])
def test_terminal_output_errors(payload, code):
    sdk = Mock()
    sdk.responses.create.return_value = payload
    with pytest.raises(LLMError, match=code):
        OpenAIProvider("test", client=sdk).generate("s", "u")


def test_selection_gates_and_no_fallback():
    assert create_provider(Settings()).model_id == "mock-v2"
    with pytest.raises(LLMError, match="live_calls_disabled"):
        create_provider(Settings(provider="openai"))
    with pytest.raises(LLMError, match="auth_mode_mismatch"):
        create_provider(Settings(provider="openai", auth_mode="chatgpt", live_calls=True))


def test_no_aws_import_for_local_openai():
    code = "import src.cli; import src.llm.openai_provider; import sys; assert 'boto3' not in sys.modules"
    subprocess.run([sys.executable, "-c", code], check=True, capture_output=True)


@pytest.mark.parametrize("change", [dict(observed_value_json='"10.0.0.0/24"'), dict(missing=True),
    dict(property_path="/Properties/Invented/Leaf"), dict(confidence=float("nan")),
    dict(related_resources=["Invented"]), dict(extra=True)])
def test_false_evidence_rejected(change):
    payload = json.loads(analysis_json())
    payload["findings"][0].update(change)
    with pytest.raises(AnalysisValidationError):
        parse_analysis_response(json.dumps(payload), "<memory>", {"Sg": "AWS::EC2::SecurityGroup"}, set(), parsed_sg().raw)


def test_retry_budget_and_input_limit(monkeypatch):
    monkeypatch.setattr("src.agents.vulnerability_detection_agent.time.sleep", lambda x: None)
    llm = Mock(model_id="test")
    llm.generate.side_effect = LLMError("transient", True)
    parsed = parsed_sg()
    with pytest.raises(LLMError):
        VulnerabilityDetectionAgent(llm, validation_retries=2).analyze(parsed, normalize_template(parsed), [])
    assert llm.generate.call_count == 3
    llm.reset_mock()
    with pytest.raises(LLMError, match="input_budget"):
        VulnerabilityDetectionAgent(llm, max_input_bytes=10).analyze(parsed, normalize_template(parsed), [])
    llm.generate.assert_not_called()


def test_quota_never_retried():
    sdk = Mock()
    exc = Exception("do not log this secret")
    exc.code = "insufficient_quota"
    exc.status_code = 429
    sdk.responses.create.side_effect = exc
    with pytest.raises(LLMError, match="quota") as caught:
        OpenAIProvider("test", client=sdk).generate("s", "u")
    assert "secret" not in str(caught.value)
    assert sdk.responses.create.call_count == 1
