"""Integration tests using official SDK objects and local subprocesses, no network."""
import json
import sys
from types import SimpleNamespace as NS
from unittest.mock import Mock
import pytest
from src.llm.openai_provider import OpenAIProvider
from src.llm.chatgpt_auth import ChatGPTAuth
from src.scanning import bounded_run
from src.agents import ReportGenerationAgent
from src.models.validation import parse_analysis_response
from src.parser.normalizer import normalize_template
from test_phase2 import analysis_json, parsed_sg


def test_official_sdk_responses_transport():
    sdk = pytest.importorskip("openai", minversion="1.68.0")
    import httpx
    calls = []
    def handle(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200, json={"id": "resp_test", "object": "response", "created_at": 1,
            "status": "completed", "model": "model-snapshot", "output": [{"type": "message", "id": "msg_1",
            "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": "{}", "annotations": []}]}],
            "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5}}, headers={"x-request-id": "req-test"})
    client = sdk.OpenAI(api_key="fake-offline", max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(handle)))
    result = OpenAIProvider("test", client=client).generate("trusted", "data")
    assert result.request_id == "req-test" and result.usage["total_tokens"] == 5
    assert result.model == "model-snapshot" and calls[0]["store"] is False
    client.close()


def test_jwt_nonce_subject_signature_and_scopes():
    jwt = pytest.importorskip("jwt", minversion="2.8")
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa
    import time
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = "test-key"
    http = Mock()
    response = Mock()
    response.json.return_value = {"keys": [jwk]}
    http.get.return_value = response
    auth = ChatGPTAuth(store=Mock(), http=http)
    auth.discovery = lambda: {"jwks_uri": "https://auth.openai.com/jwks"}
    token = jwt.encode({"iss": "https://auth.openai.com", "aud": "client", "exp": time.time()+60,
                        "sub": "user", "nonce": "nonce"}, key, algorithm="RS256", headers={"kid": "test-key"})
    tokens = {"id_token": token, "scope": "chatgpt.tokens.use.direct resource.invoke", "token_type": "Bearer"}
    assert auth.validate_tokens(tokens, "client", "nonce")["sub"] == "user"
    with pytest.raises(Exception, match="nonce"):
        auth.validate_tokens(tokens, "client", "wrong")
    with pytest.raises(Exception, match="account_mismatch"):
        auth.validate_tokens(tokens, "client", subject="someone-else")
    with pytest.raises(Exception):
        auth.validate_tokens(tokens, "different-client")
    with pytest.raises(Exception, match="permission"):
        auth.validate_tokens({**tokens, "scope": "openid"}, "client", "nonce")


def test_real_subprocess_limits():
    with pytest.raises(TimeoutError):
        bounded_run([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.05)
    with pytest.raises(ValueError, match="output_limit"):
        bounded_run([sys.executable, "-c", "print('x'*100000)"], max_bytes=1000)


def test_report_escapes_injected_html_and_links():
    data = json.loads(analysis_json())
    data["findings"][0]["description"] = '<script>alert(1)</script> ![image](https://evil.example)'
    analysis = parse_analysis_response(json.dumps(data), "<memory>", {"Sg": "AWS::EC2::SecurityGroup"}, set(), parsed_sg().raw)
    report = ReportGenerationAgent().generate(analysis, normalize_template(parsed_sg()))
    assert "<script>" not in report and "![image]" not in report
    assert "&lt;script&gt;" in report


def test_ui_offline_smoke():
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_file("src/ui.py").run(timeout=15)
    assert not app.exception
    app.checkbox[0].uncheck()
    app.text_area[0].input('Resources: {Bucket: {Type: "AWS::S3::Bucket"}}')
    app.button[0].click().run(timeout=15)
    assert not app.exception
    assert app.session_state["analysis"]["analysis_metadata"]["mode"] == "deterministic-only"
