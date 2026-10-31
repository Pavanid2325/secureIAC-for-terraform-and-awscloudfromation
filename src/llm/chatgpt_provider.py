"""Local ChatGPT-plan inference via the documented public Responses endpoint."""
import time
from src.llm.base import LLMError
from src.llm.openai_provider import completed_result, classify_error
from src.models.findings_schema import ANALYSIS_SCHEMA


class ChatGPTProvider:
    def __init__(self, model_id, timeout=60, max_output_bytes=100_000, auth=None, client_factory=None):
        from src.llm.chatgpt_auth import ChatGPTAuth
        if client_factory is None:
            from openai import OpenAI
            client_factory = OpenAI
        self.model_id = model_id
        self.auth = auth or ChatGPTAuth()
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self.client_factory = client_factory

    def models(self, token):
        response = self.auth.http.get("https://api.openai.com/v1/models", headers={"Authorization": "Bearer " + token})
        if response.status_code in {401, 403}:
            raise LLMError("authentication")
        if response.status_code == 429:
            raise LLMError("usage_limit")
        if response.status_code != 200:
            raise LLMError("model_discovery_failed")
        return [m for m in response.json()["models"] if m.get("visibility") == "list"]

    def generate(self, system_prompt, user_prompt):
        started = time.perf_counter()
        token = self.auth.access_token()
        if self.model_id not in {m["slug"] for m in self.models(token)}:
            raise LLMError("model_not_available_for_account")
        client = self.client_factory(api_key=token, base_url="https://api.openai.com/v1", timeout=self.timeout, max_retries=0)
        completed = None
        output_bytes = 0
        try:
            with client.responses.create(model=self.model_id, store=False, stream=True,
                  instructions=system_prompt, input=[{"role": "user", "content": user_prompt}],
                  text={"format": {"type": "json_schema", "name": "secureiac_findings_v2",
                                   "strict": True, "schema": ANALYSIS_SCHEMA}}) as stream:
                for event in stream:
                    if time.perf_counter() - started > self.timeout:
                        raise LLMError("stream_timeout")
                    if event.type == "response.output_text.delta":
                        output_bytes += len(event.delta.encode())
                        if output_bytes > self.max_output_bytes:
                            raise LLMError("output_budget_exceeded")
                    if event.type in {"response.failed", "response.incomplete", "error"}:
                        raise LLMError("stream_failed")
                    if event.type == "response.refusal.delta":
                        raise LLMError("refusal")
                    if event.type == "response.completed":
                        completed = event.response
            if completed is None:
                raise LLMError("interrupted_stream")
            return completed_result(completed, "chatgpt", started)
        except LLMError:
            raise
        except Exception as exc:
            raise classify_error(exc) from None
        finally:
            client.close()
