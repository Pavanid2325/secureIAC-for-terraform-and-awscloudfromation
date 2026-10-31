"""Official SDK Responses adapter. No SDK retries or implicit billing fallback."""
import time

from src.llm.base import LLMError, ProviderResult
from src.models.findings_schema import ANALYSIS_SCHEMA


class OpenAIProvider:
    provider = "openai"

    def __init__(self, model_id, timeout=60, max_tokens=4096, client=None):
        self.model_id = model_id
        self.max_tokens = max_tokens
        if client is None:
            from openai import OpenAI
            client = OpenAI(timeout=timeout, max_retries=0, base_url="https://api.openai.com/v1")
        self.client = client

    def generate(self, system_prompt, user_prompt):
        started = time.perf_counter()
        try:
            response = self.client.responses.create(
                model=self.model_id, instructions=system_prompt,
                input=[{"role": "user", "content": user_prompt}], store=False,
                max_output_tokens=self.max_tokens,
                text={"format": {"type": "json_schema", "name": "secureiac_findings_v2",
                                 "strict": True, "schema": ANALYSIS_SCHEMA}},
            )
        except Exception as exc:
            raise classify_error(exc) from None
        return completed_result(response, self.provider, started)


def classify_error(exc):
    status = getattr(exc, "status_code", None)
    code = getattr(exc, "code", None)
    if code in {"insufficient_quota", "usage_limit_reached"}:
        return LLMError("quota")
    if status in {401, 403}:
        return LLMError("authentication")
    if status == 429:
        return LLMError("rate_limit", True)
    if status in {408, 409, 500, 502, 503, 504} or type(exc).__name__ in {"APITimeoutError", "APIConnectionError"}:
        return LLMError("transient", True)
    return LLMError("request_rejected")


def completed_result(response, provider, started):
    if response.status != "completed":
        raise LLMError("incomplete" if response.status == "incomplete" else "failed")
    for item in response.output:
        for block in getattr(item, "content", []):
            if getattr(block, "type", None) == "refusal":
                raise LLMError("refusal")
    if not response.output_text:
        raise LLMError("empty_output")
    usage = response.usage.model_dump() if response.usage else {}
    return ProviderResult(response.output_text, provider, response.model,
                          getattr(response, "_request_id", None) or response.id,
                          usage, duration_ms=round((time.perf_counter()-started)*1000))
