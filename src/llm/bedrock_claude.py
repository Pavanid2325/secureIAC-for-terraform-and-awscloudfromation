"""Mockable Amazon Bedrock Runtime adapter for Anthropic Claude."""

from __future__ import annotations

import json
import logging
import random
import time
from typing import Protocol
from src.llm.base import LLMError, ProviderResult

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    boto3 = None
    Config = None
    class BotoCoreError(Exception):
        pass
    class ClientError(BotoCoreError):
        pass

logger = logging.getLogger(__name__)


class LLMClient(Protocol):
    model_id: str

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate one text response."""


class BedrockClaudeClient:
    """Direct-runtime adapter that preserves the logical agent boundary."""

    def __init__(
        self,
        region_name: str,
        model_id: str,
        temperature: float = 0.0,
        max_tokens: int = 4096,
        max_retries: int = 2,
        timeout_seconds: int = 60,
        client: object | None = None,
    ) -> None:
        if not 0 <= temperature <= 1:
            raise ValueError("temperature must be between 0 and 1")
        if max_tokens <= 0:
            raise ValueError("max_tokens must be positive")
        if client is None and boto3 is None:
            raise ImportError("boto3 is required for BedrockClaudeClient")
        self.model_id = model_id
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_retries = max_retries
        config = Config(connect_timeout=timeout_seconds, read_timeout=timeout_seconds, retries={"total_max_attempts": 1}) if Config else None
        self.client = client or boto3.client(
            "bedrock-runtime", region_name=region_name, config=config
        )

    def generate(self, system_prompt: str, user_prompt: str) -> ProviderResult:
        started = time.perf_counter()
        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            }
        )
        for attempt in range(self.max_retries + 1):
            try:
                response = self.client.invoke_model(
                    modelId=self.model_id,
                    body=body,
                    contentType="application/json",
                    accept="application/json",
                )
                payload = json.loads(response["body"].read())
                if payload.get("stop_reason") in {"max_tokens", "refusal"}:
                    raise LLMError("incomplete")
                blocks = payload.get("content", [])
                text = "".join(
                    str(block.get("text", ""))
                    for block in blocks
                    if isinstance(block, dict) and block.get("type") == "text"
                ).strip()
                if not text:
                    raise LLMError("Claude response did not contain text")
                logger.info("Claude request completed model_id=%s", self.model_id)
                return ProviderResult(text, "bedrock", payload.get("model", self.model_id),
                    response.get("ResponseMetadata", {}).get("RequestId"), payload.get("usage", {}),
                    duration_ms=round((time.perf_counter() - started) * 1000))
            except (BotoCoreError, ClientError) as exc:
                if attempt >= self.max_retries or not _is_retryable(exc):
                    logger.error("Claude request failed model_id=%s error_type=%s", self.model_id, type(exc).__name__)
                    raise LLMError("bedrock_request_failed", _is_retryable(exc)) from None
                logger.warning("Retrying transient Claude request model_id=%s attempt=%s", self.model_id, attempt + 1)
                time.sleep(min(2**attempt + random.random(), 8))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise LLMError("Malformed Bedrock Claude response") from exc
        raise LLMError("Claude request failed")


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return code in {
            "ThrottlingException", "TooManyRequestsException", "ServiceUnavailableException",
            "InternalServerException", "ModelTimeoutException",
        }
    return isinstance(exc, BotoCoreError)
