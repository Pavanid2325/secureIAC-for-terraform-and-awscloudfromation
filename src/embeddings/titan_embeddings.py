"""Amazon Titan Text Embeddings V2 client for Bedrock Runtime."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import time
from typing import Protocol

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover - exercised only in minimal environments
    boto3 = None
    BotoCoreError = Exception
    ClientError = Exception

logger = logging.getLogger(__name__)


class EmbeddingClient(Protocol):
    """Interface used by ingestion and retrieval components."""

    def embed_text(self, text: str) -> list[float]:
        """Embed one text string."""

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Embed multiple text strings at application level."""


class TitanEmbeddingClient:
    """Bedrock Runtime client for Amazon Titan Text Embeddings V2."""

    def __init__(
        self,
        region_name: str,
        model_id: str = "amazon.titan-embed-text-v2:0",
        max_retries: int = 3,
        client: object | None = None,
    ) -> None:
        self.model_id = model_id
        self.max_retries = max_retries
        if client is None and boto3 is None:
            raise ImportError("boto3 is required for TitanEmbeddingClient")
        self.client = client or boto3.client("bedrock-runtime", region_name=region_name)

    def embed_text(self, text: str) -> list[float]:
        if not text.strip():
            raise ValueError("Cannot embed empty text")
        body = json.dumps({"inputText": text})
        for attempt in range(self.max_retries + 1):
            try:
                response = self.client.invoke_model(
                    modelId=self.model_id,
                    body=body,
                    contentType="application/json",
                    accept="application/json",
                )
                payload = json.loads(response["body"].read())
                vector = payload.get("embedding")
                return _validate_vector(vector)
            except (BotoCoreError, ClientError) as exc:
                if attempt >= self.max_retries:
                    logger.error("Titan embedding request failed after retries: %s", exc)
                    raise
                if _is_retryable(exc):
                    sleep_for = min(2**attempt + random.random(), 8)
                    logger.warning("Retrying Titan embedding request after transient failure")
                    time.sleep(sleep_for)
                    continue
                logger.error("Titan embedding request failed: %s", exc)
                raise

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [self.embed_text(text) for text in texts]


class LocalHashEmbeddingClient:
    """Deterministic local embedding client for tests and offline development."""

    def __init__(self, dimensions: int = 64) -> None:
        self.dimensions = dimensions

    def embed_text(self, text: str) -> list[float]:
        if not text.strip():
            raise ValueError("Cannot embed empty text")
        values = [0.0] * self.dimensions
        for token in text.lower().split():
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:2], "big") % self.dimensions
            sign = 1.0 if digest[2] % 2 == 0 else -1.0
            values[index] += sign
        norm = math.sqrt(sum(value * value for value in values)) or 1.0
        return [value / norm for value in values]

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [self.embed_text(text) for text in texts]


def _validate_vector(vector: object) -> list[float]:
    if not isinstance(vector, list) or not vector:
        raise ValueError("Titan response did not contain a non-empty embedding vector")
    parsed = [float(value) for value in vector]
    if not all(math.isfinite(value) for value in parsed):
        raise ValueError("Titan embedding vector contains non-finite values")
    return parsed


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "")
        return code in {
            "ThrottlingException",
            "TooManyRequestsException",
            "ServiceUnavailableException",
            "InternalServerException",
        }
    return isinstance(exc, BotoCoreError)
