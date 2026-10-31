"""Centralized runtime configuration for the IaC security agent."""

from __future__ import annotations

import logging
import os
import math
from dataclasses import dataclass
from pathlib import Path


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be non-negative")
    return parsed


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc


def _bool_env(name, default):
    value = os.getenv(name, str(default)).lower()
    if value not in {"true", "false", "1", "0", "yes", "no"}:
        raise ValueError(f"{name} must be true or false")
    return value in {"true", "1", "yes"}


@dataclass(frozen=True)
class Settings:
    """Environment-driven application settings."""

    aws_region: str = "us-east-1"
    bedrock_llm_model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    bedrock_embedding_model_id: str = "amazon.titan-embed-text-v2:0"
    vector_store_type: str = "local"
    top_k_retrieval: int = 5
    knowledge_base_path: Path = Path("knowledge_base")
    log_level: str = "INFO"
    chunk_size: int = 1200
    chunk_overlap: int = 150
    local_vector_store_path: Path = Path("reports/vector_store.json")
    use_local_embeddings: bool = True
    llm_temperature: float = 0.0
    llm_max_tokens: int = 4096
    llm_max_retries: int = 2
    max_template_bytes: int = 1_048_576
    reports_path: Path = Path("reports")
    provider: str = "mock"
    auth_mode: str = "api_key"
    openai_model: str = "gpt-4o-mini-2024-07-18"
    api_timeout: int = 60
    max_attempts: int = 2
    max_input_bytes: int = 200_000
    max_output_bytes: int = 100_000
    live_calls: bool = False
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_backend: str = "semantic"
    scanner_timeout: int = 60
    policy_path: Path | None = None
    environment: str = "production"

    def __post_init__(self):
        if self.provider not in {"mock", "openai", "bedrock", "chatgpt"}:
            raise ValueError("Unsupported provider")
        if self.auth_mode not in {"api_key", "chatgpt"}:
            raise ValueError("Unsupported auth mode")
        if self.embedding_backend not in {"semantic", "hash", "titan"}:
            raise ValueError("Unsupported embedding backend")
        for name in ("api_timeout", "max_attempts", "max_input_bytes", "max_output_bytes", "llm_max_tokens", "top_k_retrieval", "max_template_bytes", "scanner_timeout", "chunk_size"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.max_attempts > 5 or not 0 <= self.chunk_overlap < self.chunk_size:
            raise ValueError("Invalid attempts or chunk overlap")
        if not self.openai_model.strip() or not self.embedding_model.strip() or not self.environment.strip():
            raise ValueError("Model and environment values must not be empty")
        if not math.isfinite(self.llm_temperature) or not 0 <= self.llm_temperature <= 1:
            raise ValueError("Invalid temperature")

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from process environment variables."""

        return cls(
            provider=os.getenv("LLM_PROVIDER", "mock"),
            auth_mode=os.getenv("AUTH_MODE", "api_key"),
            openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini-2024-07-18"),
            api_timeout=_int_env("API_TIMEOUT", 60),
            max_attempts=_int_env("MAX_ATTEMPTS", 2),
            max_input_bytes=_int_env("MAX_INPUT_BYTES", 200_000),
            max_output_bytes=_int_env("MAX_OUTPUT_BYTES", 100_000),
            live_calls=_bool_env("ENABLE_LIVE_CALLS", False),
            embedding_model=os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
            embedding_backend=os.getenv("EMBEDDING_BACKEND", "semantic"),
            scanner_timeout=_int_env("SCANNER_TIMEOUT", 60),
            policy_path=Path(os.environ["POLICY_PATH"]) if os.getenv("POLICY_PATH") else None,
            environment=os.getenv("DEPLOYMENT_ENVIRONMENT", "production"),
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            bedrock_llm_model_id=os.getenv(
                "BEDROCK_LLM_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0"
            ),
            bedrock_embedding_model_id=os.getenv(
                "BEDROCK_EMBEDDING_MODEL_ID", "amazon.titan-embed-text-v2:0"
            ),
            vector_store_type=os.getenv("VECTOR_STORE_TYPE", "local"),
            top_k_retrieval=_int_env("TOP_K_RETRIEVAL", 5),
            knowledge_base_path=Path(os.getenv("KNOWLEDGE_BASE_PATH", "knowledge_base")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            chunk_size=_int_env("CHUNK_SIZE", 1200),
            chunk_overlap=_int_env("CHUNK_OVERLAP", 150),
            local_vector_store_path=Path(
                os.getenv("LOCAL_VECTOR_STORE_PATH", "reports/vector_store.json")
            ),
            use_local_embeddings=os.getenv("USE_LOCAL_EMBEDDINGS", "true").lower()
            in {"1", "true", "yes"},
            llm_temperature=_float_env("LLM_TEMPERATURE", 0.0),
            llm_max_tokens=_int_env("LLM_MAX_TOKENS", 4096),
            llm_max_retries=_int_env("LLM_MAX_RETRIES", 2),
            max_template_bytes=_int_env("MAX_TEMPLATE_BYTES", 1_048_576),
            reports_path=Path(os.getenv("REPORTS_PATH", "reports")),
        )


def configure_logging(settings: Settings) -> None:
    """Configure process logging once from settings."""

    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
