"""Centralized runtime configuration for the IaC security agent."""

from __future__ import annotations

import logging
import os
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
    use_local_embeddings: bool = False
    llm_temperature: float = 0.0
    llm_max_tokens: int = 4096
    llm_max_retries: int = 2
    max_template_bytes: int = 1_048_576
    reports_path: Path = Path("reports")

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from process environment variables."""

        return cls(
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
            use_local_embeddings=os.getenv("USE_LOCAL_EMBEDDINGS", "false").lower()
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
