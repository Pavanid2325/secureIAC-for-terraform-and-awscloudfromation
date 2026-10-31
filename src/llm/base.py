"""Provider-neutral boundary; adapters never validate security conclusions."""
from dataclasses import dataclass, field
from typing import Protocol


class LLMError(RuntimeError):
    def __init__(self, code: str, retryable: bool = False):
        self.code = code
        self.retryable = retryable
        super().__init__(f"Inference failed: {code}")


@dataclass(frozen=True)
class ProviderResult:
    text: str
    provider: str
    model: str
    request_id: str | None = None
    usage: dict = field(default_factory=dict)
    status: str = "completed"
    duration_ms: int = 0


class LLMClient(Protocol):
    model_id: str

    def generate(self, system_prompt: str, user_prompt: str) -> str | ProviderResult: ...
