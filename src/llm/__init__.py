"""Language-model adapters."""

from .base import LLMClient, LLMError, ProviderResult


def __getattr__(name):
    if name == "BedrockClaudeClient":
        from .bedrock_claude import BedrockClaudeClient
        return BedrockClaudeClient
    raise AttributeError(name)

__all__ = ["BedrockClaudeClient", "LLMClient", "LLMError"]
