"""Explicit provider selection; never silently change authentication or billing."""
from src.llm.base import LLMError


def create_provider(settings):
    if settings.provider == "mock":
        from src.llm.mock_provider import MockProvider
        return MockProvider()
    if not settings.live_calls:
        raise LLMError("live_calls_disabled")
    if settings.provider == "chatgpt":
        if settings.auth_mode != "chatgpt":
            raise LLMError("auth_mode_mismatch")
        from src.llm.chatgpt_provider import ChatGPTProvider
        return ChatGPTProvider(settings.openai_model, settings.api_timeout, settings.max_output_bytes)
    if settings.auth_mode != "api_key":
        raise LLMError("auth_mode_mismatch")
    if settings.provider == "openai":
        from src.llm.openai_provider import OpenAIProvider
        return OpenAIProvider(settings.openai_model, settings.api_timeout, settings.llm_max_tokens)
    from src.llm.bedrock_claude import BedrockClaudeClient
    return BedrockClaudeClient(settings.aws_region, settings.bedrock_llm_model_id,
                               temperature=settings.llm_temperature, max_tokens=settings.llm_max_tokens,
                               max_retries=0, timeout_seconds=settings.api_timeout)
