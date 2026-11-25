"""LLM provider abstraction for the AI copilot.

Providers receive already-redacted text and return text; they never see raw
packets, payloads or credentials. ``none`` (the default) disables external calls
and the copilot falls back to a deterministic synthesis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from app.core.config import get_settings


class ProviderUnavailable(RuntimeError):
    """No provider configured, or the provider declined/failed."""


@dataclass
class Generation:
    text: str
    provider: str
    model: str | None
    external: bool  # True when data left the deployment (redaction applies)


class Provider(Protocol):
    name: str
    external: bool

    def generate(self, system: str, user: str, schema: dict) -> Generation: ...


def get_provider() -> Provider | None:
    s = get_settings()
    if s.llm_provider == "anthropic":
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=s.llm_api_key, model=s.llm_model, timeout_s=s.llm_timeout_s)
    if s.llm_provider == "openai_compatible":
        from .openai_compat import OpenAICompatibleProvider

        if not s.llm_base_url:
            raise ProviderUnavailable("PKO_LLM_BASE_URL is required for the openai_compatible provider")
        return OpenAICompatibleProvider(base_url=s.llm_base_url, api_key=s.llm_api_key, model=s.llm_model or "local-model",
                                        timeout_s=s.llm_timeout_s)
    return None
