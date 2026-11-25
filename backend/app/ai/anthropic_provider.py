"""Claude provider (Anthropic Messages API via the official SDK) with JSON-schema structured output."""

from __future__ import annotations

import logging

import anthropic

from .providers import Generation, ProviderUnavailable

log = logging.getLogger(__name__)
DEFAULT_MODEL = "claude-opus-5-5"


class AnthropicProvider:
    name = "anthropic"
    external = True

    def __init__(self, api_key: str | None, model: str | None, timeout_s: int):
        # api_key None lets the SDK resolve credentials from the environment.
        self.client = anthropic.Anthropic(api_key=api_key, timeout=timeout_s, max_retries=2)
        self.model = model or DEFAULT_MODEL

    def generate(self, system: str, user: str, schema: dict) -> Generation:
        try:
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"effort": "medium", "format": {"type": "json_schema", "schema": schema}},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except anthropic.RateLimitError as exc:
            raise ProviderUnavailable("AI provider rate limit reached; try again later") from exc
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            raise ProviderUnavailable("AI provider rejected the configured credentials") from exc
        except anthropic.APIStatusError as exc:
            log.warning("anthropic API error", extra={"status": exc.status_code, "request_id": getattr(exc, "request_id", None)})
            raise ProviderUnavailable(f"AI provider error ({exc.status_code})") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderUnavailable("AI provider is unreachable") from exc
        if response.stop_reason == "refusal":
            raise ProviderUnavailable("AI provider declined the request")
        if response.stop_reason == "max_tokens":
            raise ProviderUnavailable("AI response was truncated")
        text = next((b.text for b in response.content if b.type == "text"), "")
        return Generation(text=text, provider=self.name, model=response.model, external=True)
