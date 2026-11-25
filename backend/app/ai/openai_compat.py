"""Self-hosted / local models behind an OpenAI-compatible chat completions endpoint (vLLM, Ollama, LM Studio)."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import httpx

from .providers import Generation, ProviderUnavailable


def _is_local(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host in ("localhost",) or host.endswith(".internal") or host.endswith(".local") or "." not in host:
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(self, base_url: str, api_key: str | None, model: str, timeout_s: int):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_s = timeout_s
        # A model on the same network is not "external"; redaction still applies when configured.
        self.external = not _is_local(base_url)

    def generate(self, system: str, user: str, schema: dict) -> Generation:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        body = {"model": self.model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {"type": "json_schema", "json_schema": {"name": "synthesis", "schema": schema}}}
        try:
            r = httpx.post(f"{self.base_url}/chat/completions", json=body, headers=headers, timeout=self.timeout_s)
            if r.status_code == 400:  # server without json_schema support: fall back to plain JSON mode
                body["response_format"] = {"type": "json_object"}
                r = httpx.post(f"{self.base_url}/chat/completions", json=body, headers=headers, timeout=self.timeout_s)
            r.raise_for_status()
            data = r.json()
            text = data["choices"][0]["message"]["content"] or ""
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise ProviderUnavailable(f"Local AI model request failed: {type(exc).__name__}") from exc
        return Generation(text=text, provider=self.name, model=data.get("model", self.model), external=self.external)
