"""Thin provider interface around the model.

The workbench runs without a model. When ANTHROPIC_API_KEY is set and the
`anthropic` package is installed, `get_llm()` returns a client; otherwise None,
and every caller falls back to built-in text.

To use a different or local model, implement `complete(system, user, max_tokens)`
on your own class and pass an instance wherever `llm=` is accepted.
"""
from __future__ import annotations

from ..config import get_settings


class ClaudeLLM:
    def __init__(self, api_key: str, model: str):
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def complete(self, system: str, user: str, max_tokens: int = 700) -> str:
        message = self._client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}])
        return "".join(block.text for block in message.content if getattr(block, "type", "") == "text")


def get_llm():
    """Returns a model client, or None when no key or SDK is available."""
    settings = get_settings()
    if not settings.api_key:
        return None
    try:
        return ClaudeLLM(settings.api_key, settings.model)
    except ImportError:
        return None
