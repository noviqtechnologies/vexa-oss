"""
Anthropic Claude AI Provider for Vexa.

Uses the official `anthropic` Python SDK.
"""

from vexa.common.logging import get_logger
from vexa.ai_providers.base import (
    SDKAIProvider,
    AIProviderType,
    AIProviderStatus,
)
from vexa.common.config import get_env

logger = get_logger(__name__)


class AnthropicWrapper(SDKAIProvider):
    """Anthropic Provider Implementation."""

    PROVIDER_TYPE = AIProviderType.ANTHROPIC
    AUTH_ERROR_KEYWORDS = ("invalid x-api-key", "authentication", "401", "403")
    RATE_LIMIT_KEYWORDS = ("rate_limit", "too many requests", "429")

    def __init__(self):
        super().__init__()
        self._api_key = get_env("VEXA_ANTHROPIC_API_KEY", "")
        self._model = get_env("VEXA_ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

    def _get_client(self):
        try:
            import anthropic

            return anthropic.AsyncAnthropic(api_key=self._api_key)
        except ImportError:
            raise RuntimeError("anthropic SDK not installed")

    def set_api_key(self, api_key: str):
        self._api_key = api_key

    def set_model(self, model: str):
        self._model = model

    @property
    def is_available(self) -> bool:
        try:
            import anthropic  # noqa: F401

            return bool(self._api_key)
        except ImportError:
            return False

    async def check_availability(self) -> tuple[AIProviderStatus, str]:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return (
                AIProviderStatus.UNAVAILABLE,
                "Anthropic SDK not found (install with 'pip install anthropic')",
            )

        if not self._api_key:
            return AIProviderStatus.UNAVAILABLE, "VEXA_ANTHROPIC_API_KEY is not set"

        return AIProviderStatus.AVAILABLE, "Ready"

    async def _send_request(self, client, system_prompt: str, user_prompt: str) -> str:
        response = await client.messages.create(
            model=self._model,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=0.2,
            max_tokens=4096,
        )
        return response.content[0].text if response.content else ""

    async def _test_connection_request(self, client) -> None:
        await client.messages.create(
            model=self._model,
            messages=[{"role": "user", "content": "Reply with 'ok'"}],
            max_tokens=5,
        )


def get_anthropic_wrapper() -> AnthropicWrapper:
    return AnthropicWrapper()
