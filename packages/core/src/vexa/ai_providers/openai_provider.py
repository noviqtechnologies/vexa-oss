"""
OpenAI GPT AI Provider for Vexa.

Uses the official `openai` Python SDK.
"""

from vexa.common.logging import get_logger
from vexa.ai_providers.base import (
    SDKAIProvider,
    AIProviderType,
    AIProviderStatus,
)
from vexa.common.config import get_env

logger = get_logger(__name__)


class OpenAIWrapper(SDKAIProvider):
    """OpenAI Provider Implementation."""

    PROVIDER_TYPE = AIProviderType.OPENAI
    AUTH_ERROR_KEYWORDS = (
        "invalid_api_key",
        "incorrect api key",
        "authentication",
        "401",
        "403",
    )
    RATE_LIMIT_KEYWORDS = ("rate_limit", "quota", "too many requests", "429")

    def __init__(self):
        super().__init__()
        self._api_key = get_env("VEXA_OPENAI_API_KEY", "") or get_env("OPENAI_API_KEY", "")
        self._model = get_env("VEXA_OPENAI_MODEL", "gpt-4o-mini")

    def _get_client(self):
        try:
            import openai

            api_key = self._api_key or get_env("VEXA_OPENAI_API_KEY", "") or get_env("OPENAI_API_KEY", "")
            return openai.AsyncOpenAI(api_key=api_key)
        except ImportError:
            raise RuntimeError("openai SDK not installed")

    def set_api_key(self, api_key: str):
        self._api_key = api_key

    def set_model(self, model: str):
        self._model = model

    @property
    def is_available(self) -> bool:
        try:
            import openai  # noqa: F401

            return bool(self._api_key)
        except ImportError:
            return False

    async def check_availability(self) -> tuple[AIProviderStatus, str]:
        try:
            import openai  # noqa: F401
        except ImportError:
            return (
                AIProviderStatus.UNAVAILABLE,
                "OpenAI SDK not found (install with 'pip install openai')",
            )

        api_key = self._api_key or get_env("VEXA_OPENAI_API_KEY", "") or get_env("OPENAI_API_KEY", "")
        if not api_key:
            return AIProviderStatus.UNAVAILABLE, "VEXA_OPENAI_API_KEY or OPENAI_API_KEY is not set"

        return AIProviderStatus.AVAILABLE, "Ready"

    async def _send_request(self, client, system_prompt: str, user_prompt: str) -> str:
        response = await client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=4096,
        )
        return response.choices[0].message.content or ""

    async def _test_connection_request(self, client) -> None:
        await client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": "Reply with 'ok'"}],
            max_tokens=5,
        )


def get_openai_wrapper() -> OpenAIWrapper:
    return OpenAIWrapper()
