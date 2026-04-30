"""
Google Gemini SDK-based AI Provider for Vexa.

Uses the official `google-genai` Python SDK (the modern replacement for `google-generativeai`).

G-001: Cloud provider selection
SS-003: AI-powered code review
SS-010: False positive detection
"""

import asyncio
import sys
from typing import Optional

from vexa.common.logging import get_logger
from vexa.ai_providers.base import (
    SDKAIProvider,
    AIProviderType,
    AIProviderStatus,
)
from vexa.common.config import get_env

logger = get_logger(__name__)


class GeminiSDKWrapper(SDKAIProvider):
    """
    Google Gemini AI Provider using the modern `google-genai` SDK.

    Authentication: Set GOOGLE_API_KEY environment variable.
    Install SDK:    pip install google-genai
    """

    PROVIDER_TYPE = AIProviderType.GOOGLE
    AUTH_ERROR_KEYWORDS = (
        "api key not valid",
        "invalid api key",
        "permission denied",
        "401",
        "403",
    )
    RATE_LIMIT_KEYWORDS = (
        "quota",
        "rate_limit",
        "resource_exhausted",
        "too many requests",
        "429",
    )
    NETWORK_ERROR_KEYWORDS = ("dns", "connection", "network", "host", "getaddrinfo")

    def __init__(self):
        super().__init__()
        self._api_key = get_env("GOOGLE_API_KEY", "")
        self._model = get_env("GOOGLE_GEMINI_MODEL", "gemini-3.1-pro-preview")

    def _get_client(self):
        """Initialise and return the Gemini client."""
        try:
            from google import genai
            import httpx
        except ImportError:
            raise RuntimeError(
                "google-genai SDK not installed. Run: pip install google-genai"
            )

        kwargs = {}
        # Fix for Windows asyncio SSL DNS resolution flake (SSLError: [SSL] unknown error (_ssl.c:3108))
        if sys.platform == "win32":
            kwargs["http_options"] = {
                "httpx_async_client": httpx.AsyncClient(),
                "httpx_client": httpx.Client(),
            }

        return genai.Client(api_key=self._api_key, **kwargs)

    def set_api_key(self, api_key: str) -> None:
        self._api_key = api_key

    def set_model(self, model: str) -> None:
        self._model = model

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        try:
            from google import genai  # noqa: F401

            return bool(self._api_key)
        except ImportError:
            return False

    async def check_availability(self) -> tuple[AIProviderStatus, str]:
        try:
            from google import genai  # noqa: F401
        except ImportError:
            return (
                AIProviderStatus.UNAVAILABLE,
                "Google Gemini SDK not found. Install with: pip install google-genai",
            )
        except Exception as e:
            # Handle Windows SSL/DNS issues gracefully during import (aiohttp loading SSL context)
            if (
                "ssl" in str(e).lower()
                or "dns" in str(e).lower()
                or "getaddrinfo" in str(e).lower()
            ):
                return (
                    AIProviderStatus.UNAVAILABLE,
                    f"Gemini SDK initialization failed due to network/SSL environment error: {e}",
                )
            raise e

        if not self._api_key:
            return (
                AIProviderStatus.UNAVAILABLE,
                "GOOGLE_API_KEY environment variable is not set. "
                "Get a key at https://aistudio.google.com/app/apikey",
            )

        return AIProviderStatus.AVAILABLE, "Ready"

    def _classify_error(self, err_msg: str, status_code: Optional[int] = None) -> str:
        """Extended error classification with network error support."""
        err_lower = err_msg.lower()
        if status_code in (401, 403) or any(
            w in err_lower for w in self.AUTH_ERROR_KEYWORDS
        ):
            return "auth"
        if status_code == 429 or any(w in err_lower for w in self.RATE_LIMIT_KEYWORDS):
            return "rate_limit"
        if any(w in err_lower for w in self.NETWORK_ERROR_KEYWORDS):
            return "network"
        return "other"

    # ------------------------------------------------------------------
    # Connection test with retry logic for flaky DNS on Windows
    # ------------------------------------------------------------------

    async def test_connection(self) -> tuple[AIProviderStatus, str]:
        """Perform a minimal SDK request to verify API key and quota."""
        status, msg = await self.check_availability()
        if status != AIProviderStatus.AVAILABLE:
            return status, msg

        # Retry logic for flaky DNS on Windows
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                client = self._get_client()
                logger.info(
                    "Validating Gemini API key with model %s (Attempt %d)...",
                    self._model,
                    attempt + 1,
                )

                try:
                    # Primary attempt
                    response = await client.aio.models.generate_content(
                        model=self._model, contents="Reply with 'ok'"
                    )
                    _ = response.text
                    return AIProviderStatus.AVAILABLE, "Ready"
                except Exception as e:
                    err_str = str(e)

                    # 1. Fallback logic: If 404/Not Found, try gemini-1.5-flash
                    if "404" in err_str or "not found" in err_str.lower():
                        logger.warning(
                            f"Model {self._model} not found. Falling back to gemini-1.5-flash..."
                        )
                        self._model = "gemini-1.5-flash"
                        response = await client.aio.models.generate_content(
                            model=self._model, contents="Reply with 'ok'"
                        )
                        _ = response.text
                        return (
                            AIProviderStatus.AVAILABLE,
                            f"Ready (Fell back to {self._model})",
                        )

                    # 2. DNS/Network Flake: If we have retries left, wait and try again
                    if (
                        any(w in err_str.lower() for w in self.NETWORK_ERROR_KEYWORDS)
                        and attempt < max_retries
                    ):
                        wait_time = 1 * (attempt + 1)
                        logger.warning(
                            f"Connection glitch detected ([{err_str}]). Retrying in {wait_time}s..."
                        )
                        await asyncio.sleep(wait_time)
                        continue

                    raise e

            except Exception as e:
                err_type = self._classify_error(str(e))
                if err_type == "auth":
                    return AIProviderStatus.ERROR, f"Gemini Auth Error: {e}"
                if err_type == "rate_limit":
                    return AIProviderStatus.ERROR, f"Gemini Rate Limit Error: {e}"
                if err_type == "network":
                    return (
                        AIProviderStatus.ERROR,
                        f"Gemini Network Error: Could not reach Google AI services. Please check your internet connection. ({e})",
                    )
                return AIProviderStatus.ERROR, f"Gemini Connection Failed: {str(e)}"

        return AIProviderStatus.ERROR, "Gemini Connection Failed: Max retries exceeded."

    # ------------------------------------------------------------------
    # Request implementation
    # ------------------------------------------------------------------

    async def _send_request(self, client, system_prompt: str, user_prompt: str) -> str:
        from google.genai import types

        response = await client.aio.models.generate_content(
            model=self._model,
            contents=f"{system_prompt}\n\n{user_prompt}",
            config=types.GenerateContentConfig(
                temperature=0.2,
                max_output_tokens=8192,
            ),
        )
        return response.text if response.text else ""

    async def _test_connection_request(self, client) -> None:
        # Note: test_connection is overridden for Gemini due to retry/fallback logic,
        # but this is still needed for the abstract interface contract.
        response = await client.aio.models.generate_content(
            model=self._model, contents="Reply with 'ok'"
        )
        _ = response.text


def get_gemini_sdk_wrapper() -> GeminiSDKWrapper:
    return GeminiSDKWrapper()
