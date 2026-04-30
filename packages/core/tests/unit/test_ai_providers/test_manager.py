"""
Unit tests for AI Provider Manager - TDD Approach
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from vexa.ai_providers.manager import AIProviderManager
from vexa.common.models import CloudProvider, EnhancedFinding, Finding
from vexa.ai_providers.base import AIProviderStatus, AIProviderType


@pytest.fixture
def mock_gemini():
    mock = AsyncMock()
    mock.PROVIDER_TYPE = AIProviderType.GOOGLE
    mock.check_availability.return_value = (AIProviderStatus.AVAILABLE, "OK")
    mock.is_available = True
    mock.enhance_finding = MagicMock()
    return mock


@pytest.fixture
def mock_openai():
    mock = AsyncMock()
    mock.PROVIDER_TYPE = AIProviderType.OPENAI
    mock.check_availability.return_value = (AIProviderStatus.AVAILABLE, "OK")
    mock.is_available = True
    mock.enhance_finding = MagicMock()
    return mock


@pytest.fixture
def mock_anthropic():
    mock = AsyncMock()
    mock.PROVIDER_TYPE = AIProviderType.ANTHROPIC
    mock.check_availability.return_value = (AIProviderStatus.AVAILABLE, "OK")
    mock.is_available = True
    mock.enhance_finding = MagicMock()
    return mock


class TestAIProviderManager:
    @patch("vexa.ai_providers.manager.get_anthropic_wrapper")
    @patch("vexa.ai_providers.manager.get_openai_wrapper")
    @patch("vexa.ai_providers.manager.get_gemini_sdk_wrapper")
    def test_configure_google_provider(
        self, mock_get_gemini, mock_get_openai, mock_get_anthropic, mock_gemini
    ):
        """Should configure Google as primary via SDK."""
        mock_get_gemini.return_value = mock_gemini

        manager = AIProviderManager(cloud_provider=CloudProvider.GOOGLE)

        assert manager._primary_provider == mock_gemini
        assert manager._fallback_provider is None

    @patch("vexa.ai_providers.manager.get_anthropic_wrapper")
    @patch("vexa.ai_providers.manager.get_openai_wrapper")
    @patch("vexa.ai_providers.manager.get_gemini_sdk_wrapper")
    def test_configure_openai_provider(
        self, mock_get_gemini, mock_get_openai, mock_get_anthropic, mock_openai
    ):
        """Should configure OpenAI as primary."""
        mock_get_openai.return_value = mock_openai

        manager = AIProviderManager(cloud_provider=CloudProvider.OPENAI)

        assert manager._primary_provider == mock_openai

    @patch("vexa.ai_providers.manager.get_anthropic_wrapper")
    @patch("vexa.ai_providers.manager.get_openai_wrapper")
    @patch("vexa.ai_providers.manager.get_gemini_sdk_wrapper")
    def test_configure_anthropic_provider(
        self, mock_get_gemini, mock_get_openai, mock_get_anthropic, mock_anthropic
    ):
        """Should configure Anthropic as primary."""
        mock_get_anthropic.return_value = mock_anthropic

        manager = AIProviderManager(cloud_provider=CloudProvider.ANTHROPIC)

        assert manager._primary_provider == mock_anthropic

    @patch("vexa.ai_providers.manager.get_anthropic_wrapper")
    @patch("vexa.ai_providers.manager.get_openai_wrapper")
    @patch("vexa.ai_providers.manager.get_gemini_sdk_wrapper")
    def test_configure_aws_provider_disabled(
        self, mock_get_gemini, mock_get_openai, mock_get_anthropic
    ):
        """Should result in None for disabled AWS provider."""
        manager = AIProviderManager(cloud_provider=CloudProvider.AWS)
        assert manager._primary_provider is None

    @patch("vexa.ai_providers.manager.get_anthropic_wrapper")
    @patch("vexa.ai_providers.manager.get_openai_wrapper")
    @patch("vexa.ai_providers.manager.get_gemini_sdk_wrapper")
    def test_configure_azure_provider_disabled(
        self, mock_get_gemini, mock_get_openai, mock_get_anthropic
    ):
        """Should result in None for disabled Azure provider."""
        manager = AIProviderManager(cloud_provider=CloudProvider.AZURE)
        assert manager._primary_provider is None

    @pytest.mark.anyio
    @patch("vexa.ai_providers.manager.get_gemini_sdk_wrapper")
    async def test_enrich_findings_uses_primary(self, mock_get_gemini, mock_gemini):
        """Should use primary provider to enrich findings."""
        mock_get_gemini.return_value = mock_gemini

        manager = AIProviderManager(cloud_provider=CloudProvider.GOOGLE)

        finding = Finding(
            id="1",
            scanner="test",
            title="t",
            description="d",
            severity="high",
            file_path="f.py",
            line_start=1,
            line_end=2,
        )

        enriched_finding = EnhancedFinding(
            **finding.model_dump(), detailed_description="Enriched"
        )
        # Mocking
        mock_gemini.test_connection.return_value = (AIProviderStatus.AVAILABLE, "Ready")
        mock_gemini.analyze_findings_batch.return_value = [enriched_finding]
        mock_gemini.enhance_finding.return_value = enriched_finding

        result, fps = await manager.enrich_findings([finding])

        mock_gemini.analyze_findings_batch.assert_called_once()
        assert len(result) == 1
        assert result[0].detailed_description == "Enriched"
        assert len(fps) == 0
