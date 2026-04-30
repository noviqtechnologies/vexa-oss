import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Mock anthropic before importing the wrapper or running tests
mock_anthropic = MagicMock()
sys.modules["anthropic"] = mock_anthropic

from vexa.ai_providers.anthropic_provider import AnthropicWrapper
from vexa.ai_providers.base import AIProviderStatus
from vexa.common.models import Finding


@pytest.fixture
def mock_anthropic_client():
    client_mock = MagicMock()
    mock_anthropic.AsyncAnthropic.return_value = client_mock
    return client_mock


class TestAnthropicWrapper:
    @pytest.mark.anyio
    async def test_check_availability_no_key(self):
        """Should be unavailable if no API key is set."""
        with patch.dict("os.environ", {}, clear=True):
            wrapper = AnthropicWrapper()
            status, message = await wrapper.check_availability()
            assert status == AIProviderStatus.UNAVAILABLE
            assert "VEXA_ANTHROPIC_API_KEY" in message

    @pytest.mark.anyio
    async def test_check_availability_with_key(self):
        """Should be available if API key is set."""
        with patch.dict("os.environ", {"VEXA_ANTHROPIC_API_KEY": "test-key"}):
            wrapper = AnthropicWrapper()
            status, message = await wrapper.check_availability()
            assert status == AIProviderStatus.AVAILABLE
            assert "Ready" in message

    @pytest.mark.anyio
    async def test_analyze_findings_batch(self, mock_anthropic_client):
        """Should analyze a batch of findings."""
        # mock_anthropic_client is the client_mock instance returned by AsyncAnthropic()
        mock_instance = mock_anthropic_client

        # Mock response
        mock_response = MagicMock()
        mock_content = MagicMock()
        mock_content.text = """
### Finding 1 Analysis

#### Detailed Description
Enriched description

#### Remediation Code
```python
print("Fixed")
```
"""
        mock_response.content = [mock_content]
        # client.messages.create must be an AsyncMock
        mock_instance.messages = MagicMock()
        mock_instance.messages.create = AsyncMock(return_value=mock_response)

        with patch.dict("os.environ", {"VEXA_ANTHROPIC_API_KEY": "test-key"}):
            wrapper = AnthropicWrapper()
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

            results = await wrapper.analyze_findings_batch([finding], code_contexts={})

            assert len(results) == 1
            assert results[0].detailed_description == "Enriched description"
            mock_instance.messages.create.assert_called_once()
