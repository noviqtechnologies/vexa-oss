"""
Unit tests for Gemini SDK Provider.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from vexa.ai_providers.google_sdk import GeminiSDKWrapper
from vexa.ai_providers.base import AIProviderStatus
from vexa.common.models import Finding

@pytest.fixture
def mock_genai_client():
    with patch("google.genai.Client") as mock:
        yield mock

class TestGeminiSDKWrapper:
    
    @pytest.mark.anyio
    async def test_check_availability_no_key(self):
        """Should be unavailable if no API key is set."""
        with patch.dict("os.environ", {}, clear=True):
            wrapper = GeminiSDKWrapper()
            status, message = await wrapper.check_availability()
            assert status == AIProviderStatus.UNAVAILABLE
            assert "GOOGLE_API_KEY" in message or "SSL environment error" in message

    @pytest.mark.anyio
    async def test_check_availability_with_key(self):
        """Should be available if API key is set."""
        with patch.dict("os.environ", {"GOOGLE_API_KEY": "test-key"}):
            wrapper = GeminiSDKWrapper()
            status, message = await wrapper.check_availability()
            assert status == AIProviderStatus.AVAILABLE
            assert "Ready" in message

    @pytest.mark.anyio
    async def test_analyze_findings_batch(self, mock_genai_client):
        """Should analyze a batch of findings."""
        # Setup mock client and its nested methods
        mock_client_instance = mock_genai_client.return_value
        mock_response = MagicMock()
        mock_response.text = """
### Finding 1 Analysis

#### Detailed Description
Enriched description

#### Remediation Code
```python
print("Fixed")
```
"""
        # Mocking client.aio.models.generate_content
        mock_client_instance.aio.models.generate_content = AsyncMock(return_value=mock_response)
        
        with patch.dict("os.environ", {"GOOGLE_API_KEY": "test-key"}):
            wrapper = GeminiSDKWrapper()
            finding = Finding(
                id="1", scanner="test", title="t", description="d", severity="high", 
                file_path="f.py", line_start=1, line_end=2
            )
            
            results = await wrapper.analyze_findings_batch([finding], code_contexts={})
            
            assert len(results) == 1
            assert results[0].detailed_description == "Enriched description"
            mock_client_instance.aio.models.generate_content.assert_called_once()
