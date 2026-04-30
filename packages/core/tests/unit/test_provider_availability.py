import pytest
import shutil
from unittest.mock import patch, MagicMock
from vexa.common.cloud_provider import ProviderAvailability, CloudProvider

@pytest.mark.anyio
async def test_check_provider_none():
    """Test CloudProvider.NONE is always available."""
    result = await ProviderAvailability.check_provider(CloudProvider.NONE)
    assert result["available"] is True
    assert result["error"] is None

@pytest.mark.anyio
@patch("shutil.which")
async def test_check_provider_missing_binary(mock_which):
    """Test when CLI binary is missing."""
    mock_which.return_value = None
    # Use a provider that still checks for CLI (e.g. AWS but it's disabled now, so let's use a mock provider or one with CLI)
    # Actually, AWS/AZURE now returns "disabled" immediately if ai_cli_command is None.
    # So let's test that logic.
    result = await ProviderAvailability.check_provider(CloudProvider.AWS)
    assert result["available"] is False
    assert "disabled" in result["error"].lower()

@pytest.mark.anyio
@patch("shutil.which")
@patch("subprocess.run")
async def test_check_provider_deep_check_success(mock_run, mock_which):
    """Test deep check success for a provider that STILL has a CLI (if any were left)."""
    # Since we set everyone to None, this legacy path is hard to reach unless we mock PROVIDER_CAPABILITIES
    with patch("vexa.common.cloud_provider.PROVIDER_CAPABILITIES") as mock_caps:
        mock_caps.get.return_value = MagicMock(ai_cli_command="test-cli", check_args=["--v"])
        mock_which.return_value = "/usr/bin/test-cli"
        mock_run.return_value = MagicMock(returncode=0)
        
        result = await ProviderAvailability.check_provider(CloudProvider.AZURE)
        assert result["available"] is True
        assert result["error"] is None

@pytest.mark.anyio
@patch("shutil.which")
@patch("subprocess.run")
async def test_check_provider_deep_check_failure(mock_run, mock_which):
    """Test deep check failure."""
    with patch("vexa.common.cloud_provider.PROVIDER_CAPABILITIES") as mock_caps:
        mock_caps.get.return_value = MagicMock(ai_cli_command="test-cli", check_args=["--v"])
        mock_which.return_value = "/usr/bin/test-cli"
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        
        result = await ProviderAvailability.check_provider(CloudProvider.AZURE)
        assert result["available"] is False
        assert "deep check failed" in result["error"]
