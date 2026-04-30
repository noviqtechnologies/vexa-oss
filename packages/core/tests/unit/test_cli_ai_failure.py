"""
Unit tests for AI connection failure handling in CLI.
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from click.testing import CliRunner
from pathlib import Path
from vexa_cli.main import scan
from vexa.common.cloud_provider import CloudProvider

import re

def strip_ansi(text):
    """Strip ANSI escape sequences from text."""
    ansi_escape = re.compile(r'\x1b\[([0-9,;]*[mGKH])')
    return ansi_escape.sub('', text)

@pytest.fixture
def runner():
    return CliRunner()

@patch("vexa_cli.commands.scan.ProviderAvailability.check_provider", new_callable=AsyncMock)
@patch("vexa_cli.commands.scan._run_scan", new_callable=AsyncMock)
@patch("vexa_cli.commands.scan._generate_report")
def test_scan_ai_unavailable_proceed(mock_gen_report, mock_run_scan, mock_check_provider, runner):
    """Test proceeding with scan when AI is unavailable and user confirms."""
    mock_check_provider.return_value = {"available": False, "error": "SDK not found"}
    mock_run_scan.return_value = MagicMock(
        success=True, 
        total_findings=0, 
        scanned_files=5, 
        errors=[], 
        job_id="test_job",
        duration_seconds=10,
        findings_by_severity={},
        total_false_positives=0
    )
    
    with runner.isolated_filesystem():
        Path("target").mkdir()
        # Force CI to False and mock terms acceptance
        with patch.dict("os.environ", {"CI": "false"}), \
             patch("vexa.common.config.is_terms_accepted", return_value=True):
            result = runner.invoke(scan, ["target", "--ai-provider", "google"], input="\ny\n")
        
        output = strip_ansi(result.output)
        assert result.exit_code == 0, f"Command failed with output: {output}"
        assert "SDK not found" in output
        assert "Would you like to proceed" in output
        assert "capabilities disabled" in output
        assert "Provider: None" in output
        
        # Verify _run_scan was called with CloudProvider.NONE
        mock_run_scan.assert_called_once()
        args = mock_run_scan.call_args[0]
        assert args[4] == CloudProvider.NONE

@patch("vexa_cli.commands.scan.ProviderAvailability.check_provider", new_callable=AsyncMock)
@patch("vexa_cli.commands.scan._run_scan", new_callable=AsyncMock)
def test_scan_ai_unavailable_abort(mock_run_scan, mock_check_provider, runner):
    """Test aborting scan when AI is unavailable and user denies."""
    mock_check_provider.return_value = {"available": False, "error": "SDK not found"}
    
    mock_run_scan.return_value = MagicMock(success=True, total_findings=0, scanned_files=0)
    
    with runner.isolated_filesystem():
        Path("target").mkdir()
        # Force CI to False and handle 'n' input for aborting
        with patch.dict("os.environ", {"CI": "false"}), \
             patch("vexa.common.config.is_terms_accepted", return_value=True):
            result = runner.invoke(scan, ["target", "--ai-provider", "google"], input="\nn\n")
        
        output = strip_ansi(result.output)
        assert result.exit_code == 0, f"Command failed with output: {output}"
        assert "SDK not found" in output
        assert "Scan aborted" in output
        assert "Please configure" in output
        
        # Verify _run_scan was NOT called
        mock_run_scan.assert_not_called()

@patch("vexa_cli.commands.scan.ProviderAvailability.check_provider", new_callable=AsyncMock)
@patch("vexa_cli.commands.scan._run_scan", new_callable=AsyncMock)
@patch("vexa_cli.commands.scan._generate_report")
def test_scan_ai_available_no_prompt(mock_gen_report, mock_run_scan, mock_check_provider, runner):
    """Test that no prompt appears when AI is available."""
    mock_check_provider.return_value = {"available": True}
    mock_run_scan.return_value = MagicMock(
        success=True, 
        total_findings=0, 
        scanned_files=5, 
        errors=[], 
        job_id="test_job",
        duration_seconds=10,
        findings_by_severity={},
        total_false_positives=0
    )
    
    with runner.isolated_filesystem():
        Path("target").mkdir()
        with patch("vexa.common.config.is_terms_accepted", return_value=True):
            result = runner.invoke(scan, ["target", "--ai-provider", "google"])
        
        output = strip_ansi(result.output)
        assert result.exit_code == 0, f"Command failed with output: {output}"
        assert "Provider: GOOGLE" in output
        
        # Verify _run_scan was called with CloudProvider.GOOGLE
        mock_run_scan.assert_called_once()
        args = mock_run_scan.call_args[0]
        assert args[4] == CloudProvider.GOOGLE
