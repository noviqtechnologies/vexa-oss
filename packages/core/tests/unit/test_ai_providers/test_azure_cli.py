import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path
from vexa.ai_providers._legacy.azure_cli import (
    AzurePromptBuilder,
    AzureCLIExecutor,
    AzureMarkdownParser,
    AzureCLIWrapper
)
from vexa.common.models import Finding, AzureEnhancedFinding

@pytest.fixture
def sample_finding():
    return Finding(
        id="test-1",
        scanner="bandit",
        severity="high",
        title="Hardcoded Password",
        description="A hardcoded password was found.",
        file_path="app.py",
        line_start=10,
        line_end=10,
        code_snippet="password = 'secret'"
    )

class TestAzurePromptBuilder:
    def test_build_batch_prompt(self, sample_finding):
        builder = AzurePromptBuilder()
        prompt = builder.build_batch_prompt([sample_finding], {"name": "TestApp"})
        assert "TestApp" in prompt
        assert "Hardcoded Password" in prompt
        assert "Azure Security Benchmark" in prompt

class TestAzureMarkdownParser:
    def test_parse_valid_response(self, sample_finding):
        parser = AzureMarkdownParser()
        markdown = """
### Finding 1 Analysis

#### Detailed Description
This is a critical flaw.

#### Attack Scenario
1. Run the app.
2. Read the password.

#### Business Impact
Loss of $1M.

#### False Positive Analysis
- **Is False Positive**: false
- **Confidence**: 0.95
- **Explanation**: It's definitely there.

#### Code Snippets
- **Before**: 
```python
password = 'secret'
```
- **After**:
```python
import os
password = os.getenv('DB_PASSWORD')
```

#### Azure Recommendation
Use Azure Key Vault.

#### Azure Security Benchmark Pillar
Data Protection

#### Implementation Steps
1. Create Key Vault.
2. Store secret.

#### Verification Test Cases
- **Test 1**: No hardcoded pass.

#### Azure Documentation
- [Azure Security](https://learn.microsoft.com/azure/security)
"""
        results = parser.parse(markdown, [sample_finding])
        assert len(results) == 1
        finding = results[0]
        assert isinstance(finding, AzureEnhancedFinding)
        assert finding.detailed_description == "This is a critical flaw."
        assert finding.azure_recommendation == "Use Azure Key Vault."
        assert finding.azure_security_benchmark_pillar == "Data Protection"
        assert "https://learn.microsoft.com/azure/security" in finding.azure_doc_links

class TestAzureCLIWrapper:
    @pytest.mark.asyncio
    @patch("shutil.which")
    async def test_check_availability_not_found(self, mock_which):
        mock_which.return_value = None
        wrapper = AzureCLIWrapper()
        status, msg = await wrapper.check_availability()
        assert status.value == "unavailable"
        assert "not found" in msg.lower()

    @pytest.mark.asyncio
    @patch("shutil.which")
    @patch("asyncio.create_subprocess_exec")
    async def test_check_availability_available(self, mock_exec, mock_which):
        mock_which.return_value = "/usr/bin/az"
        
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate.return_value = (b"OK", b"")
        mock_exec.return_value = mock_process
        
        wrapper = AzureCLIWrapper()
        status, msg = await wrapper.check_availability()
        assert status.value == "available"
