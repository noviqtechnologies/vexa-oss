import pytest
from unittest.mock import patch, MagicMock

import io
import os
from vexa.ai_providers.openai_provider import OpenAIWrapper
from vexa.ai_providers.prompts import GenericPromptBuilder, GenericMarkdownParser
from vexa.ai_providers.base import AIProviderStatus
from vexa.common.models import Finding

@pytest.fixture
def mock_findings():
    return [
        Finding(
            id="f1",
            scanner="test_scanner",
            severity="high",
            title="SQL Injection",
            description="Found a SQL injection",
            file_path="src/main.py",
            line_start=10,
            line_end=15,
            code_snippet="cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
            cwe_ids=["CWE-89"]
        )
    ]

@patch.dict(os.environ, {"VEXA_OPENAI_API_KEY": "test-key"})
def test_openai_provider_is_available():
    provider = OpenAIWrapper()
    assert provider.is_available == True

@patch.dict(os.environ, {"VEXA_OPENAI_API_KEY": ""})
def test_openai_provider_is_not_available_without_key():
    provider = OpenAIWrapper()
    assert provider.is_available == False

@pytest.mark.anyio
@patch.dict(os.environ, {"VEXA_OPENAI_API_KEY": "test-key"})
async def test_openai_check_availability_success():
    provider = OpenAIWrapper()
    
    # Mocking openai import check
    with patch("builtins.__import__", return_value=MagicMock()):
        status, msg = await provider.check_availability()
        assert status == AIProviderStatus.AVAILABLE

def test_openai_prompt_builder(mock_findings):
    builder = GenericPromptBuilder()
    prompt = builder.build_batch_prompt(mock_findings, app_context={"name": "test_app", "services": ["auth"]})
    
    assert "You are Vexa, an expert AI security assistant" in prompt
    assert "test_app" in prompt
    assert "SQL Injection" in prompt
    assert "cursor.execute" in prompt
    assert "Required Response Format" in prompt

def test_openai_markdown_parser(mock_findings):
    parser = GenericMarkdownParser()
    markdown = """
### Finding 1
#### Detailed Description
Detailed desc for SQLi
#### Attack Scenario
Attacker can drop tables.
#### Remediation Code
```python
cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
```
#### False Positive Analysis
- **Is False Positive**: false
- **Confidence**: 0.95
- **Explanation**: User input goes straight to query.
"""
    enhanced = parser.parse(markdown, mock_findings)
    assert len(enhanced) == 1
    assert enhanced[0].detailed_description == "Detailed desc for SQLi"
    assert enhanced[0].attack_scenario == "Attacker can drop tables."
    assert "cursor.execute" in enhanced[0].remediation_code
    assert enhanced[0].is_false_positive == False
    assert enhanced[0].false_positive_confidence == 0.95

