"""
Tests for SS-010: False Positive Detection via AI (>90% confidence).

Validates the prompt builder produces FP analysis sections and
the parser correctly extracts confidence scores.
"""

from vexa.ai_providers.prompts import GenericPromptBuilder, GenericMarkdownParser
from vexa.common.models import Finding


class TestFalsePositiveDetection:
    """SS-010: AI FP detection pipeline."""

    def test_prompt_includes_fp_analysis_section(self):
        """SS-010: Workspace scan prompts must request FP analysis."""
        builder = GenericPromptBuilder()
        finding = Finding(
            id="F1",
            scanner="bandit",
            severity="high",
            title="eval() usage",
            description="Use of eval",
            file_path="test_helpers.py",
            line_start=5,
            line_end=5,
        )
        prompt = builder.build_batch_prompt([finding], is_workspace_scan=True)
        assert "False Positive" in prompt
        assert "Confidence" in prompt

    def test_prompt_includes_remediation_section(self):
        """SS-010: Prompt must request remediation code."""
        builder = GenericPromptBuilder()
        finding = Finding(
            id="F1",
            scanner="bandit",
            severity="high",
            title="eval() usage",
            description="Use of eval",
            file_path="test.py",
            line_start=5,
            line_end=5,
        )
        prompt = builder.build_batch_prompt([finding], is_workspace_scan=False)
        assert "Remediation Code" in prompt

    def test_parser_extracts_fp_confidence(self):
        """SS-010: Parser must extract FP confidence >= 0.9."""
        parser = GenericMarkdownParser()
        md = """### Finding 1 Analysis
#### Description
This eval usage is in a test helper file used only for testing.

#### Attack Scenario
N/A — test file context.

#### Business Impact
No impact.

#### False Positive Analysis
- **Is False Positive**: true
- **Confidence**: 0.95
- **Explanation**: This eval is in a test file

#### Remediation Code
```python
# No fix needed — false positive
```
"""
        findings = [
            Finding(
                id="F1",
                scanner="bandit",
                severity="high",
                title="eval() usage",
                description="Use of eval",
                file_path="test_helpers.py",
                line_start=5,
                line_end=5,
            )
        ]
        results = parser.parse(md, findings)
        assert len(results) == 1
        assert results[0].false_positive_confidence >= 0.9
        assert results[0].is_false_positive is True

    def test_parser_handles_non_fp(self):
        """SS-010: Parser must handle true positive findings."""
        parser = GenericMarkdownParser()
        md = """### Finding 1 Analysis
#### Description
This os.system call passes unsanitized user input.

#### Attack Scenario
An attacker could inject arbitrary commands.

#### Business Impact
Full system compromise.

#### False Positive Analysis
- **Is False Positive**: false
- **Confidence**: 0.10
- **Explanation**: This is a real vulnerability

#### Remediation Code
```python
subprocess.run(['cmd'], shell=False)
```
"""
        findings = [
            Finding(
                id="F1",
                scanner="bandit",
                severity="critical",
                title="os.system",
                description="Command injection",
                file_path="app.py",
                line_start=10,
                line_end=10,
            )
        ]
        results = parser.parse(md, findings)
        assert len(results) == 1
        assert results[0].is_false_positive is False
        assert results[0].false_positive_confidence <= 0.2

    def test_rag_context_injected_into_prompt(self):
        """SS-010 + P2-RAG: RAG context should appear in prompt."""
        builder = GenericPromptBuilder()
        finding = Finding(
            id="F1",
            scanner="bandit",
            severity="high",
            title="eval() usage",
            description="Use of eval",
            file_path="test_helpers.py",
            line_start=5,
            line_end=5,
        )
        rag_contexts = {"F1": "[TEST FILE] test_helpers.py is a test file."}
        prompt = builder.build_batch_prompt(
            [finding], is_workspace_scan=True, rag_contexts=rag_contexts
        )
        assert "Zero-Telemetry RAG" in prompt
        assert "test_helpers.py is a test file" in prompt
