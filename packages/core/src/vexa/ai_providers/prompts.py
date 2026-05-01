import re
from typing import List, Dict, Any, Optional

from vexa.common.models import Finding, EnhancedFinding
from vexa.common.logging import get_logger
from vexa.ai_providers.guides import get_guide

logger = get_logger(__name__)


class GenericPromptBuilder:
    """Build structured prompts for AI Providers (Gemini, OpenAI, Anthropic)."""

    SYSTEM_CONTEXT_TEMPLATE = """You are Vexa, an elite AI Security Engineer specializing in cloud-native application security and automated remediation.

### ROLE AND OBJECTIVE
Your goal is to analyze security findings and provide high-fidelity, production-ready remediation. You must be precise, objective, and strictly follow the structured format to ensure automated parsing.

### APPLICATION CONTEXT
- **Application Name:** {app_name}
- **Cloud Environment:** {cloud_services}

### CRITICAL OPERATIONAL CONSTRAINTS
1. **ZERO HALLUCINATION POLICY**: 
   - Only use information provided in the finding or the local workspace context.
   - If a finding is a False Positive (FP), explicitly state it and return the ORIGINAL code.
   - Never invent environment variables, library names, or API endpoints that do not exist in the context.
2. **REMEDIATION INTEGRITY (FIX-03)**:
   - **Drop-in Replacement**: The code block must contain ONLY the replacement for the vulnerable snippet.
   - **Signature Preservation**: Maintain all original variable names, function signatures, and class names.
   - **Logic Continuity**: If the original was an assignment, the fix must be an assignment.
   - **Minimalism**: Apply the least intrusive change required to resolve the vulnerability.
3. **ZERO-CHATTER RULE**: 
   - The remediation code block (triple backticks) MUST NOT contain comments, explanations, or multiple variants. 
   - It must be pure, copy-pasteable source code.
4. **TONE**: Maintain a professional, technical, and corporate tone. Avoid flowery language.

### ENHANCEMENT GUIDE
{enhancement_guide}

### OUTPUT STRUCTURE
For each finding, you MUST provide the analysis in the exact Markdown structure specified below. Failure to follow the structure or leaving the Remediation Code block empty will result in a system failure."""

    def build_batch_prompt(
        self,
        findings: List[Finding],
        app_context: Optional[Dict[str, Any]] = None,
        is_workspace_scan: bool = False,
        rag_contexts: Optional[Dict[str, str]] = None,
    ) -> str:
        """Build prompt for batch of findings.

        Args:
            findings: List of findings to analyze.
            app_context: Application context metadata.
            is_workspace_scan: Whether this is a workspace-level scan.
            rag_contexts: Optional dict mapping finding_id -> local RAG context string.
        """

        app_context = app_context or {}
        app_name = app_context.get("name", "Unknown Application")
        services = ", ".join(app_context.get("services", ["Core Services"]))

        # Select guide based on app context
        cloud_type = app_context.get("cloud_provider", "google")

        system_context = self.SYSTEM_CONTEXT_TEMPLATE.format(
            app_name=app_name,
            cloud_services=services,
            enhancement_guide=get_guide(cloud_type),
        )

        prompt = f"{system_context}\n\n"
        prompt += "## SECURITY FINDINGS TO ANALYZE\n\n"

        rag_contexts = rag_contexts or {}

        for i, finding in enumerate(findings, 1):
            prompt += f"""### Finding {i}
- **Scanner**: {finding.scanner}
- **Severity**: {finding.severity}
- **Title**: {finding.title}
- **File**: {finding.file_path}
- **Lines**: {finding.line_start}-{finding.line_end}
- **Vulnerable Code Snippet**:
```
{finding.code_snippet}
```

"""
            # Inject local RAG context if available
            finding_id = str(getattr(finding, "id", ""))
            if finding_id and finding_id in rag_contexts:
                prompt += f"""#### Local Workspace Context (Zero-Telemetry RAG)
The following code context from the same workspace is provided to help you determine if this is a False Positive or to provide a more accurate fix:
```
{rag_contexts[finding_id]}
```
**Instruction**: Use this context to verify if the vulnerability is actually reachable or if it's already mitigated elsewhere in the file.

"""

        prompt += self._get_response_template(is_workspace_scan)
        return prompt

    def _get_response_template(self, is_workspace_scan: bool) -> str:

        remediation_instruction = """#### Remediation Code
Provide a direct, production-ready drop-in replacement for the vulnerable snippet.

**Strict Rules**:
- No line numbers.
- No conversational text inside the block.
- Preserve indentation.
- If it's an FP, return the original code exactly.

```
[Fixed code snippet only]
```"""

        template = """
## REQUIRED RESPONSE FORMAT (FOR EACH FINDING)

### Finding N Analysis
"""

        if is_workspace_scan:
            template += f"""
#### False Positive Analysis
- **Is False Positive**: [true|false]
- **Confidence**: [0.0 to 1.0]
- **Explanation**: [Provide a concise technical justification for the FP status]

{remediation_instruction}
"""
        else:
            template += f"""
#### Detailed Description
[Provide a deep technical analysis of the vulnerability, why it occurs, and the specific risk it poses to this application.]

#### Attack Scenario
[Describe a step-by-step technical exploit path that an attacker could take to leverage this vulnerability.]

#### Business Impact
[Explain the potential impact on data confidentiality, integrity, and availability. Focus on technical and operational risks.]

#### False Positive Analysis
- **Is False Positive**: [true|false]
- **Confidence**: [0.0 to 1.0]
- **Explanation**: [Provide a concise technical justification for the FP status]

{remediation_instruction}

#### Implementation Steps
1. [Step 1: Preparation]
2. [Step 2: Code Change]
3. [Step 3: Verification]

#### Verification Test Cases
- **Test Case 1**: [Description of the test] -> **Expected Result**: [What success looks like]

#### Documentation References
- [Reference 1](URL)
- [Reference 2](URL)
"""
        return template


class GenericMarkdownParser:
    """Parse Markdown responses from AI Providers into EnhancedFindings."""

    # Improved pattern to be more resilient to variations in "Finding N Analysis"
    FINDING_PATTERN = (
        r"### \s*(?:Analysis\s+for\s+)?Finding\s*(\d+)(?::)?(?:\s*Analysis)?.*?(?:\n|$)"
    )

    SECTION_PATTERNS = {
        "detailed_description": r"#### (?:Detailed\s+)?Description(?::)?\s*(.+?)(?=####|$)",
        "attack_scenario": r"#### Attack Scenario(?::)?\s*(.+?)(?=####|$)",
        "business_impact": r"#### Business Impact(?::)?\s*(.+?)(?=####|$)",
        "remediation_code": r"#### (?:Remediation Code|Proposed Fix)[^\n]*\n*```(?:\w+)?\s*(.*?)\s*```",
        "recommendation": r"#### (?:Google Cloud |Documentation )?References?(?::)?\s*(.+?)(?=####|$)",
        "test_cases": r"#### Verification Test Cases(?::)?\s*(.+?)(?=####|$)",
    }

    def parse(
        self, markdown_text: str, original_findings: List[Finding]
    ) -> List[EnhancedFinding]:
        """Parse markdown response and merge with original findings."""
        if not markdown_text:
            logger.warning("Empty markdown response received from AI")
            return []

        # Split by finding sections
        finding_sections = re.split(self.FINDING_PATTERN, markdown_text)

        enhanced = []

        for i in range(1, len(finding_sections), 2):
            try:
                finding_idx_str = finding_sections[i]
                section = finding_sections[i + 1]

                finding_idx = int(finding_idx_str) - 1  # 1-based to 0-based

                if finding_idx < 0 or finding_idx >= len(original_findings):
                    logger.warning(f"Parsed finding index {finding_idx} out of range")
                    continue

                original = original_findings[finding_idx]

                detailed_description = self._extract("detailed_description", section)
                if not detailed_description:
                    detailed_description = original.description

                remediation = self._extract("remediation_code", section)

                # Pre-process remediation to strip hallucinated line numbers from AI
                if remediation:
                    cleaned_lines = []
                    for line in remediation.split("\n"):
                        # Strip lines starting with optional space, numbers, and space, maintaining remaining indent.
                        match = re.match(r"^(\s*)\d+\s+(.*)", line)
                        if match:
                            cleaned_lines.append(match.group(1) + match.group(2))
                        else:
                            cleaned_lines.append(line)
                    remediation = "\n".join(cleaned_lines)

                enhanced.append(
                    EnhancedFinding(
                        id=original.id,
                        scanner=original.scanner,
                        severity=original.severity,
                        title=original.title,
                        description=original.description,
                        file_path=original.file_path,
                        detailed_description=detailed_description,
                        attack_scenario=self._extract("attack_scenario", section),
                        business_impact=self._extract("business_impact", section),
                        exploitability="unknown",
                        code_snippet=original.code_snippet,
                        code_snippet_before=original.code_snippet,
                        code_snippet_after=remediation,
                        line_start=original.line_start,
                        line_end=original.line_end,
                        remediation_code=remediation,
                        remediation_guidance=detailed_description,
                        cli_commands=[],
                        implementation_steps=self._extract_list(
                            "Implementation Steps", section
                        ),
                        test_cases=self._extract_list_items("test_cases", section),
                        rollback_procedure="",
                        google_cloud_recommendation=self._extract(
                            "recommendation", section
                        ),
                        google_cloud_doc_links=self._extract_links(section),
                        cwe_ids=original.cwe_ids,
                        owasp_category=original.owasp_category,
                        false_positive_confidence=self._extract_fp_confidence(section),
                        is_false_positive=self._extract_fp_status(section),
                        fp_explanation=self._extract_fp_explanation(section),
                    )
                )
            except (ValueError, IndexError) as e:
                logger.error(f"Failed to parse finding index from section: {e}")
            except Exception as e:
                logger.error(f"Unexpected error parsing finding section: {e}")

        return enhanced

    def _extract(self, field: str, section: str) -> str:
        pattern = self.SECTION_PATTERNS.get(field)
        if not pattern:
            return ""

        match = re.search(pattern, section, re.DOTALL | re.IGNORECASE)
        res = match.group(1).strip() if match and match.groups() else ""

        # Fallback for remediation_code
        if field == "remediation_code" and not res:
            code_blocks = re.findall(r"```(?:\w+)?\s*(.*?)\s*```", section, re.DOTALL)
            for block in code_blocks:
                if len(block.strip()) > 10:
                    return block.strip()

        return res

    def _extract_list(self, title: str, section: str) -> List[str]:
        pattern = rf"#### {title}\s+(.+?)(?=####|$)"
        match = re.search(pattern, section, re.DOTALL | re.IGNORECASE)
        if not match:
            return []
        content = match.group(1)
        return re.findall(r"^\d+\.\s+(.+)$", content, re.MULTILINE)

    def _extract_list_items(self, field: str, section: str) -> List[str]:
        content = self._extract(field, section)
        if not content:
            return []
        return re.findall(r"(?:-|\*|\d+\.)\s+(.+)$", content, re.MULTILINE)

    def _extract_links(self, section: str) -> List[str]:
        # Broaden link extraction to any valid URL
        pattern = r"https?://[^\s\)]+"
        return re.findall(pattern, section)

    def _extract_fp_confidence(self, section: str) -> float:
        match = re.search(r"\*\*Confidence\*\*:\s*\[?([\d.]+)\]?", section, re.IGNORECASE)
        try:
            return float(match.group(1)) if match else 0.0
        except ValueError:
            return 0.0

    def _extract_fp_status(self, section: str) -> bool:
        match = re.search(
            r"\*\*Is False Positive\*\*:\s*\[?(true|false)\]?", section, re.IGNORECASE
        )
        return match.group(1).lower() == "true" if match else False

    def _extract_fp_explanation(self, section: str) -> str:
        match = re.search(r"\*\*Explanation\*\*:\s*\[?(.+?)\]?(?:\n|$)", section, re.IGNORECASE)
        return match.group(1).strip() if match else ""
