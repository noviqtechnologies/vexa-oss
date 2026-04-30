import re
from typing import List, Dict, Any, Optional

from vexa.common.models import Finding, EnhancedFinding
from vexa.common.logging import get_logger
from vexa.ai_providers.guides import get_guide

logger = get_logger(__name__)


class GenericPromptBuilder:
    """Build structured prompts for AI Providers (Gemini, OpenAI, Anthropic)."""

    SYSTEM_CONTEXT_TEMPLATE = """You are Vexa, an expert AI security assistant.

**Application context:**
- **Application name:** {app_name}
- **Cloud services detected:** {cloud_services}

Analyze the following security findings and provide enhanced details in Markdown format.
Strictly adhere to the **Critical Requirements** and the specific cloud guide below.

1. The remediation code you generate MUST be highly secure.
2. Ensure you do not introduce any new vulnerabilities or regressions while fixing the original flaw.
3. **ZERO-CHATTER RULE**: Do NOT include any explanations, comments, conversational text, or multiple variants inside the triple-backtick remediation block. The block MUST contain ONLY the pure, production-ready source code for a direct drop-in replacement.
4. Maintain a highly professional, objective, and corporate tone in all generated reports.

{enhancement_guide}

For each finding, provide the analysis in the exact structure specified. **NEVER leave the Remediation Code block empty; it must contain a valid code fix.** Failure to follow these requirements will result in invalid analysis."""

    def build_batch_prompt(self, findings: List[Finding], app_context: Optional[Dict[str, Any]] = None, is_workspace_scan: bool = False, rag_contexts: Optional[Dict[str, str]] = None) -> str:
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
            enhancement_guide=get_guide(cloud_type)
        )
        
        prompt = f"{system_context}\n\n"
        prompt += "## Security Findings to Analyze\n\n"
        
        rag_contexts = rag_contexts or {}
        
        for i, finding in enumerate(findings, 1):
            prompt += f"""### Finding {i}
- **Scanner**: {finding.scanner}
- **Severity**: {finding.severity}
- **Title**: {finding.title}
- **File**: {finding.file_path}
- **Lines**: {finding.line_start}-{finding.line_end}
- **Code**:
```
{finding.code_snippet}
```

"""
            # Inject local RAG context if available
            finding_id = str(getattr(finding, "id", ""))
            if finding_id and finding_id in rag_contexts:
                prompt += f"""#### Local Workspace Context (Zero-Telemetry RAG)
```
{rag_contexts[finding_id]}
```
Use this local context to assess whether this finding is a false positive.

"""
        
        prompt += self._get_response_template(is_workspace_scan)
        return prompt

    def _get_response_template(self, is_workspace_scan: bool) -> str:
        
        remediation_instruction = """#### Remediation Code
Provide a direct, exact, production-ready drop-in replacement for the specific lines of the provided vulnerable snippet. 

**SAFETY GUARDRAILS (FIX-03)**:
1. **Variable Persistence**: Maintain all original variable names, function signatures, and class names exactly as they appear in the original snippet.
2. **Logic Integrity**: Do NOT change the logic type. If the original snippet is an assignment (e.g., `VAR = "..."`), the remediation MUST also be an assignment. If it is a conditional check, it must remain a conditional check.
3. **Least Intrusive**: Perform the minimum amount of change necessary to resolve the security vulnerability while following best practices.
4. **Indentation**: Preserve all original indentation exactly as given. 

**STRICT OUTPUT RULES**:
- Do NOT include any surrounding code that was not in the original snippet.
- Do NOT include line numbers at the beginning of the lines. Only output the raw code.
- Provide REAL, working code designed for production. Do NOT output generic examples.
- Do NOT truncate the snippet. 
- Do NOT include ANY conversational text, explanations, or multiple choices inside the triple-backtick block. 
- The block must contain ONLY pure, copy-pasteable source code.

```
[Fixed code snippet only]
```"""

        template = """
## Required Response Format (for each finding)

### Finding N Analysis
"""

        # In workspace scans, we prioritize False Positives and rapid remediation.
        # In detailed scans, we include extensive breakdown.
        if is_workspace_scan:
             template += f"""
#### False Positive Analysis
- **Is False Positive**: [true|false]
- **Confidence**: [0.0-1.0]
- **Explanation**: [Required]

{remediation_instruction}
"""
        else:
             template += f"""
#### Detailed Description
[Comprehensive explanation of the vulnerability]

#### Attack Scenario
[Step-by-step attack scenario showing how this could be exploited]

#### Business Impact
[Impact on business operations, data, reputation. Do NOT include revenue loss details or financial estimates. Keep the tone professional.]

#### False Positive Analysis
- **Is False Positive**: [true|false]
- **Confidence**: [0.0-1.0]
- **Explanation**: [Required]

{remediation_instruction}

#### Implementation Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]

#### Verification Test Cases
- **Test Case 1**: [Description] -> **Expected Output**: [Output]

#### Google Cloud Documentation
- [Link 1](https://cloud.google.com/...)
- [Link 2](https://cloud.google.com/...)
"""
        return template


class GenericMarkdownParser:
    """Parse Markdown responses from AI Providers into EnhancedFindings."""
    
    FINDING_PATTERN = r"### \s*(?:Analysis\s+for\s+)?Finding\s*(\d+)(?::)?(?:\s*Analysis)?.*?(?:\n|$)"
    
    SECTION_PATTERNS = {
        "detailed_description": r"#### (?:Detailed\s+)?Description(?::)?\s*(.+?)(?=####|$)",
        "attack_scenario": r"#### Attack Scenario(?::)?\s*(.+?)(?=####|$)",
        "business_impact": r"#### Business Impact(?::)?\s*(.+?)(?=####|$)",
        "remediation_code": r"#### (?:Remediation Code|Proposed Fix)[^\n]*\n*```(?:\w+)?\s*(.*?)\s*```",
        "google_cloud_recommendation": r"#### (?:Google Cloud )?Recommendation(?::)?\s*(.+?)(?=####|$)",
        "test_cases": r"#### Verification Test Cases(?::)?\s*(.+?)(?=####|$)",
    }

    def parse(self, markdown_text: str, original_findings: List[Finding]) -> List[EnhancedFinding]:
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
                section = finding_sections[i+1]
                
                finding_idx = int(finding_idx_str) - 1 # 1-based to 0-based
                
                if finding_idx < 0 or finding_idx >= len(original_findings):
                    logger.warning(f"Parsed finding index {finding_idx} out of range")
                    continue
                    
                original = original_findings[finding_idx]
                
                detailed_description = self._extract("detailed_description", section)
                if not detailed_description:
                    detailed_description = original.description

                remediation = self._extract("remediation_code", section)
                
                # Pre-process remediation to strip hallucinated line numbers from AI (e.g., '15   subprocess.Popen()')
                if remediation:
                    cleaned_lines = []
                    for line in remediation.split('\n'):
                        # Strip lines starting with optional space, numbers, and space, maintaining remaining indent.
                        match = re.match(r'^(\s*)\d+\s+(.*)', line)
                        if match:
                            cleaned_lines.append(match.group(1) + match.group(2))
                        else:
                            cleaned_lines.append(line)
                    remediation = '\n'.join(cleaned_lines)
                
                enhanced.append(EnhancedFinding(
                    # Original fields
                    id=original.id,
                    scanner=original.scanner,
                    severity=original.severity,
                    title=original.title,
                    description=original.description,
                    file_path=original.file_path,
                    
                    # Parsed enhanced fields
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
                    implementation_steps=self._extract_list("Implementation Steps", section),
                    test_cases=self._extract_list_items("test_cases", section),
                    rollback_procedure="",
                    
                    google_cloud_recommendation=self._extract("google_cloud_recommendation", section),
                    google_cloud_doc_links=self._extract_links(section),
                    cwe_ids=original.cwe_ids,
                    owasp_category=original.owasp_category,
                    
                    # IMPORTANT: Centralized FP logic mapping
                    false_positive_confidence=self._extract_fp_confidence(section),
                    is_false_positive=self._extract_fp_status(section),
                    fp_explanation=self._extract_fp_explanation(section),
                ))
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
        
        # SPECIAL CASE: If remediation_code is empty, try to find ANY code block in this section
        if field == "remediation_code" and not res:
            logger.debug("Remediation Code section not found. Attempting fallback to any code block.")
            code_blocks = re.findall(r"```(?:\w+)?\s*(.*?)\s*```", section, re.DOTALL)
            for block in code_blocks:
                if len(block.strip()) > 10: # Likely actual code
                    return block.strip()

        return res

    def _extract_list(self, title: str, section: str) -> List[str]:
        pattern = fr"#### {title}\s+(.+?)(?=####|$)"
        match = re.search(pattern, section, re.DOTALL)
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
        pattern = r'http[s]?://cloud\.google\.com/[^\s\)]+'
        return re.findall(pattern, section)
    
    def _extract_fp_confidence(self, section: str) -> float:
        match = re.search(r'\*\*Confidence\*\*:\s*([\d.]+)', section)
        try:
            return float(match.group(1)) if match else 0.0
        except ValueError:
            return 0.0
    
    def _extract_fp_status(self, section: str) -> bool:
        match = re.search(r'\*\*Is False Positive\*\*:\s*(true|false)', section, re.IGNORECASE)
        # Note: We let the provider manager do the threshold logic. 
        # Here we just parse what the AI explicitly answered.
        return match.group(1).lower() == 'true' if match else False
        
    def _extract_fp_explanation(self, section: str) -> str:
        match = re.search(r'\*\*Explanation\*\*:\s*(.+)', section)
        return match.group(1).strip() if match else ""
