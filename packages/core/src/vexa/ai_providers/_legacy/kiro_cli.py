import asyncio
import re
import shutil
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from vexa.common.models import Finding, KiroEnhancedFinding, EnhancedFinding
from vexa.common.logging import get_logger
from vexa.ai_providers.base import (
    BaseAIProvider, 
    AIProviderType, 
    AIProviderStatus,
    PromptBuilder,
    CLIExecutor,
    MarkdownParser
)
from vexa.common.config import AI_BATCH_TIMEOUT

from vexa.ai_providers.guides import get_guide

logger = get_logger(__name__)

# --- 1. Prompt Builder ---
class KiroPromptBuilder(PromptBuilder):
    """Build structured prompts for Kiro CLI with Application Context"""
    
    SYSTEM_CONTEXT_TEMPLATE = """You are a security expert with deep knowledge of 
cloud security best practices. 

**Application context:**
- **Application name:** {app_name}
- **Cloud services detected:** {cloud_services}

Analyze the following security findings and provide enhanced details in Markdown format.
Strictly adhere to the **Critical Requirements** and the specific cloud guide below.

{enhancement_guide}

For each finding, provide the analysis in the exact structure specified. Failure to follow these requirements will result in invalid analysis."""

    def build_batch_prompt(self, findings: List[Finding], app_context: Optional[Dict[str, Any]] = None) -> str:
        """Build prompt for batch of findings"""
        
        app_context = app_context or {}
        app_name = app_context.get("name", "Unknown Application")
        services = ", ".join(app_context.get("services", ["AWS Core Services"]))
        
        # Select guide based on app context or default to aws
        cloud_type = app_context.get("cloud_provider", "aws")
        
        system_context = self.SYSTEM_CONTEXT_TEMPLATE.format(
            app_name=app_name,
            cloud_services=services,
            enhancement_guide=get_guide(cloud_type)
        )
        
        prompt = f"{system_context}\n\n"
        prompt += "## Security Findings to Analyze\n\n"
        
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
        
        prompt += self._get_response_template()
        return prompt
    
    def _get_response_template(self) -> str:
        return """
## Required Response Format (for each finding)

### Finding N Analysis

#### Detailed Description
[Comprehensive explanation]

#### Attack Scenario
[Step-by-step exploit]

#### Business Impact
[Impact on business operations, data, reputation. Do NOT include revenue loss details or financial estimates. Keep the tone professional.]

# #### Exploitability
# [easy|medium|hard]

#### False Positive Analysis
- **Is False Positive**: [true|false]
- **Confidence**: [0.0-1.0]
- **Explanation**: [Required]

#### Code Snippets
- **Before**: 
```
[Original vulnerable code snippet]
```
Lines: [start]-[end]

- **After**:
```
[Fixed code snippet showing remediation]
```

# #### Remediation CLI Commands
# ```bash
# # Provide aws CLI commands to implement the fix
# ```

#### Implementation Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]

#### Verification Test Cases
- **Test Case 1**: [Description] -> **Expected Output**: [Output]

#### Kiro Documentation
- [Link 1](https://docs.kiro.ai/...)
- [Link 2](https://kiro.ai/...)
"""

# --- 2. CLI Executor ---
class KiroCLIExecutor(CLIExecutor):
    """Execute Kiro CLI commands with proper error handling"""
    
    COMMAND = "kiro"
    TIMEOUT = AI_BATCH_TIMEOUT  # seconds per batch
    
    async def execute(self, prompt: str) -> str:
        """Execute Kiro CLI and return markdown response"""
        
        # Use absolute path for Windows compatibility
        full_path = shutil.which(self.COMMAND)
        if not full_path:
            raise FileNotFoundError(f"CLI command '{self.COMMAND}' not found.")

        # SEC-006: shell=False enforced
        # On Windows, we must use cmd.exe /c to run .CMD files safely without shell=True
        if os.name == 'nt' and full_path.lower().endswith('.cmd'):
            cmd = ["cmd.exe", "/c", full_path, "chat"]
        else:
            cmd = [full_path, "chat"]
        # Note: 'kiro-cli chat' typically interactive or takes input via stdin nicely.
        
        env = os.environ.copy()
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=prompt.encode()),
                timeout=self.TIMEOUT
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                # Check for quota error specifically to provide better feedback
                if any(kw in error_msg.lower() for kw in ["429", "quota", "exhausted your capacity", "rate limit"]):
                     raise RuntimeError(f"Kiro CLI Quota Exceeded: {error_msg}")
                     
                logger.error("Kiro CLI failed (Exit %d): %s", process.returncode, error_msg)
                raise RuntimeError(f"Kiro CLI Error: {error_msg}")
            
            return self.clean_output(stdout.decode())
            
        except asyncio.TimeoutError:
             logger.error("Kiro CLI timed out after %d seconds", self.TIMEOUT)
             try:
                 process.kill()
             except:
                 pass
             raise RuntimeError(f"Kiro CLI Timed Out ({self.TIMEOUT}s)")
        except Exception as e:
             logger.exception("Kiro CLI execution failed: %s", e)
             raise e

# --- 3. Markdown Parser ---
class KiroMarkdownParser(MarkdownParser):
    """Parse Kiro CLI markdown response into KiroEnhancedFindings"""
    
    FINDING_PATTERN = r"### \s*(?:Analysis\s+for\s+)?Finding\s*(\d+)(?::)?(?:\s*Analysis)?.*?(?:\n|$)"
    SECTION_PATTERNS = {
        "detailed_description": r"#### (?:Detailed\s+)?Description(?::)?\s*(.+?)(?=####|$)",
        "attack_scenario": r"#### Attack Scenario(?::)?\s*(.+?)(?=####|$)",
        "business_impact": r"#### Business Impact(?::)?\s*(.+?)(?=####|$)",
        # "exploitability": r"#### Exploitability(?::)?\s*(?:\[)?(\w+)(?:\])?",
        "remediation_code": r"#### Remediation Code.*?```(?:\w+)?[\s\n]+(.*?)```",
        "code_after": r"#### Code Snippets.*?After\*\*:(?::)?\s*```(?:\w+)?[\s\n]+(.*?)```",
        # "cli_commands": r"#### Remediation CLI Commands(?::)?\s*```(?:\w+)?[\s\n]+(.*?)```",
        "kiro_recommendation": r"#### (?:Kiro )?Recommendation(?::)?\s*(.+?)(?=####|$)",
        "kiro_well_architected_pillar": r"#### Kiro Well-Architected Pillar(?::)?\s+(\w+)",
        "test_cases": r"#### Verification Test Cases(?::)?\s*(.+?)(?=####|$)",
    }
    
    def parse(self, markdown: str, original_findings: List[Finding]) -> List[KiroEnhancedFinding]:
        """Parse markdown response and merge with original findings"""
        
        finding_sections = re.split(self.FINDING_PATTERN, markdown)
        
        enhanced = []
        for i in range(1, len(finding_sections), 2):
            try:
                finding_idx = int(finding_sections[i]) - 1
                section = finding_sections[i+1]
                
                if finding_idx < 0 or finding_idx >= len(original_findings):
                    logger.warning(f"Parsed finding index {finding_idx} out of range")
                    continue
                    
                original = original_findings[finding_idx]
                
                enhanced.append(KiroEnhancedFinding(
                    # Original fields
                    id=original.id,
                    scanner=original.scanner,
                    severity=original.severity,
                    title=original.title,
                    description=original.description,
                    file_path=original.file_path,
                    
                    # Parsed enhanced fields
                    detailed_description=self._extract("detailed_description", section) or original.description,
                    attack_scenario=self._extract("attack_scenario", section),
                    business_impact=self._extract("business_impact", section),
                    # exploitability=(self._extract("exploitability", section) or "unknown").lower(),
exploitability="unknown",
                    
                    code_snippet=original.code_snippet,
                    code_snippet_before=original.code_snippet,
                    code_snippet_after=self._extract("code_after", section),
                    line_start=original.line_start,
                    line_end=original.line_end,
                    
                    remediation_code=self._extract("remediation_code", section),
                    # cli_commands=self._extract_code_lines("cli_commands", section),
cli_commands=[],
                    implementation_steps=self._extract_list("Implementation Steps", section),
                    test_cases=self._extract_list_items("test_cases", section),
                    rollback_procedure="",
                    
                    kiro_recommendation=self._extract("kiro_recommendation", section),
                    kiro_well_architected_pillar=self._extract("kiro_well_architected_pillar", section),
                    kiro_doc_links=self._extract_links(section),
                    cwe_ids=original.cwe_ids,
                    owasp_category=original.owasp_category,
                    
                    false_positive_confidence=self._extract_fp_confidence(section),
                    is_false_positive=self._extract_fp_status(section),
                    fp_explanation=self._extract_fp_explanation(section),
                ))
            except Exception as e:
                logger.error(f"Failed to parse Kiro finding section: {e}")
                
        return enhanced
    
    def _extract(self, field: str, section: str) -> str:
        pattern = self.SECTION_PATTERNS[field]
        match = re.search(pattern, section, re.DOTALL | re.IGNORECASE)
        
        if not match:
             # Fallback for simpler headers without ####
            simple_pattern = pattern.replace("#### ", "####? ")
            match = re.search(simple_pattern, section, re.DOTALL | re.IGNORECASE)

        res = match.group(1).strip() if match else ""
        if not res and field not in ["remediation_code", "code_after"]:
             logger.debug(f"Kiro Parser: Could not extract field '{field}' from section")
        return res

    def _extract_list(self, title: str, section: str) -> List[str]:
        # Simple extraction of numbered lists under a header
        pattern = fr"#### {title}\s+(.+?)(?=####|$)"
        match = re.search(pattern, section, re.DOTALL)
        if not match:
            return []
        content = match.group(1)
        # Extract lines starting with numbers
        return re.findall(r"^\d+\.\s+(.+)$", content, re.MULTILINE)

    def _extract_code_lines(self, field: str, section: str) -> List[str]:
        code = self._extract(field, section)
        if not code:
            return []
        return [line.strip() for line in code.split("\n") if line.strip()]

    def _extract_list_items(self, field: str, section: str) -> List[str]:
        content = self._extract(field, section)
        if not content:
            return []
        # Find lines starting with - or * or numbers
        return re.findall(r"(?:-|\*|\d+\.)\s+(.+)$", content, re.MULTILINE)
        pattern = fr"#### {title}\s+(.+?)(?=####|$)"
        match = re.search(pattern, section, re.DOTALL)
        if not match:
            return []
        content = match.group(1)
        return re.findall(r"^\d+\.\s+(.+)$", content, re.MULTILINE)
    
        """Extract Kiro documentation links"""
        pattern = r'http[s]?://(?:docs\.)?kiro\.ai/[^\s\)]+'
        return re.findall(pattern, section)
    
    def _extract_fp_confidence(self, section: str) -> float:
        match = re.search(r'\*\*Confidence\*\*:\s*([\d.]+)', section)
        try:
            return float(match.group(1)) if match else 0.0
        except ValueError:
            return 0.0
    
    def _extract_fp_status(self, section: str) -> bool:
        match = re.search(r'\*\*Is False Positive\*\*:\s*(true|false)', section, re.I)
        return match.group(1).lower() == 'true' if match else False

    def _extract_fp_explanation(self, section: str) -> str:
        match = re.search(r'\*\*Explanation\*\*:\s*(.+)', section)
        return match.group(1).strip() if match else ""

# --- 4. Wrapper ---

class KiroCLIWrapper(BaseAIProvider):
    """Kiro CLI Provider Implementation"""
    
    PROVIDER_TYPE = AIProviderType.AWS
    
    def __init__(self):
        self.prompt_builder = KiroPromptBuilder()
        self.executor = KiroCLIExecutor()
        self.parser = KiroMarkdownParser()
        self._is_available = shutil.which("kiro") is not None
        
    @property
    def is_available(self) -> bool:
        return self._is_available
        
    async def check_availability(self) -> tuple[AIProviderStatus, str]:
        if not self._is_available:
            return AIProviderStatus.UNAVAILABLE, "Kiro CLI not found (install from Kiro documentation)"
        
        # Check Execution
        try:
            process = await asyncio.create_subprocess_exec(
                "kiro", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                return AIProviderStatus.UNAVAILABLE, f"Kiro CLI error: {stderr.decode().strip()}"
        except Exception as e:
            return AIProviderStatus.UNAVAILABLE, f"Kiro CLI check failed: {str(e)}"

        return AIProviderStatus.AVAILABLE, "Ready"

    async def analyze_findings_batch(
        self, 
        findings: List[Finding], 
        code_contexts: Dict[str, str],
        batch_size: int = 5,
        app_context: Optional[Dict[str, Any]] = None
    ) -> List[KiroEnhancedFinding]:
        """Process findings, typically a single batch passed from the manager."""
        
        if not findings:
            return []
            
        prompt = self.prompt_builder.build_batch_prompt(findings, app_context=app_context)
        
        try:
            markdown_response = await self.executor.execute(prompt)
            logger.info("Received Kiro AI response length: %d characters", len(markdown_response))
            
            # Diagnostic: Log first 200 chars to help identify structure issues
            if len(markdown_response) > 0:
                  logger.debug("Kiro AI Response Start: %s...", markdown_response[:200].replace("\n", " "))
                 
            return self.parser.parse(markdown_response, findings)
        except Exception as e:
            logger.exception("Kiro Analysis failed for batch of %d findings: %s", len(findings), e)
            raise e

    def enhance_finding(self, finding: Finding, analysis: Any) -> EnhancedFinding:
        pass
        
    async def generate_stride_analysis(self, repo_path: Any, category: str) -> Dict[str, Any]:
        return {"error": "Not implemented"}

    async def test_connection(self) -> tuple[AIProviderStatus, str]:
        """Perform a minimal AI request to verify connectivity and quota."""
        try:
            # Minimal prompt to check connectivity and quota
            await self.executor.execute("hi")
            return AIProviderStatus.AVAILABLE, "Ready"
        except RuntimeError as e:
            err_msg = str(e)
            if any(kw in err_msg.lower() for kw in ["429", "quota", "rate limit", "exhausted"]):
                return AIProviderStatus.ERROR, "AI Analysis Failed: Quota Exceeded (429)"
            return AIProviderStatus.ERROR, f"AI Connection Failed: {err_msg}"
        except Exception as e:
            return AIProviderStatus.ERROR, f"AI Connection Failed: {str(e)}"

def get_kiro_wrapper() -> KiroCLIWrapper:
    return KiroCLIWrapper()
