import asyncio
import re
import shutil
import os
from typing import List, Dict, Any, Optional, AsyncIterator
from pathlib import Path

from vexa.common.models import Finding, AzureEnhancedFinding
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
class AzurePromptBuilder(PromptBuilder):
    """Build structured prompts for Azure CLI"""
    
    SYSTEM_CONTEXT_TEMPLATE = """You are an Azure security expert. 
    
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
        services = ", ".join(app_context.get("services", ["Azure Core Services"]))
        
        # Select guide based on app context or default to azure
        cloud_type = app_context.get("cloud_provider", "azure")
        
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
[Comprehensive explanation of the vulnerability]

#### Attack Scenario
[Step-by-step attack scenario showing how this could be exploited]

#### Business Impact
[Impact on business operations, data, reputation. Do NOT include revenue loss details or financial estimates. Keep the tone professional.]

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

#### Azure Recommendation
[Azure-specific security recommendation aligned with Azure Security Benchmark]

#### Azure Security Benchmark Pillar
[Network Security|Identity Management|Privileged Access|Data Protection|Asset Management|Logging and Threat Detection|Incident Response|Posture and Vulnerability Management|Endpoint Security|Backup and Recovery]

#### Implementation Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]

#### Verification Test Cases
- **Test Case 1**: [Description] -> **Expected Output**: [Output]

#### Azure Documentation
- [Link 1](https://learn.microsoft.com/azure/...)
- [Link 2](https://learn.microsoft.com/azure/...)
"""

# --- 2. CLI Executor ---
class AzureCLIExecutor(CLIExecutor):
    """Execute Azure OpenAI via 'az rest' - no extensions required"""
    
    COMMAND = "az"
    TIMEOUT = AI_BATCH_TIMEOUT
    # Azure OpenAI API version
    API_VERSION = "2024-08-01-preview"
    
    def _get_azure_openai_config(self) -> tuple:
        """Get Azure OpenAI endpoint and deployment from environment."""
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        if not endpoint:
            raise RuntimeError(
                "AZURE_OPENAI_ENDPOINT environment variable not set. "
                "Set it to your Azure OpenAI resource endpoint, e.g.: "
                "https://<your-resource>.openai.azure.com"
            )
        
        # Ensure endpoint doesn't have trailing slash
        endpoint = endpoint.rstrip("/")
        return endpoint, deployment
    
    async def execute(self, prompt: str) -> str:
        """Execute Azure OpenAI via 'az rest' and return markdown response"""
        import json as _json
        
        full_path = shutil.which(self.COMMAND)
        if not full_path:
            raise FileNotFoundError(f"CLI command '{self.COMMAND}' not found.")

        endpoint, deployment = self._get_azure_openai_config()
        
        # Build the Azure OpenAI Chat Completions REST URL
        url = (
            f"{endpoint}/openai/deployments/{deployment}"
            f"/chat/completions?api-version={self.API_VERSION}"
        )
        
        # Build the request body
        body = _json.dumps({
            "messages": [
                {"role": "system", "content": "You are an Azure security expert. Respond in Markdown format."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 4096
        })
        
        # Use 'az rest' which handles authentication automatically
        # SEC-006: shell=False enforced
        if os.name == 'nt' and full_path.lower().endswith('.cmd'):
            cmd = [
                "cmd.exe", "/c", full_path,
                "rest",
                "--method", "POST",
                "--url", url,
                "--body", body,
                "--resource", "https://cognitiveservices.azure.com",
            ]
        else:
            cmd = [
                full_path,
                "rest",
                "--method", "POST",
                "--url", url,
                "--body", body,
                "--resource", "https://cognitiveservices.azure.com",
            ]
        
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
                process.communicate(),
                timeout=self.TIMEOUT
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                if any(kw in error_msg.lower() for kw in ["429", "quota", "rate limit"]):
                     raise RuntimeError(f"Azure AI Quota Exceeded: {error_msg}")
                     
                logger.error("Azure CLI failed (Exit %d): %s", process.returncode, error_msg)
                raise RuntimeError(f"Azure CLI Error: {error_msg}")
            
            # Parse the JSON response and extract the assistant's message content
            response_data = _json.loads(stdout.decode())
            choices = response_data.get("choices", [])
            if not choices:
                raise RuntimeError("Azure OpenAI returned empty response")
            
            content = choices[0].get("message", {}).get("content", "")
            return self.clean_output(content)
            
        except asyncio.TimeoutError:
             logger.error("Azure CLI timed out after %d seconds", self.TIMEOUT)
             try:
                 process.kill()
             except:
                 pass
             raise RuntimeError(f"Azure CLI Timed Out ({self.TIMEOUT}s)")
        except RuntimeError:
             raise
        except Exception as e:
             logger.exception("Azure CLI execution failed: %s", e)
             raise e

# --- 3. Markdown Parser ---
class AzureMarkdownParser(MarkdownParser):
    """Parse Azure CLI markdown response into AzureEnhancedFindings"""
    
    FINDING_PATTERN = r"### \s*(?:Analysis\s+for\s+)?Finding\s*(\d+)(?::)?(?:\s*Analysis)?.*?(?:\n|$)"
    SECTION_PATTERNS = {
        "detailed_description": r"#### (?:Detailed\s+)?Description(?::)?\s*(.+?)(?=####|$)",
        "attack_scenario": r"#### Attack Scenario(?::)?\s*(.+?)(?=####|$)",
        "business_impact": r"#### Business Impact(?::)?\s*(.+?)(?=####|$)",
        "remediation_code": r"#### (?:Remediation Code|Code Snippets).*?After\*\*:(?::)?\s*```(?:\w+)?[\s\n]+(.*?)```",
        "code_after": r"#### (?:Remediation Code|Code Snippets).*?After\*\*:(?::)?\s*```(?:\w+)?[\s\n]+(.*?)```",
        "azure_recommendation": r"#### Azure Recommendation(?::)?\s*(.+?)(?=####|$)",
        "azure_benchmark_pillar": r"#### Azure Security Benchmark Pillar(?::)?\s*(.+?)(?=####|$)",
        "test_cases": r"#### Verification Test Cases(?::)?\s*(.+?)(?=####|$)",
    }
    
    def parse(self, markdown_text: str, original_findings: List[Finding]) -> List[AzureEnhancedFinding]:
        """Parse markdown response and merge with original findings"""
        if not markdown_text:
            return []
            
        finding_sections = re.split(self.FINDING_PATTERN, markdown_text)
        enhanced = []
        
        for i in range(1, len(finding_sections), 2):
            try:
                finding_idx = int(finding_sections[i]) - 1
                section = finding_sections[i+1]
                
                if finding_idx < 0 or finding_idx >= len(original_findings):
                    continue
                    
                original = original_findings[finding_idx]
                
                detailed_description = self._extract("detailed_description", section)
                if not detailed_description:
                    detailed_description = original.description

                enhanced.append(AzureEnhancedFinding(
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
                    code_snippet_after=self._extract("code_after", section),
                    line_start=original.line_start,
                    line_end=original.line_end,
                    remediation_code=self._extract("remediation_code", section),
                    implementation_steps=self._extract_list("Implementation Steps", section),
                    test_cases=self._extract_list_items("test_cases", section),
                    rollback_procedure="",
                    azure_recommendation=self._extract("azure_recommendation", section),
                    azure_security_benchmark_pillar=self._extract("azure_benchmark_pillar", section),
                    azure_doc_links=self._extract_links(section),
                    cwe_ids=original.cwe_ids,
                    owasp_category=original.owasp_category,
                    false_positive_confidence=self._extract_fp_confidence(section),
                    is_false_positive=self._extract_fp_status(section),
                    fp_explanation=self._extract_fp_explanation(section),
                ))
            except Exception as e:
                logger.error(f"Error parsing Azure finding section: {e}")
                
        return enhanced
    
    def _extract(self, field: str, section: str) -> str:
        pattern = self.SECTION_PATTERNS[field]
        match = re.search(pattern, section, re.DOTALL | re.IGNORECASE)
        return match.group(1).strip() if match else ""
    
    def _extract_list(self, title: str, section: str) -> List[str]:
        pattern = fr"#### {title}\s+(.+?)(?=####|$)"
        match = re.search(pattern, section, re.DOTALL)
        if not match: return []
        return re.findall(r"^\d+\.\s+(.+)$", match.group(1), re.MULTILINE)
    
    def _extract_list_items(self, field: str, section: str) -> List[str]:
        content = self._extract(field, section)
        if not content: return []
        return re.findall(r"(?:-|\*|\d+\.)\s+(.+)$", content, re.MULTILINE)

    def _extract_links(self, section: str) -> List[str]:
        return re.findall(r'http[s]?://learn\.microsoft\.com/[^\s\)]+', section)
    
    def _extract_fp_confidence(self, section: str) -> float:
        match = re.search(r'\*\*Confidence\*\*:\s*([\d.]+)', section)
        return float(match.group(1)) if match else 0.0
    
    def _extract_fp_status(self, section: str) -> bool:
        match = re.search(r'\*\*Is False Positive\*\*:\s*(true|false)', section, re.I)
        return match.group(1).lower() == 'true' if match else False
        
    def _extract_fp_explanation(self, section: str) -> str:
        match = re.search(r'\*\*Explanation\*\*:\s*(.+)', section)
        return match.group(1).strip() if match else ""

# --- 4. Wrapper ---
class AzureCLIWrapper(BaseAIProvider):
    """Azure AI CLI Provider Implementation"""
    
    PROVIDER_TYPE = AIProviderType.AZURE
    
    def __init__(self):
        self.prompt_builder = AzurePromptBuilder()
        self.executor = AzureCLIExecutor()
        self.parser = AzureMarkdownParser()
        self._is_available = shutil.which("az") is not None
        
    @property
    def is_available(self) -> bool:
        return self._is_available
        
    async def check_availability(self) -> tuple[AIProviderStatus, str]:
        if not self._is_available:
            return AIProviderStatus.UNAVAILABLE, "Azure CLI not found (install from https://aka.ms/installazurecliwindows)"
        
        # Check for AI extension or similar
        try:
             process = await asyncio.create_subprocess_exec(
                "az", "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
             )
             stdout, stderr = await process.communicate()
             if process.returncode != 0:
                  return AIProviderStatus.UNAVAILABLE, "Azure CLI is installed but not functioning correctly"
        except Exception as e:
             return AIProviderStatus.UNAVAILABLE, f"Azure CLI check failed: {str(e)}"

        return AIProviderStatus.AVAILABLE, "Ready"

    async def analyze_findings_batch(
        self, 
        findings: List[Finding], 
        code_contexts: Dict[str, str],
        batch_size: int = 5,
        app_context: Optional[Dict[str, Any]] = None
    ) -> List[AzureEnhancedFinding]:
        if not findings:
            return []
            
        prompt = self.prompt_builder.build_batch_prompt(findings, app_context=app_context)
        
        try:
            markdown_response = await self.executor.execute(prompt)
            return self.parser.parse(markdown_response, findings)
        except Exception as e:
            logger.exception("Azure analysis failed for batch")
            raise e

    def enhance_finding(self, finding: Finding, analysis: Any) -> AzureEnhancedFinding:
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

def get_azure_wrapper() -> AzureCLIWrapper:
    return AzureCLIWrapper()
