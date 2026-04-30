import asyncio
import re
import shutil
import os
from typing import List, Dict, Any, Optional, AsyncIterator
from pathlib import Path

from vexa.common.models import Finding, EnhancedFinding
from vexa.common.logging import get_logger
from vexa.ai_providers.base import (
    BaseAIProvider, 
    AIProviderType, 
    AIProviderStatus,
    CLIExecutor
)
from vexa.ai_providers.prompts import GenericPromptBuilder, GenericMarkdownParser
from vexa.common.config import AI_BATCH_TIMEOUT

logger = get_logger(__name__)

# The Gemini Prompt Builder and Parser have been centralized. 
# We now use GenericPromptBuilder and GenericMarkdownParser from `vexa.ai_providers.prompts`
class GeminiCLIExecutor(CLIExecutor):
    """Execute Gemini CLI commands with proper error handling"""
    
    COMMAND = "gemini"
    TIMEOUT = AI_BATCH_TIMEOUT  # seconds per batch
    
    async def execute(self, prompt: str) -> str:
        """Execute gemini CLI and return markdown response"""
        
        # Use absolute path for Windows compatibility with .CMD files
        full_path = shutil.which(self.COMMAND)
        if not full_path:
            raise FileNotFoundError(f"CLI command '{self.COMMAND}' not found.")

        # SEC-006: shell=False enforced
        # Use -o text as per 'gemini chat --help' choices
        # On Windows, we must use cmd.exe /c to run .CMD files safely without shell=True
        # We use --prompt to force headless mode, passing a prefix as arg and the rest via stdin
        headless_arg = "Analyze findings:"
        
        if os.name == 'nt' and full_path.lower().endswith(('.cmd', '.ps1')):
            # On Windows, wrappers can be problematic with stdin. 
            # We try to use positional args which is the modern recommendation.
            cmd = ["cmd.exe", "/c", full_path, headless_arg]
        else:
            # Use positional arg as --prompt is deprecated
            cmd = [full_path, headless_arg]
        
        # We need to consider environment variables for auth if needed, usually handled by shell env
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
                     raise RuntimeError(f"AI Quota Exceeded: {error_msg}")
                     
                logger.error("Gemini CLI failed (Exit %d): %s", process.returncode, error_msg)
                raise RuntimeError(f"Gemini CLI Error: {error_msg}")
            
            return self.clean_output(stdout.decode())
        except asyncio.TimeoutError:
             logger.error("Gemini CLI timed out after %d seconds", self.TIMEOUT)
             try:
                 process.kill()
             except:
                 pass
             raise RuntimeError(f"Gemini CLI Timed Out ({self.TIMEOUT}s)")
        except Exception as e:
             logger.exception("Gemini CLI execution failed: %s", e)
             raise e

# --- 4. Wrapper / Batch Processor Orchestrator ---

class GeminiCLIWrapper(BaseAIProvider):
    """Google Gemini CLI Provider Implementation"""
    
    PROVIDER_TYPE = AIProviderType.GOOGLE
    
    def __init__(self):
        self.prompt_builder = GenericPromptBuilder()
        self.executor = GeminiCLIExecutor()
        self.parser = GenericMarkdownParser()
        self._is_available = shutil.which("gemini") is not None
        
    @property
    def is_available(self) -> bool:
        return self._is_available
        
    async def check_availability(self) -> tuple[AIProviderStatus, str]:
        if not self._is_available:
            return AIProviderStatus.UNAVAILABLE, "Gemini CLI not found (install with 'npm install -g @google/gemini-cli')"
        
        # Check API Key
        if "GOOGLE_API_KEY" not in os.environ:
             return AIProviderStatus.UNAVAILABLE, "GOOGLE_API_KEY environment variable not set"
             
        # Check Execution
        try:
             # Check if it's the right "gemini" tool by checking help for chat command
             process = await asyncio.create_subprocess_exec(
                "gemini", "--help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
             )
             stdout, stderr = await process.communicate()
             if process.returncode != 0:
                  err_msg = stderr.decode().strip()
                  # Specific check for NPM package which fails with "Unknown argument"
                  if "Unknown argument" in err_msg or "invalid" in err_msg.lower():
                       return AIProviderStatus.UNAVAILABLE, "Incompatible 'gemini' CLI found (legacy NPM package detected). Please install the official Google version: 'npm install -g @google/gemini-cli'"
                  return AIProviderStatus.UNAVAILABLE, f"Gemini CLI error: {err_msg}"
        except Exception as e:
             return AIProviderStatus.UNAVAILABLE, f"Gemini CLI check failed: {str(e)}"

        return AIProviderStatus.AVAILABLE, "Ready"

    async def analyze_findings_batch(
        self, 
        findings: List[Finding], 
        code_contexts: Dict[str, str],
        batch_size: int = 5,
        app_context: Optional[Dict[str, Any]] = None
    ) -> List[EnhancedFinding]:
        """Process findings, typically a single batch passed from the manager."""
        
        if not findings:
            return []
            
        prompt = self.prompt_builder.build_batch_prompt(findings, app_context=app_context)
        
        try:
            markdown_response = await self.executor.execute(prompt)
            logger.info("Received AI response length: %d characters", len(markdown_response))
            
            # Diagnostic: Log first 200 chars to help identify structure issues
            if len(markdown_response) > 0:
                 logger.debug("AI Response Start: %s...", markdown_response[:200].replace("\n", " "))
            
            return self.parser.parse(markdown_response, findings)
        except Exception as e:
            logger.exception("Analysis failed for batch of %d findings: %s", len(findings), e)
            raise e

    def enhance_finding(self, finding: Finding, analysis: Any) -> EnhancedFinding:
        # Not used in this batched flow, as analyze_findings_batch returns EnhancedFinding list directly
        pass
        
    async def generate_stride_analysis(self, repo_path: Any, category: str) -> Dict[str, Any]:
        # Placeholder for STRIDE implementation
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

def get_gemini_wrapper() -> GeminiCLIWrapper:
    return GeminiCLIWrapper()
