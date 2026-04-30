from abc import ABC, abstractmethod
from typing import List, Any, Optional, AsyncIterator, Dict
from dataclasses import dataclass
from enum import Enum

from vexa.common.models import Finding, EnhancedFinding
from vexa.common.logging import get_logger

logger = get_logger(__name__)

class AIProviderType(str, Enum):
    GOOGLE = "google"
    AWS = "aws"
    AZURE = "azure"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"

class AIProviderStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"

class PromptBuilder(ABC):
    """Abstract base class for building AI prompts."""
    @abstractmethod
    def build_batch_prompt(self, findings: List[Finding], app_context: Optional[Dict[str, Any]] = None) -> str:
        pass

class CLIExecutor(ABC):
    """Abstract base class for executing CLI commands."""
    @abstractmethod
    async def execute(self, prompt: str) -> str:
        """Execute the CLI command with the given prompt and return output."""
        pass

    @staticmethod
    def clean_output(text: str) -> str:
        """Remove ANSI escape sequences and SGR codes from text."""
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

class MarkdownParser(ABC):
    """Abstract base class for parsing markdown responses."""
    @abstractmethod
    def parse(self, markdown: str, original_findings: List[Finding]) -> List[EnhancedFinding]:
        pass

@dataclass
class AIAnalysisResult:
    """Raw result from AI analysis"""
    content: str
    metadata: Dict[str, Any]

class BaseAIProvider(ABC):
    """Base class for AI providers integration."""
    
    PROVIDER_TYPE: AIProviderType
    
    @property
    @abstractmethod
    def is_available(self) -> bool:
        pass
        
    @abstractmethod
    async def check_availability(self) -> tuple[AIProviderStatus, str]:
        pass
        
    @abstractmethod
    async def analyze_findings_batch(
        self, 
        findings: List[Finding], 
        code_contexts: Dict[str, str],
        batch_size: int = 5,
        app_context: Optional[Dict[str, Any]] = None
    ) -> List[Any]: # Returns raw analysis objects/dicts
        pass

    @abstractmethod
    def enhance_finding(self, finding: Finding, analysis: Any) -> EnhancedFinding:
        pass
        
    @abstractmethod
    async def generate_stride_analysis(self, repo_path: Any, category: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def test_connection(self) -> tuple[AIProviderStatus, str]:
        """Perform a minimal AI request to verify connectivity and quota."""
        pass


class SDKAIProvider(BaseAIProvider):
    """
    Template Method base class for SDK-based AI providers.

    Captures the identical patterns shared by Anthropic, OpenAI, and Gemini:
    - Shared system prompt
    - Shared prompt_builder / parser initialization
    - Shared analyze_findings_batch flow: build prompt → send → extract text → parse
    - Shared test_connection skeleton: check_availability → minimal request → classify error
    - Shared error classification logic
    - Default no-op stubs for enhance_finding and generate_stride_analysis

    Concrete subclasses implement only:
    - _get_client()         → returns the SDK client instance
    - _send_request()       → executes the API call and returns the response text
    - _test_connection_request() → executes a minimal validation request
    - _check_sdk_installed()  → verifies the SDK is importable
    - check_availability()  → provider-specific availability check
    - is_available (property)
    - AUTH_ERROR_KEYWORDS / RATE_LIMIT_KEYWORDS (class-level tuples for error classification)
    """

    SYSTEM_PROMPT = (
        "You are Vexa, an expert AI security assistant. "
        "Analyze security findings and provide remediation in Markdown format. "
        "Follow the ZERO-CHATTER RULE: remediation code blocks must contain "
        "ONLY pure source code, no explanations."
    )

    # Subclasses can extend these for provider-specific error patterns
    AUTH_ERROR_KEYWORDS: tuple = ("authentication", "401", "403")
    RATE_LIMIT_KEYWORDS: tuple = ("rate_limit", "quota", "too many requests", "429")

    def __init__(self):
        from vexa.ai_providers.prompts import GenericPromptBuilder, GenericMarkdownParser
        self.prompt_builder = GenericPromptBuilder()
        self.parser = GenericMarkdownParser()

    @abstractmethod
    def _get_client(self):
        """Return the SDK client instance."""
        pass

    @abstractmethod
    async def _send_request(self, client, system_prompt: str, user_prompt: str) -> str:
        """Execute the API call and return the response text."""
        pass

    @abstractmethod
    async def _test_connection_request(self, client) -> None:
        """Execute a minimal validation request (e.g., 'Reply with ok'). Raise on failure."""
        pass

    def _classify_error(self, err_msg: str, status_code: Optional[int] = None) -> str:
        """Classify an error message into auth/rate_limit/other categories."""
        err_lower = err_msg.lower()
        if status_code in (401, 403) or any(w in err_lower for w in self.AUTH_ERROR_KEYWORDS):
            return "auth"
        if status_code == 429 or any(w in err_lower for w in self.RATE_LIMIT_KEYWORDS):
            return "rate_limit"
        return "other"

    async def analyze_findings_batch(
        self,
        findings: List[Finding],
        code_contexts: Dict[str, str],
        batch_size: int = 10,
        app_context: Optional[Dict[str, Any]] = None,
        is_workspace_scan: bool = False,
    ) -> List[EnhancedFinding]:

        if not findings:
            return []

        client = self._get_client()
        prompt = self.prompt_builder.build_batch_prompt(
            findings, app_context=app_context, is_workspace_scan=is_workspace_scan
        )

        try:
            logger.info(
                "Sending batch of %d findings to %s...",
                len(findings), self.PROVIDER_TYPE.value,
            )
            text = await self._send_request(client, self.SYSTEM_PROMPT, prompt)
            logger.debug("Received AI response length: %d characters", len(text))
            return self.parser.parse(text, findings)
        except Exception as e:
            err_type = self._classify_error(str(e), getattr(e, "status_code", None))
            if err_type == "rate_limit":
                raise RuntimeError(f"{self.PROVIDER_TYPE.value} Rate Limit Exceeded: {e}")
            logger.exception("%s analysis failed: %s", self.PROVIDER_TYPE.value, e)
            raise

    async def test_connection(self) -> tuple[AIProviderStatus, str]:
        """Perform a minimal AI request to verify connectivity and quota."""
        status, msg = await self.check_availability()
        if status != AIProviderStatus.AVAILABLE:
            return status, msg

        try:
            client = self._get_client()
            logger.info("Validating %s API key...", self.PROVIDER_TYPE.value)
            await self._test_connection_request(client)
            return AIProviderStatus.AVAILABLE, "Ready"
        except Exception as e:
            err_type = self._classify_error(str(e), getattr(e, "status_code", None))
            provider = self.PROVIDER_TYPE.value.title()
            if err_type == "auth":
                return AIProviderStatus.ERROR, f"{provider} Auth Error: {e}"
            if err_type == "rate_limit":
                return AIProviderStatus.ERROR, f"{provider} Rate Limit Error: {e}"
            return AIProviderStatus.ERROR, f"{provider} Connection Failed: {str(e)}"

    def enhance_finding(self, finding: Finding, analysis: Any) -> EnhancedFinding:
        pass  # Batch flow only

    async def generate_stride_analysis(self, repo_path: Any, category: str) -> Dict[str, Any]:
        return {"error": "Not implemented"}
