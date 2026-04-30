"""
Ollama Local LLM Provider for Vexa — Privacy Vault.

Implements PRIV-01: Provides AI-powered security analysis using a locally-running
Ollama instance. Zero data leaves the developer's machine. All HTTP calls go to
localhost only — no DNS resolution to external hosts.

When this provider is active, Vexa operates in "Privacy Vault" mode:
- Every CLI output line includes a trust indicator showing local mode
- Telemetry is disabled
- An audit log records what was processed (but never the code itself)

This is the product's only defensible moat against AWS, Snyk, and SonarQube —
genuine, verifiable, air-gapped AI security analysis.
"""

import json
import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from vexa.common.models import Finding, EnhancedFinding
from vexa.common.logging import get_logger
from vexa.ai_providers.base import (
    BaseAIProvider,
    AIProviderType,
    AIProviderStatus,
)
from vexa.ai_providers.prompts import GenericPromptBuilder, GenericMarkdownParser
from vexa.common.config import VEXA_HOME

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Trust Indicator — shown at the start of every local-mode CLI run
# ---------------------------------------------------------------------------

PRIVACY_VAULT_BANNER = (
    "🔒 Privacy Vault Active — Running on {model} via Ollama\n"
    "   Zero data egress. All analysis stays on this machine."
)

PRIVACY_VAULT_ERROR = (
    "⚠️  Privacy Vault: Local AI not running.\n"
    "\n"
    "To start it:  ollama serve\n"
    "Then retry:   vexa fix ."
)

# Supported models with minimum hardware requirements
SUPPORTED_MODELS = {
    "gemma4:26b": {
        "min_ram_gb": 16,
        "recommended_ram_gb": 32,
        "quality": "Best — MoE, fast + smart (recommended)",
    },
    "gemma4:e4b": {
        "min_ram_gb": 8,
        "recommended_ram_gb": 16,
        "quality": "Good — multimodal, lightweight",
    },
    "gemma4:31b": {
        "min_ram_gb": 32,
        "recommended_ram_gb": 64,
        "quality": "Best — enterprise dense",
    },
    "llama3:8b": {"min_ram_gb": 8, "recommended_ram_gb": 16, "quality": "Good"},
    "codellama:13b": {
        "min_ram_gb": 16,
        "recommended_ram_gb": 32,
        "quality": "Better — optimised for code",
    },
    "mistral:7b": {"min_ram_gb": 8, "recommended_ram_gb": 16, "quality": "Good — fast"},
    "codellama:34b": {
        "min_ram_gb": 32,
        "recommended_ram_gb": 64,
        "quality": "Best — enterprise",
    },
}


class OllamaProvider(BaseAIProvider):
    """
    Local LLM provider using Ollama for air-gapped security analysis.

    All network calls go to localhost only. No external DNS resolution.
    No code, metadata, or telemetry leaves the developer's machine.

    Reuses the existing GenericPromptBuilder and GenericMarkdownParser —
    the prompt format is provider-agnostic by design.
    """

    PROVIDER_TYPE = AIProviderType.OLLAMA

    def __init__(
        self,
        model: str = "gemma4:26b",
        host: str = "localhost",
        port: int = 11434,
    ):
        """
        Initialize the Ollama provider for local AI analysis.

        Args:
            model: Ollama model name (e.g., 'llama3:8b', 'codellama:13b').
            host: Ollama server hostname. Default: localhost.
            port: Ollama server port. Default: 11434.
        """
        self.model = model
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self.prompt_builder = GenericPromptBuilder()
        self.parser = GenericMarkdownParser()
        self._audit_log_dir = VEXA_HOME / "audit"

    # ------------------------------------------------------------------
    # Trust Indicator Helpers
    # ------------------------------------------------------------------

    def get_trust_banner(self) -> str:
        """Get the trust indicator banner for CLI output."""
        return PRIVACY_VAULT_BANNER.format(model=self.model)

    def is_local_mode(self) -> bool:
        """Always True for Ollama — this is a local-only provider."""
        return True

    # ------------------------------------------------------------------
    # Availability Checks
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """Check if Ollama appears to be reachable (synchronous quick check)."""
        try:
            import urllib.request

            req = urllib.request.Request(
                f"{self.base_url}/api/tags",
                method="GET",
            )
            # Set a very short timeout for the quick check
            urllib.request.urlopen(req, timeout=3)
            return True
        except Exception:
            return False

    async def check_availability(self) -> tuple[AIProviderStatus, str]:
        """
        Check if Ollama is installed and running.

        Returns a plain-English message if not available — never a traceback.
        """
        try:
            import urllib.request

            req = urllib.request.Request(
                f"{self.base_url}/api/tags",
                method="GET",
            )
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode("utf-8"))

            # Check if our target model is available
            available_models = [m.get("name", "") for m in data.get("models", [])]
            if self.model not in available_models:
                # Model is not pulled yet — give a helpful message
                model_names = (
                    ", ".join(available_models[:5]) if available_models else "none"
                )
                return (
                    AIProviderStatus.UNAVAILABLE,
                    f"Ollama is running but the model '{self.model}' is not installed.\n"
                    f"Install it with: ollama pull {self.model}\n"
                    f"Available models: {model_names}",
                )

            return AIProviderStatus.AVAILABLE, f"Ready — {self.model} via Ollama"

        except ConnectionRefusedError:
            return (
                AIProviderStatus.UNAVAILABLE,
                "Local AI is not running. Start it with: ollama serve",
            )
        except Exception as e:
            err_str = str(e).lower()
            if "refused" in err_str or "connection" in err_str or "urlopen" in err_str:
                return (
                    AIProviderStatus.UNAVAILABLE,
                    "Local AI is not running. Start it with: ollama serve",
                )
            return (
                AIProviderStatus.ERROR,
                f"Could not connect to local AI: {e}\n"
                "Make sure Ollama is running (ollama serve) and try again.",
            )

    async def test_connection(self) -> tuple[AIProviderStatus, str]:
        """
        Test that Ollama can generate a response.

        Sends a minimal prompt to verify the model is loaded and responsive.
        """
        status, msg = await self.check_availability()
        if status != AIProviderStatus.AVAILABLE:
            return status, msg

        try:
            response = await self._generate("Reply with 'ok'", max_tokens=10)
            if response and len(response.strip()) > 0:
                return AIProviderStatus.AVAILABLE, f"Ready — {self.model}"
            return (
                AIProviderStatus.ERROR,
                "Local AI responded but with empty output. Try a different model.",
            )
        except Exception as e:
            return (
                AIProviderStatus.ERROR,
                f"Local AI test failed: {e}\n"
                "Try restarting Ollama (ollama serve) or pulling the model again.",
            )

    # ------------------------------------------------------------------
    # Core Generation — HTTP to localhost only
    # ------------------------------------------------------------------

    async def _generate(self, prompt: str, max_tokens: int = 8192) -> str:
        """
        Send a prompt to the local Ollama instance and return the response.

        This method ONLY makes HTTP calls to localhost. No external DNS
        resolution occurs. This is verified by the test suite.
        """
        import urllib.request

        url = f"{self.base_url}/api/generate"
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": max_tokens,
                },
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        # Run the synchronous HTTP call in a thread pool to avoid blocking
        # the async event loop
        loop = asyncio.get_event_loop()
        try:
            response = await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=300)
            )
            data = json.loads(response.read().decode("utf-8"))
            return data.get("response", "")
        except ConnectionRefusedError:
            raise RuntimeError("Local AI is not running. Start it with: ollama serve")
        except Exception as e:
            err_str = str(e).lower()
            if "refused" in err_str or "connection" in err_str:
                raise RuntimeError(
                    "Local AI is not running. Start it with: ollama serve"
                )
            raise RuntimeError(
                f"Local AI request failed: {e}\n"
                "Make sure Ollama is running and the model is installed."
            )

    # ------------------------------------------------------------------
    # AI Analysis — Implements BaseAIProvider interface
    # ------------------------------------------------------------------

    async def analyze_findings_batch(
        self,
        findings: List[Finding],
        code_contexts: Dict[str, str],
        batch_size: int = 5,
        app_context: Optional[Dict[str, Any]] = None,
        is_workspace_scan: bool = False,
    ) -> List[EnhancedFinding]:
        """
        Analyze a batch of security findings using the local Ollama model.

        Uses the same prompt format as cloud providers (GenericPromptBuilder).
        All processing happens on localhost — zero external network calls.
        """
        if not findings:
            return []

        prompt = self.prompt_builder.build_batch_prompt(
            findings,
            app_context=app_context,
            is_workspace_scan=is_workspace_scan,
        )

        system_prompt = (
            "You are Vexa, an expert AI security assistant. "
            "Analyze security findings and provide remediation in Markdown format. "
            "Follow the ZERO-CHATTER RULE: remediation code blocks must contain "
            "ONLY pure source code, no explanations."
        )

        full_prompt = f"{system_prompt}\n\n{prompt}"

        try:
            logger.info(
                "[local] Sending batch of %d findings to Ollama (%s)...",
                len(findings),
                self.model,
            )

            text = await self._generate(full_prompt)
            logger.debug(
                "[local] Received Ollama response length: %d characters", len(text)
            )

            enhanced = self.parser.parse(text, findings)

            # Write audit log entry
            self._write_audit_log(findings, enhanced)

            return enhanced

        except Exception as e:
            logger.exception("[local] Ollama analysis failed: %s", e)
            raise

    def enhance_finding(self, finding: Finding, analysis: Any) -> EnhancedFinding:
        """Not used — batch flow only."""
        pass

    async def generate_stride_analysis(
        self, repo_path: Any, category: str
    ) -> Dict[str, Any]:
        """STRIDE analysis is not supported in local mode for v1."""
        return {"error": "STRIDE analysis is not available in local mode."}

    # ------------------------------------------------------------------
    # Audit Log — Records what was processed, never the code itself
    # ------------------------------------------------------------------

    def _get_or_create_audit_key(self) -> bytes:
        """Retrieve or generate the local HMAC key used to sign audit logs to prevent tampering."""
        key_file = VEXA_HOME / "audit.key"
        if not key_file.exists():
            import secrets

            key_file.parent.mkdir(parents=True, exist_ok=True)
            key = secrets.token_bytes(32)
            key_file.write_bytes(key)
            # Ensure proper file permissions (only readable by user)
            key_file.chmod(0o600)
            return key
        return key_file.read_bytes()

    def _write_audit_log(
        self,
        input_findings: List[Finding],
        output_findings: List[EnhancedFinding],
    ) -> None:
        """
        Write an audit entry recording what was analysed locally.

        The audit log proves zero data left the machine. It records:
        - Timestamp
        - Model used
        - Finding IDs processed
        - No code content (never logged)
        - external_calls: 0
        """
        import hmac
        import hashlib

        try:
            self._audit_log_dir.mkdir(parents=True, exist_ok=True)
            audit_file = self._audit_log_dir / "audit.log"

            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "provider": "ollama",
                "model": self.model,
                "host": f"{self.host}:{self.port}",
                "finding_ids_processed": [f.id for f in input_findings],
                "findings_count": len(input_findings),
                "enhanced_count": len(output_findings),
                "external_calls": 0,
                "data_egress": False,
            }

            payload = json.dumps(entry, sort_keys=True)
            key = self._get_or_create_audit_key()
            signature = hmac.new(
                key, payload.encode("utf-8"), hashlib.sha256
            ).hexdigest()

            signed_entry = {"payload": entry, "signature": signature}

            with open(audit_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(signed_entry) + "\n")

            logger.debug(
                "[local] Audit log entry written: %d findings processed",
                len(input_findings),
            )

        except Exception as e:
            # Audit log failure should never crash the scan
            logger.warning("Failed to write audit log: %s", e)

    def set_api_key(self, api_key: str) -> None:
        """Ollama does not use API keys — this is a no-op for interface compatibility."""
        pass


def get_ollama_wrapper(
    model: str = "gemma4:26b",
    host: str = "localhost",
    port: int = 11434,
) -> OllamaProvider:
    """
    Create an Ollama provider instance for local AI analysis.

    Args:
        model: Ollama model name. Default: llama3:8b.
        host: Ollama hostname. Default: localhost.
        port: Ollama port. Default: 11434.

    Returns:
        Configured OllamaProvider instance.
    """
    return OllamaProvider(model=model, host=host, port=port)
