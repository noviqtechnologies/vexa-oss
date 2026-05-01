from typing import Optional, Dict, List, Any
from vexa.common.models import CloudProvider


# Define capabilities logic here
class ProviderCapabilities:
    """Capabilities associated with a cloud provider."""

    def __init__(
        self,
        ai_cli_command: Optional[str],
        code_review_enabled: bool,
        false_positive_detection: bool,
        stride_analysis: bool,
        check_args: Optional[List[str]] = None,
        ping_args: Optional[List[str]] = None,
    ):
        self.ai_cli_command = ai_cli_command
        self.code_review_enabled = code_review_enabled
        self.false_positive_detection = false_positive_detection
        self.stride_analysis = stride_analysis
        self.check_args = check_args or []
        self.ping_args = ping_args or []


# Define capabilities map
PROVIDER_CAPABILITIES: Dict[CloudProvider, ProviderCapabilities] = {
    CloudProvider.GOOGLE: ProviderCapabilities(
        ai_cli_command=None,  # SDK-based
        code_review_enabled=True,
        false_positive_detection=True,
        stride_analysis=True,
        check_args=[],
    ),
    CloudProvider.AWS: ProviderCapabilities(
        ai_cli_command=None,  # CLI Disabled
        code_review_enabled=False,
        false_positive_detection=False,
        stride_analysis=False,
    ),
    CloudProvider.AZURE: ProviderCapabilities(
        ai_cli_command=None,  # CLI Disabled
        code_review_enabled=False,
        false_positive_detection=False,
        stride_analysis=False,
    ),
    CloudProvider.OPENAI: ProviderCapabilities(
        ai_cli_command=None,  # SDK-based
        code_review_enabled=True,
        false_positive_detection=True,
        stride_analysis=False,
    ),
    CloudProvider.ANTHROPIC: ProviderCapabilities(
        ai_cli_command=None,  # SDK-based
        code_review_enabled=True,
        false_positive_detection=True,
        stride_analysis=False,
    ),
    CloudProvider.OLLAMA: ProviderCapabilities(
        ai_cli_command=None,  # SDK-based (HTTP to localhost)
        code_review_enabled=True,
        false_positive_detection=True,
        stride_analysis=False,
    ),
    CloudProvider.NONE: ProviderCapabilities(
        ai_cli_command=None,
        code_review_enabled=False,
        false_positive_detection=False,
        stride_analysis=False,
    ),
}

# Explicit list of providers supported in CLI (Excludes Azure)
SUPPORTED_PROVIDERS = [
    CloudProvider.GOOGLE,
    CloudProvider.AWS,
    CloudProvider.AZURE,
    CloudProvider.OPENAI,
    CloudProvider.ANTHROPIC,
    CloudProvider.OLLAMA,
    CloudProvider.NONE,
]

import shutil


class ProviderAvailability:
    """Check availability of cloud provider CLIs."""

    @staticmethod
    async def check_provider(
        provider: CloudProvider, check_quota: bool = False
    ) -> Dict[str, Any]:
        """
        Check if the provider is available.
        For SDK-based providers (Gemini, OpenAI, Anthropic), uses the SDK wrapper.
        For legacy CLI-based providers, checks the local system.
        """
        if provider == CloudProvider.NONE:
            return {"available": True, "authenticated": True, "error": None}

        # SDK-based check for active providers
        if provider in (
            CloudProvider.GOOGLE,
            CloudProvider.OPENAI,
            CloudProvider.ANTHROPIC,
            CloudProvider.OLLAMA,
        ):
            from vexa.ai_providers.manager import AIProviderManager

            manager = AIProviderManager(cloud_provider=provider)
            # Use the manager's ability to check connection (includes API key check)
            if provider == CloudProvider.GOOGLE:
                p = manager._gemini
            elif provider == CloudProvider.OPENAI:
                p = manager._openai
            elif provider == CloudProvider.OLLAMA:
                p = manager._ollama
            else:
                p = manager._anthropic

            if not p:
                return {
                    "available": False,
                    "authenticated": False,
                    "error": f"Provider {provider.value} not configured",
                }

            from vexa.ai_providers.base import AIProviderStatus

            status, msg = await p.check_availability()
            if status != AIProviderStatus.AVAILABLE:
                return {"available": False, "authenticated": False, "error": msg}

            # If deep check requested, test the connection
            if check_quota:
                status, msg = await p.test_connection()
                if status != AIProviderStatus.AVAILABLE:
                    return {"available": False, "authenticated": True, "error": msg}

            return {"available": True, "authenticated": True, "error": None}

        # Legacy CLI check
        capabilities = PROVIDER_CAPABILITIES.get(provider)
        if not capabilities or not capabilities.ai_cli_command:
            return {
                "available": False,
                "authenticated": False,
                "error": f"Provider '{provider.value}' is disabled or requires an SDK.",
            }

        cli_cmd = capabilities.ai_cli_command
        full_path = shutil.which(cli_cmd)

        if not full_path:
            return {
                "available": False,
                "authenticated": False,
                "error": f"CLI tool '{cli_cmd}' not found. Please install it.",
            }

        # Deep check if check_args provided
        if capabilities.check_args:
            import subprocess

            try:
                # Run deep check e.g. 'az ai --help'
                # Use shell=False for security [SEC-006]
                # Handle Windows .cmd/.bat files [SEC-006 compliant]
                import os

                full_cmd = [full_path] + capabilities.check_args
                if os.name == "nt" and full_path.lower().endswith((".cmd", ".ps1")):
                    # On Windows, gemini.cmd/ps1 wrappers can be problematic with stdin/headless mode.
                    # We try to resolve the actual JS file and run with node directly.
                    node_path = shutil.which("node")

                    # Helper to find the JS file relative to the wrapper
                    # wrapper is usually in .../npm/gemini.cmd
                    # js is usually in .../npm/node_modules/@google/gemini-cli/dist/index.js
                    wrapper_dir = os.path.dirname(full_path)
                    js_path = os.path.join(
                        wrapper_dir,
                        "node_modules",
                        "@google",
                        "gemini-cli",
                        "dist",
                        "index.js",
                    )

                    if (
                        provider == CloudProvider.GOOGLE
                        and node_path
                        and os.path.exists(js_path)
                    ):
                        # Construct node command: node index.js [args]
                        full_cmd = [node_path, js_path] + capabilities.check_args
                    else:
                        # Fallback to cmd wrapper if we can't find the inner parts or for other providers
                        full_cmd = ["cmd.exe", "/c"] + full_cmd
                else:
                    full_cmd = [full_path] + capabilities.check_args

                result = subprocess.run(
                    full_cmd, capture_output=True, text=True, timeout=30, check=False
                )
                if result.returncode != 0:
                    err_hint = ""
                    stderr_content = result.stderr.strip() or result.stdout.strip()
                    if provider == CloudProvider.GOOGLE and "npm" in full_path.lower():
                        err_hint = "\n👉 [Hint] Found legacy NPM 'gemini' tool. Install the official Google version: 'npm install -g @google/gemini-cli'"

                    return {
                        "available": False,
                        "authenticated": False,
                        "error": f"CLI found at {full_path} but deep check failed: {stderr_content}{err_hint}",
                    }
            except subprocess.TimeoutExpired:
                err_hint = ""
                if provider == CloudProvider.GOOGLE and "npm" in full_path.lower():
                    err_hint = "\n👉 [Hint] The Gemini CLI is taking too long to respond. This can happen on first run. Please try running 'gemini chat \"hi\"' manually in your terminal first to authenticate."

                return {
                    "available": False,
                    "authenticated": False,
                    "error": f"Deep check for {cli_cmd} timed out after 15s. The tool might be hanging.{err_hint}",
                }
            except Exception as e:
                return {
                    "available": False,
                    "authenticated": False,
                    "error": f"Deep check failed for {cli_cmd}: {str(e)}",
                }

        # Optional: Check quota/connectivity if requested
        if check_quota and capabilities.ping_args:
            import subprocess

            try:
                # Handle Windows .cmd/.bat files [SEC-006 compliant]
                import os

                # On Windows, bypass wrapper for reliability if possible
                full_ping = [full_path] + capabilities.ping_args

                if os.name == "nt" and full_path.lower().endswith(
                    (".cmd", ".bat", ".ps1")
                ):
                    node_path = shutil.which("node")
                    wrapper_dir = os.path.dirname(full_path)
                    js_path = os.path.join(
                        wrapper_dir,
                        "node_modules",
                        "@google",
                        "gemini-cli",
                        "dist",
                        "index.js",
                    )

                    if node_path and os.path.exists(js_path):
                        # Construct node command: node index.js [args]
                        full_ping = [node_path, js_path] + capabilities.ping_args
                    else:
                        full_ping = ["cmd.exe", "/c"] + full_ping
                else:
                    full_ping = [full_path] + capabilities.ping_args

                result = subprocess.run(
                    full_ping, capture_output=True, text=True, timeout=90, check=False
                )
                if result.returncode != 0:
                    stderr_content = result.stderr.strip() or result.stdout.strip()
                    if any(
                        kw in stderr_content.lower()
                        for kw in ["429", "quota", "rate limit", "exhausted"]
                    ):
                        return {
                            "available": False,
                            "authenticated": True,
                            "error": "AI Analysis Failed: Quota Exceeded (429)",
                        }
                    return {
                        "available": False,
                        "authenticated": True,
                        "error": f"AI Connection Test Failed: {stderr_content}",
                    }
            except Exception as e:
                return {
                    "available": False,
                    "authenticated": True,
                    "error": f"AI Connection Test Failed: {str(e)}",
                }

        return {"available": True, "authenticated": True, "error": None}
