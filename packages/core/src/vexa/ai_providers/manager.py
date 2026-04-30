"""
AI Provider Manager for Vexa.

Orchestrates AI provider selection, fallback, and finding enrichment.

Implements:
- G-001, G-002: Cloud provider selection
- SS-003, SS-004: AI-powered code review
- SS-010, SS-011: False positive detection (>90%)
"""

import asyncio
import json
import hashlib
from typing import Any, Dict, List, Optional, Tuple, Set
from pathlib import Path

from vexa.ai_providers.base import (
    AIAnalysisResult,
    AIProviderStatus,
    AIProviderType,
    BaseAIProvider,
)
# SDK-based providers (active)
from vexa.ai_providers.google_sdk import get_gemini_sdk_wrapper
from vexa.ai_providers.openai_provider import get_openai_wrapper
from vexa.ai_providers.anthropic_provider import get_anthropic_wrapper
from vexa.ai_providers.ollama_provider import get_ollama_wrapper

# CLI-based providers (disabled — moved to _legacy/)
# from vexa.ai_providers._legacy.google_cli import get_gemini_wrapper
# from vexa.ai_providers._legacy.kiro_cli import get_kiro_wrapper
# from vexa.ai_providers._legacy.azure_cli import get_azure_wrapper
from vexa.common.logging import get_logger, audit_logger
from vexa.common.models import CloudProvider, Finding, EnhancedFinding
from vexa.common.config import (
    AI_BATCH_SIZE, 
    FALSE_POSITIVE_THRESHOLD, 
    AI_CACHE_FILE, 
    AI_MIN_SEVERITY_THRESHOLD
)


logger = get_logger(__name__)


class AIProviderManager:
    """
    Manages AI provider selection, fallback, and finding enrichment.
    
    G-001: Allow user to choose between different cloud providers
    G-002: Use appropriate AI capabilities based on chosen provider
    
    Features:
    - Automatic provider selection based on cloud provider
    - Fallback between providers on failure
    - Batch processing for efficiency
    - False positive filtering at >90% confidence
    """
    
    PROMPT_VERSION = "2"  # Increment this to invalidate AI cache when prompts change
    
    def __init__(
        self,
        cloud_provider: CloudProvider = CloudProvider.NONE,
        ai_provider_override: Optional[str] = None,
        ai_model_override: Optional[str] = None,
        api_key_override: Optional[str] = None,
        ollama_url_override: Optional[str] = None,
        batch_size: int = AI_BATCH_SIZE,
        fp_threshold: float = FALSE_POSITIVE_THRESHOLD,
        min_severity: str = AI_MIN_SEVERITY_THRESHOLD,
    ):
        """
        Initialize AI Provider Manager.
        
        Args:
            cloud_provider: Selected cloud provider
            batch_size: Number of findings per AI batch
            fp_threshold: False positive confidence threshold (0-1)
        """
        self.cloud_provider = cloud_provider
        self.ai_provider_override = ai_provider_override
        self.ai_model_override = ai_model_override
        self.api_key_override = api_key_override
        self.ollama_url_override = ollama_url_override
        self.batch_size = batch_size
        self.fp_threshold = fp_threshold * 100  # Convert to percentage
        self.min_severity = min_severity
        
        # Cache for AI results
        self._cache_file = AI_CACHE_FILE
        self._cache: Dict[str, Dict[str, Any]] = self._load_cache()
        
        # Initialize SDK-based providers
        self._gemini = get_gemini_sdk_wrapper()
        self._openai = get_openai_wrapper()
        self._anthropic = get_anthropic_wrapper()
        self._ollama = None  # Lazy-initialized when needed

        # CLI-based providers (disabled)
        self._kiro = None
        self._azure = None
        
        # Privacy Vault mode flag — set when Ollama is active
        self.is_local_mode = False
        
        # Primary provider based on cloud selection
        self._primary_provider: Optional[BaseAIProvider] = None
        self._fallback_provider: Optional[BaseAIProvider] = None
        
        self._configure_providers()
    
    def _configure_providers(self) -> None:
        """Configure primary and fallback providers based on cloud selection."""
        # Reset providers
        self._primary_provider = None
        self._fallback_provider = None
        self.is_local_mode = False
        
        # Explicit override handling (for IDE/CLI direct configuration)
        if self.ai_provider_override:
            override = self.ai_provider_override.lower()
            if override == "google":
                self._primary_provider = self._gemini
                if self.ai_model_override:
                    self._gemini.model = self.ai_model_override
                if self.api_key_override:
                    self._gemini.set_api_key(self.api_key_override)
            elif override == "openai":
                self._primary_provider = self._openai
                if self.ai_model_override:
                    self._openai.model = self.ai_model_override
                if self.api_key_override:
                    self._openai.set_api_key(self.api_key_override)
            elif override == "anthropic":
                self._primary_provider = self._anthropic
                if self.ai_model_override:
                    self._anthropic.model = self.ai_model_override
                if self.api_key_override:
                    self._anthropic.set_api_key(self.api_key_override)
            elif override == "ollama":
                # Privacy Vault mode — local LLM
                from vexa.common.config_manager import load_config
                import os
                config = load_config(os.getcwd())
                model = self.ai_model_override or config.ai.model or "gemma4:26b"
                
                host = config.ai.ollama_host
                port = config.ai.ollama_port
                
                if self.ollama_url_override:
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(self.ollama_url_override)
                        host = parsed.hostname or host
                        port = parsed.port or port
                    except Exception:
                        pass

                self._ollama = get_ollama_wrapper(
                    model=model,
                    host=host,
                    port=port,
                )
                self._primary_provider = self._ollama
                self.is_local_mode = True
                logger.info("Privacy Vault activated — all analysis runs locally via Ollama (%s)", model)
            elif override == "aws":
                logger.warning("AWS Kiro CLI provider is disabled. Configure OpenAI or Anthropic instead.")
                self._primary_provider = None
            elif override == "azure":
                logger.warning("Azure CLI provider is disabled. Configure OpenAI or Anthropic instead.")
                self._primary_provider = None

        else:
            # Route cloud provider selection to active SDK providers
            if self.cloud_provider == CloudProvider.GOOGLE:
                self._primary_provider = self._gemini
            elif self.cloud_provider == CloudProvider.AWS:
                logger.warning("AWS cloud provider selected but no active SDK provider is configured. Use OpenAI or Anthropic.")
                self._primary_provider = None
            elif self.cloud_provider == CloudProvider.AZURE:
                logger.warning("Azure CLI provider is disabled. Use OpenAI or Anthropic instead.")
                self._primary_provider = None
            elif self.cloud_provider == CloudProvider.OPENAI:
                self._primary_provider = self._openai
            elif self.cloud_provider == CloudProvider.ANTHROPIC:
                self._primary_provider = self._anthropic
            elif self.cloud_provider == CloudProvider.OLLAMA:
                # Privacy Vault mode — local LLM
                from vexa.common.config_manager import load_config
                import os
                # Try to load Ollama config from .vexa.yml
                config = load_config(os.getcwd())
                self._ollama = get_ollama_wrapper(
                    model=config.ai.model,
                    host=config.ai.ollama_host,
                    port=config.ai.ollama_port,
                )
                self._primary_provider = self._ollama
                self.is_local_mode = True
                logger.info("Privacy Vault activated — all analysis runs locally via Ollama (%s)", config.ai.model)
            
        if self._primary_provider:
             logger.info(
                "AI provider configured: %s",
                self._primary_provider.PROVIDER_TYPE.value
            )

    # ------------------------------------------------------------------
    # Cache & Optimization Logic
    # ------------------------------------------------------------------

    def _load_cache(self) -> Dict[str, Any]:
        """Load AI result cache from disk."""
        if not self._cache_file.exists():
            return {}
        try:
            with open(self._cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to load AI cache: %s", e)
            return {}

    def _save_cache(self) -> None:
        """Save AI result cache to disk."""
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._cache_file, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save AI cache: %s", e)

    def _get_finding_hash(self, finding: Finding) -> str:
        """Generate a unique hash for a finding based on its core characteristics."""
        key = f"{self.PROMPT_VERSION}:{finding.scanner}:{finding.title}:{finding.code_snippet}"
        return hashlib.sha256(key.encode()).hexdigest()

    def _severity_to_rank(self, severity: str) -> int:
        """Convert severity string to numerical rank for comparison."""
        ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return ranks.get(severity.lower(), 0)

    # ------------------------------------------------------------------
    # Availability
    async def check_providers(self) -> Dict[str, Any]:
        """
        Check availability of all active SDK-based providers.

        Returns:
            Dictionary with provider status information.
        """
        results = {}

        # Check Gemini SDK
        gemini_status, gemini_msg = await self._gemini.check_availability()
        if gemini_status == AIProviderStatus.AVAILABLE:
            gemini_status, gemini_msg = await self._gemini.test_connection()

        results["gemini"] = {
            "status": gemini_status.value,
            "message": gemini_msg,
            "is_primary": self._primary_provider == self._gemini,
        }

        # Check OpenAI
        openai_status, openai_msg = await self._openai.check_availability()
        if openai_status == AIProviderStatus.AVAILABLE:
            openai_status, openai_msg = await self._openai.test_connection()

        results["openai"] = {
            "status": openai_status.value,
            "message": openai_msg,
            "is_primary": self._primary_provider == self._openai,
        }

        # Check Anthropic
        anthropic_status, anthropic_msg = await self._anthropic.check_availability()
        if anthropic_status == AIProviderStatus.AVAILABLE:
            anthropic_status, anthropic_msg = await self._anthropic.test_connection()

        results["anthropic"] = {
            "status": anthropic_status.value,
            "message": anthropic_msg,
            "is_primary": self._primary_provider == self._anthropic,
        }

        # CLI-based providers are disabled
        results["kiro"] = {"status": "disabled", "message": "AWS Kiro CLI provider is disabled. Use OpenAI or Anthropic instead.", "is_primary": False}
        results["azure"] = {"status": "disabled", "message": "Azure CLI provider is disabled. Use OpenAI or Anthropic instead.", "is_primary": False}

        # Overall status
        results["has_available_provider"] = any(
            s == AIProviderStatus.AVAILABLE
            for s in [gemini_status, openai_status, anthropic_status]
        )

        return results
    
    async def enrich_findings(
        self,
        findings: List[Finding],
        code_contexts: Optional[Dict[str, str]] = None,
        app_context: Optional[Dict[str, Any]] = None,
        is_workspace_scan: bool = False,
    ) -> Tuple[List[EnhancedFinding], List[EnhancedFinding]]:
        """
        Enrich findings with AI-generated analysis with deduplication and caching.
        """
        if not self._primary_provider:
            logger.warning("No AI provider configured, returning unenriched findings")
            return [self._finding_to_enhanced(f) for f in findings], []
        
        # 1. Filter by Severity
        min_rank = self._severity_to_rank(self.min_severity)
        to_enrich = []
        filtered_results = []
        
        for f in findings:
            if self._severity_to_rank(f.severity) < min_rank:
                filtered_results.append(self._finding_to_enhanced(f))
            else:
                to_enrich.append(f)
                
        if not to_enrich:
            return filtered_results, []

        # 2. Deduplication & Cache Lookup
        unique_findings_to_enrich = []
        finding_id_to_hash = {f.id: self._get_finding_hash(f) for f in to_enrich}
        hash_to_enhanced = {} # Stores the result for a given hash
        
        # Check cache first
        for f in to_enrich:
            f_hash = finding_id_to_hash[f.id]
            if f_hash in self._cache:
                # Cache hit! Create an EnhancedFinding from the cached data
                cached_data = self._cache[f_hash]
                enhanced = self._finding_to_enhanced(f)
                for key, val in cached_data.items():
                    if hasattr(enhanced, key):
                        setattr(enhanced, key, val)
                hash_to_enhanced[f_hash] = enhanced
        
        # Identify hashes that still need enrichment
        hashes_needed = set(finding_id_to_hash.values()) - set(hash_to_enhanced.keys())
        
        # Map one finding instance to each unique hash needed
        hash_to_representative = {}
        for f in to_enrich:
            f_hash = finding_id_to_hash[f.id]
            if f_hash in hashes_needed and f_hash not in hash_to_representative:
                hash_to_representative[f_hash] = f
        
        unique_findings_to_enrich = list(hash_to_representative.values())

        if unique_findings_to_enrich:
            # Pre-check connectivity
            status, msg = await self._primary_provider.test_connection()
            if status != AIProviderStatus.AVAILABLE:
                logger.error("AI Provider Connection Failed: %s", msg)
                error_results = [self._finding_to_enhanced(f, error_message=msg) for f in unique_findings_to_enrich]
                for ef in error_results:
                    hash_to_enhanced[finding_id_to_hash[ef.id]] = ef
            else:
                # 3. Batch Process Unique Findings
                from vexa.common.config import AI_MAX_CONCURRENT_BATCHES
                code_contexts = code_contexts or {}
                semaphore = asyncio.Semaphore(AI_MAX_CONCURRENT_BATCHES)
                
                batches = [unique_findings_to_enrich[i : i + self.batch_size] 
                          for i in range(0, len(unique_findings_to_enrich), self.batch_size)]
                
                logger.info("Enriching %d unique findings in %d batches", len(unique_findings_to_enrich), len(batches))

                async def _process_batch_with_limit(batch: List[Finding]) -> List[EnhancedFinding]:
                    async with semaphore:
                        return await self._process_batch(
                            batch, 
                            code_contexts=code_contexts, 
                            app_context=app_context,
                            is_workspace_scan=is_workspace_scan
                        )

                tasks = [_process_batch_with_limit(batch) for batch in batches]
                batch_executions = await asyncio.gather(*tasks, return_exceptions=True)
                
                for res in batch_executions:
                    if isinstance(res, list):
                        for ef in res:
                            f_hash = finding_id_to_hash[ef.id]
                            hash_to_enhanced[f_hash] = ef
                            # Save to persistent cache if successful (remediation found)
                            if ef.remediation_code and "failed" not in ef.remediation_code.lower():
                                self._cache[f_hash] = {
                                    "detailed_description": ef.detailed_description,
                                    "attack_scenario": ef.attack_scenario,
                                    "business_impact": ef.business_impact,
                                    "exploitability": ef.exploitability,
                                    "remediation_code": ef.remediation_code,
                                    "remediation_guidance": ef.remediation_guidance,
                                    "implementation_steps": ef.implementation_steps,
                                    "rollback_procedure": ef.rollback_procedure,
                                }
                    else:
                        logger.error("Batch failed: %s", res)
            
            # Save updated cache to disk
            self._save_cache()

        # 4. Final Re-mapping
        final_enhanced = []
        for f in to_enrich:
            f_hash = finding_id_to_hash[f.id]
            if f_hash in hash_to_enhanced:
                # Copy the enrichment from the representative finding to THIS specific instance
                template = hash_to_enhanced[f_hash]
                instance = self._finding_to_enhanced(f)
                for key in ["detailed_description", "attack_scenario", "business_impact", 
                           "exploitability", "remediation_code", "remediation_guidance", 
                           "implementation_steps", "rollback_procedure"]:
                    if hasattr(template, key):
                        setattr(instance, key, getattr(template, key))
                final_enhanced.append(instance)
            else:
                final_enhanced.append(self._finding_to_enhanced(f, error_message="AI enrichment skipped or failed"))

        # Filter False Positives
        all_results = filtered_results + final_enhanced
        final_findings, fps = await self.filter_false_positives(all_results)
        
        logger.info(
            "Enrichment complete: %d optimized (cached/deduped), %d total, %d FPs filtered",
            len(to_enrich) - len(unique_findings_to_enrich), len(findings), len(fps)
        )
        
        return final_findings, fps

    async def _process_batch(
        self, 
        batch: List[Finding],
        code_contexts: Dict[str, str],
        app_context: Optional[Dict[str, Any]] = None,
        is_workspace_scan: bool = False,
    ) -> List[EnhancedFinding]:
        """Process a single batch of findings with fallback logic."""
        batch_enhanced = []
        batch_error = None
        
        # Try primary provider
        try:
            if self._primary_provider.is_available:
                batch_enhanced = await self._primary_provider.analyze_findings_batch(
                    batch,
                    code_contexts=code_contexts,
                    batch_size=len(batch),
                    app_context=app_context,
                    is_workspace_scan=is_workspace_scan
                )
            else:
                status, msg = await self._primary_provider.check_availability()
                batch_error = f"Primary AI Provider Unavailable: {msg}"
        except Exception as e:
            logger.exception("Primary provider failed for batch: %s", e)
            batch_error = str(e)
            
        # If primary failed, we no longer fallback automatically
        if batch_error:
            logger.warning("AI analysis failed for batch: %s", batch_error)

        # Combine results for this batch
        batch_results = []
        enriched_ids = {f.id for f in batch_enhanced}
        
        for finding in batch:
            if finding.id in enriched_ids:
                # Successfully enriched
                for ef in batch_enhanced:
                    if ef.id == finding.id:
                        batch_results.append(ef)
                        break
            else:
                # Failed to enrich - use professional error message
                user_message = self._map_error_to_user_message(batch_error)
                batch_results.append(self._finding_to_enhanced(finding, error_message=user_message))
                
        return batch_results

    def _map_error_to_user_message(self, error: Optional[str]) -> str:
        """Map internal system errors to user-friendly messages."""
        if not error:
            return "AI Analysis Failed: Service Temporarily Unavailable"
            
        err_lower = error.lower()
        
        # Prioritize service/quota errors
        if any(kw in err_lower for kw in ["quota", "rate limit", "429", "too many requests"]):
            return "AI Analysis Failed: Quota Exceeded (429)"
        elif "timed out" in err_lower or "deadline" in err_lower:
            return "AI Analysis Failed: Service Timeout"
            
        # Distinguish between missing tool and incompatible tool
        if any(kw in err_lower for kw in ["file not found", "no such file", "command not found", "winerror 2"]):
            return "AI Analysis Failed: AI Tool Not Installed or Path Error"
            
        # If it failed but the command was likely found, check for arg errors (incompatibility)
        if any(kw in err_lower for kw in ["argument", "invalid option", "not recognized", "unknown option"]):
            return f"AI Analysis Failed: Incompatible AI Tool Version or Flags ({error[:40]})"
            
        if "api_key" in err_lower or "authentication" in err_lower or "unauthorized" in err_lower:
            return "AI Analysis Failed: Configuration Error (Missing/Invalid API Key)"
        elif "markdown" in err_lower or "parse" in err_lower:
            return "AI Analysis Failed: Parsing Error (Unexpected AI Response)"
            
        return f"AI Analysis Failed: {error[:60]}..." if error else "AI Analysis Failed: Service Unavailable"
    
    async def filter_false_positives(
        self,
        findings: List[EnhancedFinding],
    ) -> Tuple[List[EnhancedFinding], List[EnhancedFinding]]:
        """
        Filter findings based on false positive confidence.
        
        SS-010, SS-011: >90% FP detection confidence
        
        Args:
            findings: List of enhanced findings to filter
            
        Returns:
            Tuple of (valid_findings, false_positives)
        """
        valid = []
        false_positives = []
        
        for finding in findings:
            # Check if FP confidence is high
            fp_conf_percent = finding.false_positive_confidence * 100 if finding.false_positive_confidence <= 1.0 else finding.false_positive_confidence

            if finding.is_false_positive and fp_conf_percent > self.fp_threshold:
                false_positives.append(finding)
                logger.debug(
                    "Finding %s marked as FP (confidence: %.1f%%)",
                    finding.id, fp_conf_percent
                )
            else:
                valid.append(finding)
        
        logger.info(
            "FP filtering: %d valid, %d false positives (threshold: %.1f%%)",
            len(valid), len(false_positives), self.fp_threshold
        )
        
        return (valid, false_positives)
    
    async def generate_stride_threats(
        self,
        repository_path: str,
        categories: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate STRIDE threat analysis for repository.
        
        TM-001, TM-002: STRIDE threat models
        TM-005: Parallel STRIDE category execution
        
        Args:
            repository_path: Path to the repository
            categories: STRIDE categories to analyze (default: all)
            
        Returns:
            Dictionary with STRIDE analysis results
        """
        from pathlib import Path
        
        if categories is None:
            categories = [
                "spoofing",
                "tampering",
                "repudiation",
                "information_disclosure",
                "denial_of_service",
                "elevation_of_privilege",
            ]
        
        if not self._primary_provider:
            logger.warning("No AI provider available for STRIDE analysis")
            return {"error": "No AI provider available", "categories": {}}
        
        repo_path = Path(repository_path)
        
        # TM-005: Run categories in parallel
        tasks = [
            self._primary_provider.generate_stride_analysis(repo_path, category)
            for category in categories
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        stride_results = {}
        for category, result in zip(categories, results):
            if isinstance(result, Exception):
                logger.error("STRIDE analysis failed for %s: %s", category, result)
                stride_results[category] = {"error": str(result), "threats": []}
            else:
                stride_results[category] = result
        
        # Count total threats
        total_threats = sum(
            len(r.get("threats", []))
            for r in stride_results.values()
            if isinstance(r, dict)
        )
        
        logger.info(
            "STRIDE analysis completed: %d categories, %d total threats",
            len(categories), total_threats
        )
        
        return {
            "repository_path": str(repository_path),
            "categories": stride_results,
            "total_threats": total_threats,
            "provider": self._primary_provider.PROVIDER_TYPE.value,
        }
    
    def _finding_to_enhanced(self, finding: Finding, error_message: str = "") -> EnhancedFinding:
        """Convert a Finding to EnhancedFinding without AI enrichment."""
        return EnhancedFinding(
            id=finding.id,
            scanner=finding.scanner,
            severity=finding.severity,
            title=finding.title,
            description=finding.description,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end,
            code_snippet=finding.code_snippet,
            code_snippet_before=finding.code_snippet,  # Requirement: code_snippet (before)
            cwe_ids=finding.cwe_ids,
            owasp_category=finding.owasp_category,
            mitre_attack_id=finding.mitre_attack_id,
            nist_controls=finding.nist_controls,
            # Initialize other AI fields with defaults to ensure they are present in JSON
            detailed_description=error_message if error_message else "",
            attack_scenario="",
            business_impact="",
            exploitability="unknown",
            remediation_code=f"# {error_message}" if error_message else "",
            remediation_guidance=error_message if error_message else "",
            implementation_steps=[],
            rollback_procedure="",
            google_cloud_recommendation="",
            google_cloud_doc_links=[],
        )


# Singleton instance
_ai_manager: Optional[AIProviderManager] = None


def get_ai_manager(
    cloud_provider: CloudProvider = CloudProvider.NONE,
    ai_provider_override: Optional[str] = None,
    ai_model_override: Optional[str] = None,
    api_key_override: Optional[str] = None,
    ollama_url_override: Optional[str] = None,
    min_severity: str = AI_MIN_SEVERITY_THRESHOLD
) -> AIProviderManager:
    """
    Get the AI Provider Manager singleton.
    
    Args:
        cloud_provider: Cloud provider to configure
        ai_provider_override: Optional direct string override ("google", "openai", "anthropic")
        api_key_override: Optional API key material to pass to the provider
        ollama_url_override: Optional URL for local Ollama instance
        min_severity: Minimum severity threshold for AI enrichment
        
    Returns:
        AIProviderManager instance
    """
    global _ai_manager
    if (
        _ai_manager is None or 
        _ai_manager.cloud_provider != cloud_provider or 
        _ai_manager.ai_provider_override != ai_provider_override or
        _ai_manager.ai_model_override != ai_model_override or
        _ai_manager.api_key_override != api_key_override or
        _ai_manager.ollama_url_override != ollama_url_override or
        _ai_manager.min_severity != min_severity
    ):
        _ai_manager = AIProviderManager(
            cloud_provider=cloud_provider,
            ai_provider_override=ai_provider_override,
            ai_model_override=ai_model_override,
            api_key_override=api_key_override,
            ollama_url_override=ollama_url_override,
            min_severity=min_severity
        )
    return _ai_manager
