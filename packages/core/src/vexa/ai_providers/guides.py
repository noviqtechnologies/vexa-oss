"""
Security Enhancement Guides for AI Providers.

These guides provide the structured requirements and templates used to generate
high-quality, code-level analysis for security findings.
"""

CRITICAL_REQUIREMENTS = """
**Critical Requirements:**
1. **Show exact file paths and line numbers** affected.
2. **Provide a Remediation Code snippet** showing the fix.
3. **Create specific test cases** with expected outputs for verification.
4. **Document the Business Impact** clearly and professionally (do NOT include revenue loss details or financial estimates).
5. **Reference actual cloud services** (GCP/AWS/Azure) used in the application context.
"""

GOOGLE_ENHANCEMENT_GUIDE = f"""
**Follow this Google Cloud Security Enhancement Guide:**
# 1. **CLI Synchronization**: Use `gcloud` commands for all remediation steps.
2. **Security Pillars**: Align with Google Cloud Security Command Center best practices.
3. **Reference Docs**: Cite specific links from cloud.google.com/security.
{CRITICAL_REQUIREMENTS}
"""

AWS_ENHANCEMENT_GUIDE = f"""
**Follow this AWS Well-Architected Security Guide:**
# 1. **CLI Synchronization**: Use `aws` CLI commands for all remediation steps.
2. **Security Pillars**: Align with the AWS Well-Architected Security Pillar.
3. **Reference Docs**: Cite specific links from docs.aws.amazon.com/security.
{CRITICAL_REQUIREMENTS}
"""

AZURE_ENHANCEMENT_GUIDE = f"""
**Follow this Azure Security Benchmark Guide:**
# 1. **CLI Synchronization**: Use `az` CLI commands for all remediation steps.
2. **Security Pillars**: Align with Azure Security Benchmark v3.
3. **Reference Docs**: Cite specific links from learn.microsoft.com/azure/security.
{CRITICAL_REQUIREMENTS}
"""

def get_guide(provider: str) -> str:
    """Return the enhancement guide for the specified provider."""
    provider_lower = provider.lower()
    if "google" in provider_lower or "gcp" in provider_lower:
        return GOOGLE_ENHANCEMENT_GUIDE
    elif "aws" in provider_lower or "amazon" in provider_lower:
        return AWS_ENHANCEMENT_GUIDE
    elif "azure" in provider_lower or "microsoft" in provider_lower:
        return AZURE_ENHANCEMENT_GUIDE
    return ""
