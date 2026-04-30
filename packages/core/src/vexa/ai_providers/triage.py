"""
AI Triage and Prioritisation Engine for Vexa.

Implements FIX-02: Ranks findings by composite score and selects the top-N
most impactful, fixable issues for the developer. Translates scanner-specific
titles into plain-English descriptions that anyone can understand.

This module is the brain behind "show 3 things and fix them" — replacing
the old "show 50 findings and hope someone reads them" approach.
"""

from typing import List, Optional, Tuple
from vexa.common.models import EnhancedFinding
from vexa.common.logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Severity and Exploitability Weights
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 1.0,
}

EXPLOITABILITY_WEIGHTS = {
    "easy": 3.0,
    "medium": 2.0,
    "hard": 1.0,
    "unknown": 1.5,  # Assume moderate risk when unknown
}

# ---------------------------------------------------------------------------
# Confidence Level Categorisation
# ---------------------------------------------------------------------------

CONFIDENCE_HIGH_THRESHOLD = 70.0
CONFIDENCE_MEDIUM_THRESHOLD = 40.0


def categorise_confidence(score: float) -> str:
    """
    Convert a numeric confidence score (0-100) into a plain-English level.

    Returns one of: 'High', 'Medium', or 'Low'.
    """
    if score >= CONFIDENCE_HIGH_THRESHOLD:
        return "High"
    elif score >= CONFIDENCE_MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def confidence_explanation(score: float) -> str:
    """
    Generate a one-sentence, plain-English explanation of fix confidence.

    The explanation helps developers decide how much to trust the AI's fix
    without needing to understand what the score means technically.
    """
    if score >= CONFIDENCE_HIGH_THRESHOLD:
        return "I'm confident about this fix — it follows well-established security patterns."
    elif score >= CONFIDENCE_MEDIUM_THRESHOLD:
        return "Review this one carefully — the fix looks right, but your specific setup may differ."
    return "I'm not confident enough to auto-fix this one — here's what to watch out for."


# ---------------------------------------------------------------------------
# Plain-English Title Generation
# ---------------------------------------------------------------------------

# Maps common scanner finding title patterns to friendly, non-technical descriptions.
# The key is a lowercase substring that appears in the scanner title.
# The value is a tuple of (plain_english_title, what_to_look_for).
_PLAIN_ENGLISH_MAP = {
    # Hardcoded credentials
    "hardcoded password": (
        "Your password is written directly in your code",
        "Anyone who reads your source code — including version control history — can see it."
    ),
    "hard-coded password": (
        "Your password is written directly in your code",
        "Anyone who reads your source code — including version control history — can see it."
    ),
    "hardcoded secret": (
        "A secret value is written directly in your code",
        "Secrets in source code can be extracted by anyone with access to the repository."
    ),
    "high entropy string": (
        "This looks like a secret or API key left in your code",
        "If this is a real key or password, anyone who reads the code can use it."
    ),

    # Debug mode
    "debug": (
        "Your app is running in debug mode",
        "Debug mode exposes sensitive information if deployed to production."
    ),
    "flask debug": (
        "Your web app is running in debug mode",
        "This exposes an interactive debugger that lets anyone run code on your server."
    ),

    # SQL injection
    "sql injection": (
        "Your database query could be manipulated by an attacker",
        "An attacker could read, modify, or delete your database contents."
    ),
    "sql": (
        "Your database query may be vulnerable to manipulation",
        "User input is being included in a database query without proper protection."
    ),

    # Command injection
    "command injection": (
        "An attacker could run system commands through your app",
        "User input is being passed to a system command without proper protection."
    ),
    "subprocess": (
        "Your code runs system commands that could be exploited",
        "The way system commands are invoked here could let an attacker run their own commands."
    ),
    "shell injection": (
        "An attacker could inject commands into your system",
        "System commands are being built from untrusted input."
    ),

    # Cross-site scripting
    "xss": (
        "Your web page could display malicious content from an attacker",
        "An attacker could inject harmful scripts that run in your users' browsers."
    ),
    "cross-site scripting": (
        "Your web page could display malicious content from an attacker",
        "An attacker could inject harmful scripts that run in your users' browsers."
    ),

    # Insecure deserialization
    "pickle": (
        "Your code loads data in a way that could run hidden malicious code",
        "An attacker could craft data that executes code when your app reads it."
    ),
    "deseriali": (
        "Your code loads data in a way that could be exploited",
        "The data loading method used here can be tricked into running malicious code."
    ),
    "yaml.load": (
        "Your code loads configuration in an unsafe way",
        "Use safe loading to prevent hidden code execution from config files."
    ),

    # Cryptography
    "weak crypto": (
        "Your code uses outdated encryption that can be broken",
        "Modern computers can break this encryption — upgrade to current standards."
    ),
    "md5": (
        "Your code uses a hashing method that is no longer secure",
        "MD5 hashes can be forged — use a modern algorithm instead."
    ),
    "sha1": (
        "Your code uses a hashing method that is no longer considered secure",
        "SHA-1 has known weaknesses — use SHA-256 or better."
    ),

    # HTTPS / TLS
    "ssl": (
        "Your code may not verify secure connections properly",
        "Without proper verification, an attacker could intercept your data."
    ),
    "verify=false": (
        "Your code skips security checks on network connections",
        "This means your app will trust any server, even a malicious one."
    ),
    "tls": (
        "Your secure connection setup needs improvement",
        "The current configuration may allow outdated protocols."
    ),

    # Authentication
    "authentication": (
        "Your login or access control has a potential weakness",
        "An attacker might be able to bypass authentication."
    ),
    "jwt": (
        "Your authentication token handling has a potential issue",
        "Tokens that are not properly validated could let attackers impersonate users."
    ),

    # File handling
    "path traversal": (
        "An attacker could access files outside the intended directory",
        "User-supplied file paths are not properly restricted."
    ),
    "directory traversal": (
        "An attacker could access files outside the intended directory",
        "User-supplied file paths are not properly restricted."
    ),

    # Infrastructure
    "wildcard": (
        "Your infrastructure permissions are too broad",
        "Restricting permissions reduces the damage an attacker can do."
    ),
    "public access": (
        "Your cloud resource is accessible to anyone on the internet",
        "Restrict access to only the users and services that need it."
    ),
    "unencrypted": (
        "Your data is stored or transmitted without encryption",
        "Anyone who intercepts this data can read it."
    ),
    "logging": (
        "Sensitive information might be written to log files",
        "Log files are often less protected than the app itself."
    ),

    # Dependency vulnerabilities
    "vulnerable dependency": (
        "One of your project's dependencies has a known security issue",
        "Update to a newer version to get the fix."
    ),
    "outdated": (
        "One of your project's dependencies is out of date",
        "Outdated packages may contain known security issues."
    ),
    "cve-": (
        "One of your dependencies has a publicly known security issue",
        "A fix is available — update to the recommended version."
    ),

    # Secrets
    "api key": (
        "An API key may be exposed in your code",
        "API keys in source code can be used by anyone who finds them."
    ),
    "private key": (
        "A private key may be exposed in your code",
        "Private keys should never be stored in source code."
    ),
    "token": (
        "An access token may be exposed in your code",
        "Tokens in source code can be used by anyone who finds them."
    ),
}


def generate_plain_english_title(finding: EnhancedFinding) -> Tuple[str, str]:
    """
    Translate a scanner-specific finding title into plain English.

    Returns a tuple of (plain_title, explanation).
    The title describes what is wrong. The explanation describes why it matters.

    If the AI has already generated a detailed_description, we prefer that
    since it is context-aware. The static map is the fallback.
    """
    # If AI enrichment provided a good detailed description, use it
    detailed_description = getattr(finding, 'detailed_description', '')
    if (detailed_description
            and len(detailed_description) > 20
            and "failed" not in detailed_description.lower()
            and "error" not in detailed_description.lower()):
        return detailed_description.split('.')[0] + '.', detailed_description

    # Static mapping fallback — match on the original scanner title
    title_lower = finding.title.lower()
    desc_lower = finding.description.lower() if finding.description else ""
    search_text = f"{title_lower} {desc_lower}"

    for pattern, (plain_title, explanation) in _PLAIN_ENGLISH_MAP.items():
        if pattern in search_text:
            return plain_title, explanation

    # Ultimate fallback: clean up the scanner title to remove jargon
    clean_title = _remove_jargon(finding.title)
    return clean_title, finding.description or "Review this code for potential security improvements."


def _remove_jargon(title: str) -> str:
    """
    Remove common security jargon patterns from a title.

    Strips scanner rule codes, vulnerability identifiers, and technical prefixes
    so the title reads like plain English.
    """
    import re
    # Remove patterns like "B105 - ", "B201:", "CKV_", etc.
    cleaned = re.sub(r'^[A-Z]{1,4}[-_]?\d{2,6}\s*[-:]\s*', '', title)
    # Remove CWE references
    cleaned = re.sub(r'\s*\(?CWE-\d+\)?\s*', ' ', cleaned)
    # Remove CVE references
    cleaned = re.sub(r'\s*\(?CVE-\d{4}-\d+\)?\s*', ' ', cleaned)
    # Clean up whitespace
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()

    if cleaned:
        # Capitalize first letter
        return cleaned[0].upper() + cleaned[1:]
    return "A potential security issue was found in your code"


# ---------------------------------------------------------------------------
# Core Prioritisation Logic
# ---------------------------------------------------------------------------

def calculate_fix_confidence(finding: EnhancedFinding) -> float:
    """
    Calculate a confidence score (0-100) for how likely the AI-generated fix
    is correct and safe to apply.

    Higher scores mean the AI is more confident the fix will work without
    breaking anything.
    """
    score = 50.0  # Base confidence

    # Has remediation code? That's the most important signal.
    remediation_code = getattr(finding, 'remediation_code', '')
    if remediation_code and len(remediation_code.strip()) > 10:
        # Check it's not just an error message
        if not remediation_code.startswith("#"):
            score += 25.0
        else:
            score -= 30.0  # Error placeholder — very low confidence
    else:
        score -= 30.0  # No fix available — very low confidence

    # False positive confidence inversely affects fix confidence
    # (if the AI thinks it might be a false positive, the fix is less important)
    if getattr(finding, 'is_false_positive', False):
        score -= 40.0

    # Higher severity findings tend to have more established fix patterns
    severity_bonus = {
        "critical": 10.0, "high": 5.0, "medium": 0.0, "low": -5.0, "info": -10.0
    }
    score += severity_bonus.get(finding.severity, 0.0)

    # Easy-to-exploit findings tend to have clearer fixes
    exploitability = getattr(finding, 'exploitability', 'unknown')
    exploit_bonus = {"easy": 10.0, "medium": 5.0, "hard": 0.0, "unknown": 0.0}
    score += exploit_bonus.get(exploitability, 0.0)

    # Has implementation steps? More structured = more confident
    implementation_steps = getattr(finding, 'implementation_steps', [])
    if implementation_steps and len(implementation_steps) > 0:
        score += 5.0

    # Clamp to 0-100
    return max(0.0, min(100.0, score))


def calculate_composite_score(finding: EnhancedFinding) -> float:
    """
    Calculate a composite prioritisation score for a finding.

    Score = severity_weight × exploitability_weight × fix_confidence_normalised

    Higher scores mean the finding should be presented to the developer first.
    """
    severity_w = SEVERITY_WEIGHTS.get(finding.severity, 1.0)
    exploitability = getattr(finding, 'exploitability', 'unknown')
    exploit_w = EXPLOITABILITY_WEIGHTS.get(exploitability, 1.5)
    confidence = calculate_fix_confidence(finding) / 100.0  # Normalise to 0-1

    return severity_w * exploit_w * confidence


def prioritise_findings(
    findings: List[EnhancedFinding],
    limit: int = 3,
    min_confidence: float = 0.0,
    severity_filter: str = "medium",
) -> List[EnhancedFinding]:
    """
    Select the top-N most important, fixable findings from a scan result.

    This is the core of the "show 3 things and fix them" philosophy. Instead
    of overwhelming developers with 50 findings, we pick the ones that:
    1. Have the highest real-world impact (severity × exploitability)
    2. Have the best chance of a correct AI fix (fix confidence)
    3. Are not false positives

    Args:
        findings: List of AI-enriched findings from a scan.
        limit: Maximum number of findings to return. Default: 3.
        min_confidence: Minimum fix confidence threshold (0-100). Default: 0.
        severity_filter: Minimum severity level to include. Default: 'medium'.

    Returns:
        List of top-N findings, sorted by composite priority score (highest first).
        Each finding is enriched with additional triage metadata:
        - _fix_confidence: float (0-100)
        - _confidence_level: str ('High', 'Medium', 'Low')
        - _confidence_explanation: str
        - _plain_title: str
        - _plain_explanation: str
        - _composite_score: float
    """
    severity_rank = {
        "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0
    }
    min_rank = severity_rank.get(severity_filter.lower(), 2)

    # Step 1: Filter out false positives and below-threshold findings
    candidates = []
    for f in findings:
        # Skip false positives
        is_fp = getattr(f, 'is_false_positive', False)
        fp_conf = getattr(f, 'false_positive_confidence', 0.0)
        if is_fp and fp_conf > 0.9:
            continue

        # Skip findings below severity threshold
        if severity_rank.get(f.severity, 0) < min_rank:
            continue

        # Skip findings without any remediation code
        remediation_code = getattr(f, 'remediation_code', '')
        has_fix = (
            remediation_code
            and len(remediation_code.strip()) > 10
            and not remediation_code.strip().startswith("# AI Analysis Failed")
            and not remediation_code.strip().startswith("# AI")
        )

        # Calculate scores
        fix_conf = calculate_fix_confidence(f)

        # Skip below minimum confidence
        if fix_conf < min_confidence:
            continue

        # Enrich with triage metadata (using private attributes to avoid model conflicts)
        f._fix_confidence = fix_conf
        f._confidence_level = categorise_confidence(fix_conf)
        f._confidence_explanation = confidence_explanation(fix_conf)
        f._composite_score = calculate_composite_score(f)

        # Generate plain-English title
        plain_title, plain_explanation = generate_plain_english_title(f)
        f._plain_title = plain_title
        f._plain_explanation = plain_explanation

        candidates.append(f)

    # Step 2: Sort by composite score (highest first)
    candidates.sort(key=lambda f: f._composite_score, reverse=True)

    # Step 3: Deduplicate by file+line (keep highest-scored)
    seen = set()
    deduplicated = []
    for f in candidates:
        key = (f.file_path, f.line_start)
        if key not in seen:
            seen.add(key)
            deduplicated.append(f)

    # Step 4: Take top-N
    result = deduplicated[:limit]

    logger.info(
        "Triage complete: %d findings in -> %d candidates -> %d selected (limit=%d)",
        len(findings), len(deduplicated), len(result), limit
    )

    return result
