"""
Detect-Secrets Scanner for Secret Detection.

SS-001: detect-secrets - Hardcoded secrets detection
Modes: LOCAL, CONTAINER
"""

import json
from pathlib import Path
from typing import List, Optional

from vexa.scanners.base import (
    BaseScanner,
    Finding,
    FindingSeverity,
    ScanMode,
)
from vexa.common.logging import get_logger


logger = get_logger(__name__)


class DetectSecretsScanner(BaseScanner):
    """
    detect-secrets scanner for finding hardcoded secrets.

    detect-secrets is an enterprise-friendly tool for
    detecting secrets in source code.
    """

    name = "detect-secrets"
    supported_modes = [ScanMode.LOCAL, ScanMode.CONTAINER]

    def get_command(
        self, path: Path, exclusions: Optional[List[str]] = None
    ) -> List[str]:
        """Build detect-secrets command."""
        cmd = [
            "detect-secrets",
            "scan",
        ]

        # --all-files is only for directory scans. For single files, it's better to pass the file directly.
        if path.is_dir():
            cmd.append("--all-files")

        if exclusions:
            for ex in exclusions:
                # detect-secrets takes a regex for --exclude-files.
                # We do simple escaping to make it behave like a path pattern.
                # We avoid join("|") and parens to comply with SEC-002 (Command Injection Prevention).
                regex = ex.replace(".", "\\.").replace("*", ".*")
                if regex.endswith("/"):
                    regex = regex[:-1]
                cmd.extend(["--exclude-files", regex])

        cmd.append(str(path))
        return cmd

    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """Parse detect-secrets JSON output into normalized findings."""
        findings = []

        if not output.strip():
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse detect-secrets JSON output: %s", e)
            return findings

        # detect-secrets output format: { "results": { "filename": [...] } }
        results = data.get("results", {})

        for raw_file_path, secrets in results.items():
            # Normalize path: forward slashes and remove ./ prefix
            file_path = raw_file_path.replace("\\", "/")
            if file_path.startswith("./"):
                file_path = file_path[2:]

            if target_path.is_file():
                full_path = target_path
            else:
                full_path = (
                    (target_path / file_path).resolve()
                    if not Path(file_path).is_absolute()
                    else Path(file_path)
                )

            # Optimization: Cache file lines if multiple secrets in same file
            file_lines = []
            if full_path.exists():
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        file_lines = f.readlines()
                except Exception:
                    pass

            for secret in secrets:
                line_idx = secret.get("line_number", 1) - 1
                snippet = ""
                if 0 <= line_idx < len(file_lines):
                    snippet = file_lines[line_idx].strip()

                # Use a static rule ID based on the secret type
                secret_type = secret.get("type", "secret")
                rule_id = secret_type.lower().replace(" ", "-")

                # Filter out false positives for "Secret Keyword" in common import statements [FP-002]
                if secret_type == "Secret Keyword" and (
                    snippet.startswith("import ") or snippet.startswith("from ")
                ):
                    continue

                # Map specific secret types to more granular CWEs
                cwe_mapping = {
                    "AWS Access Key": ["CWE-798", "CWE-312", "CWE-320"],
                    "Private Key": ["CWE-320", "CWE-312"],
                    "RSA Private Key": ["CWE-320", "CWE-312"],
                    "Cryptographic Key": ["CWE-320", "CWE-312"],
                    "Base64 High Entropy String": ["CWE-312"],
                    "Hex High Entropy String": ["CWE-312"],
                    "Secret Keyword": ["CWE-798", "CWE-259"],
                    "Password": ["CWE-798", "CWE-259"],
                    "Jenkins Crumb": ["CWE-798"],
                    "Slack Token": ["CWE-798", "CWE-312"],
                    "Stripe API Key": ["CWE-798", "CWE-312"],
                    "GitHub Token": ["CWE-798", "CWE-312"],
                }

                cwe_ids = cwe_mapping.get(secret_type, ["CWE-798", "CWE-259"])

                finding = Finding(
                    id=f"detect-secrets-{rule_id}",
                    scanner=self.name,
                    title=f"Hardcoded {secret.get('type', 'Secret')}",
                    description=f"Potential {secret.get('type', 'secret')} detected in code",
                    severity=FindingSeverity.HIGH,
                    file_path=file_path,
                    line_start=secret.get("line_number", 0),
                    line_end=secret.get("line_number", 0),
                    code_snippet=snippet,
                    confidence="high" if secret.get("is_verified") else "medium",
                    cwe_ids=cwe_ids,
                    raw_data=secret,
                )
                findings.append(finding)

        return findings
