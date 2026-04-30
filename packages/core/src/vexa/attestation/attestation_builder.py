"""
In-toto v1 Attestation Builder for Vexa.

Generates attestation statements that cryptographically bind:
- A git commit SHA
- A scan result digest (SHA-256 of SARIF/JSON output)
- The policy verdict (pass/fail)
- Scanner versions used

Format follows the in-toto Statement v1 specification:
https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
"""

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from vexa.common.logging import get_logger

logger = get_logger(__name__)

# In-toto v1 constants
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE_VEXA = "https://usevexa.dev/attestation/scan-result/v1"


class AttestationBuilder:
    """
    Builds in-toto v1 attestation statements for Vexa scan results.

    The attestation binds a specific commit to a scan result, enabling
    downstream verification that a codebase passed a security policy
    before being released or deployed.
    """

    def __init__(self, workspace_path: Path):
        self.workspace_path = workspace_path.resolve()

    def get_git_commit_sha(self) -> Optional[str]:
        """Get the current HEAD commit SHA from git."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                cwd=str(self.workspace_path),
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning("Git not available or timed out: %s", e)
        return None

    def compute_digest(self, data: str) -> str:
        """Compute SHA-256 digest of the given data."""
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def build_statement(
        self,
        scan_result_json: str,
        policy_verdict: str,
        scanners_run: List[str],
        total_findings: int,
        severity_counts: Optional[Dict[str, int]] = None,
        commit_sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build an in-toto v1 attestation statement.

        Args:
            scan_result_json: JSON string of the scan result (used for digest).
            policy_verdict: "PASS" or "FAIL".
            scanners_run: List of scanner names that were executed.
            total_findings: Total number of findings.
            severity_counts: Optional dict of severity -> count.
            commit_sha: Optional git commit SHA (auto-detected if not provided).

        Returns:
            In-toto Statement v1 dictionary.
        """
        # Auto-detect commit
        if not commit_sha:
            commit_sha = self.get_git_commit_sha()

        result_digest = self.compute_digest(scan_result_json)

        subject = {
            "name": str(self.workspace_path),
            "digest": {"sha256": result_digest},
        }

        if commit_sha:
            subject["annotations"] = {"git_commit": commit_sha}

        predicate = {
            "scanner": "Vexa",
            "scannerVersion": self._get_vexa_version(),
            "scannersRun": scanners_run,
            "policyVerdict": policy_verdict,
            "totalFindings": total_findings,
            "severityCounts": severity_counts or {},
            "telemetryPolicy": "zero-telemetry",
            "executionEnvironment": "local",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        statement = {
            "_type": STATEMENT_TYPE,
            "subject": [subject],
            "predicateType": PREDICATE_TYPE_VEXA,
            "predicate": predicate,
        }

        logger.info(
            "Attestation built: commit=%s, verdict=%s, findings=%d",
            commit_sha or "unknown",
            policy_verdict,
            total_findings,
        )

        return statement

    def save_statement(
        self, statement: Dict[str, Any], output_path: Optional[Path] = None
    ) -> Path:
        """
        Save the attestation statement to disk.

        Args:
            statement: The in-toto statement dict.
            output_path: Output file path (default: workspace/.vexa/attestation.intoto.jsonl).

        Returns:
            Path to the saved attestation file.
        """
        if output_path is None:
            output_dir = self.workspace_path / ".vexa"
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / "attestation.intoto.jsonl"

        # JSONL format (one statement per line, appendable)
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(statement, separators=(",", ":")) + "\n")

        logger.info("Attestation saved to %s", output_path)
        return output_path

    def _get_vexa_version(self) -> str:
        """Get the installed Vexa version."""
        try:
            from vexa import __version__

            return __version__
        except ImportError:
            return "unknown"
