"""
Attestation Verifier for Vexa.

Verifies that a previously generated attestation matches a local
scan result and commit SHA. Used by `vexa verify` CLI command.
"""

import hashlib
import json
from pathlib import Path
from typing import List, Optional, Tuple

from vexa.common.logging import get_logger

logger = get_logger(__name__)


class AttestationVerifier:
    """
    Verifies Vexa attestation statements against local state.

    Checks:
    1. The attestation references the correct commit SHA.
    2. The scan result digest matches the provided SARIF/JSON file.
    3. The policy verdict is PASS.
    """

    def __init__(self, workspace_path: Path):
        self.workspace_path = workspace_path.resolve()

    def verify(
        self,
        attestation_path: Path,
        scan_result_path: Optional[Path] = None,
        expected_commit: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Verify an attestation file.

        Args:
            attestation_path: Path to the .intoto.jsonl attestation file.
            scan_result_path: Optional path to a SARIF/JSON scan result to verify digest.
            expected_commit: Optional commit SHA to verify against.

        Returns:
            Tuple of (is_valid, list_of_messages).
        """
        messages = []

        if not attestation_path.exists():
            return False, [f"Attestation file not found: {attestation_path}"]

        try:
            lines = attestation_path.read_text(encoding="utf-8").strip().splitlines()
            if not lines:
                return False, ["Attestation file is empty."]

            # Verify the latest attestation (last line)
            statement = json.loads(lines[-1])
        except (json.JSONDecodeError, IndexError) as e:
            return False, [f"Failed to parse attestation: {e}"]

        # 1. Verify statement type
        if statement.get("_type") != "https://in-toto.io/Statement/v1":
            messages.append("⚠️ Unknown attestation type.")

        # 2. Verify predicate
        predicate = statement.get("predicate", {})

        policy = predicate.get("policyVerdict", "UNKNOWN")
        if policy == "PASS":
            messages.append("✅ Policy verdict: PASS")
        else:
            messages.append(f"❌ Policy verdict: {policy}")

        messages.append(f"📊 Total findings: {predicate.get('totalFindings', 'N/A')}")
        messages.append(f"🔧 Scanners: {', '.join(predicate.get('scannersRun', []))}")
        messages.append(f"🕐 Timestamp: {predicate.get('timestamp', 'N/A')}")
        messages.append(f"🛡️ Telemetry: {predicate.get('telemetryPolicy', 'N/A')}")

        # 3. Verify commit SHA
        subjects = statement.get("subject", [])
        attestation_commit = None
        attestation_digest = None

        for subj in subjects:
            annots = subj.get("annotations", {})
            attestation_commit = annots.get("git_commit")
            attestation_digest = subj.get("digest", {}).get("sha256")

        if expected_commit:
            if attestation_commit == expected_commit:
                messages.append(f"✅ Commit SHA matches: {expected_commit[:12]}")
            else:
                messages.append(
                    f"❌ Commit mismatch: expected {expected_commit[:12]}, "
                    f"got {attestation_commit[:12] if attestation_commit else 'N/A'}"
                )
                return False, messages
        elif attestation_commit:
            messages.append(f"📝 Attested commit: {attestation_commit[:12]}")

        # 4. Verify scan result digest
        if scan_result_path and attestation_digest:
            if scan_result_path.exists():
                actual_digest = hashlib.sha256(
                    scan_result_path.read_text(encoding="utf-8").encode("utf-8")
                ).hexdigest()
                if actual_digest == attestation_digest:
                    messages.append("✅ Scan result digest matches.")
                else:
                    messages.append("❌ Scan result digest mismatch!")
                    return False, messages
            else:
                messages.append(f"⚠️ Scan result file not found: {scan_result_path}")

        is_valid = policy == "PASS"
        return is_valid, messages
