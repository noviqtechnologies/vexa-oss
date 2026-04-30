"""
Remediation Engine for Vexa Agentic Self-Healing.

Provides structured, line-range patch application with ledger tracking,
verification via re-scan, and rollback support.

Implements Pivot 1 of the 2026 Technical Moat strategy.
"""

import json
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from vexa.common.logging import get_logger

logger = get_logger(__name__)


class PatchEntry:
    """Represents a single applied patch."""

    def __init__(
        self,
        file_path: str,
        finding_id: str,
        finding_title: str,
        severity: str,
        line_start: int,
        line_end: int,
        original_code: str,
        patched_code: str,
        status: str = "applied",
    ):
        self.id = uuid.uuid4().hex[:8]
        self.file_path = file_path
        self.finding_id = finding_id
        self.finding_title = finding_title
        self.severity = severity
        self.line_start = line_start
        self.line_end = line_end
        self.original_code = original_code
        self.patched_code = patched_code
        self.status = status  # applied | verified | failed | rolled_back
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "file_path": self.file_path,
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "severity": self.severity,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "original_code": self.original_code,
            "patched_code": self.patched_code,
            "status": self.status,
            "timestamp": self.timestamp,
        }


class PatchLedger:
    """Tracks all patches applied during a remediation session."""

    def __init__(self, workspace_path: Path):
        self.workspace_path = workspace_path
        self.ledger_dir = workspace_path / ".vexa"
        self.ledger_file = self.ledger_dir / "patch_ledger.json"
        self.entries: List[PatchEntry] = []
        self._load()

    def _load(self) -> None:
        """Load existing ledger from disk."""
        if self.ledger_file.exists():
            try:
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # We only load metadata; entries are session-scoped
                    logger.debug(
                        "Loaded patch ledger with %d historical entries",
                        len(data.get("entries", [])),
                    )
            except Exception as e:
                logger.warning("Failed to load patch ledger: %s", e)

    def save(self) -> None:
        """Persist the ledger to disk."""
        try:
            self.ledger_dir.mkdir(parents=True, exist_ok=True)
            data = {
                "workspace": str(self.workspace_path),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "entries": [e.to_dict() for e in self.entries],
            }
            with open(self.ledger_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error("Failed to save patch ledger: %s", e)

    def add(self, entry: PatchEntry) -> None:
        self.entries.append(entry)

    def get_applied_count(self) -> int:
        return sum(1 for e in self.entries if e.status == "applied")

    def get_verified_count(self) -> int:
        return sum(1 for e in self.entries if e.status == "verified")

    def get_failed_count(self) -> int:
        return sum(1 for e in self.entries if e.status == "failed")

    def mark_verified(self, patch_id: str) -> None:
        for e in self.entries:
            if e.id == patch_id:
                e.status = "verified"
                return

    def mark_failed(self, patch_id: str) -> None:
        for e in self.entries:
            if e.id == patch_id:
                e.status = "failed"
                return


class RemediationEngine:
    """
    Core engine for applying, verifying, and rolling back security patches.

    Features:
    - Line-range based patching (not naive string replacement)
    - Automated workspace snapshotting
    - Patch ledger for audit trail
    - Iterative scan-patch-verify loop
    """

    def __init__(self, workspace_path: Path):
        self.workspace_path = workspace_path.resolve()
        self.ledger = PatchLedger(self.workspace_path)
        self.backup_dir: Optional[Path] = None

    def create_snapshot(self) -> Path:
        """Create a backup snapshot of the workspace for rollback."""
        self.backup_dir = (
            Path(tempfile.gettempdir()) / f"vexa_backup_{self.workspace_path.name}"
        )
        try:
            if self.backup_dir.exists():
                shutil.rmtree(self.backup_dir)
            shutil.copytree(self.workspace_path, self.backup_dir, dirs_exist_ok=True)
            logger.info("Workspace snapshot created at %s", self.backup_dir)
            return self.backup_dir
        except Exception as e:
            logger.error("Failed to create snapshot: %s", e)
            raise RuntimeError(f"Snapshot creation failed: {e}")

    def apply_patch(
        self,
        file_path: str,
        finding_id: str,
        finding_title: str,
        severity: str,
        line_start: int,
        line_end: int,
        original_code: str,
        patched_code: str,
    ) -> Optional[PatchEntry]:
        """
        Apply a patch using line-range replacement.

        Args:
            file_path: Absolute path to the target file.
            finding_id: ID of the finding being remediated.
            finding_title: Title of the finding.
            severity: Severity level.
            line_start: 1-indexed start line of the vulnerable code.
            line_end: 1-indexed end line of the vulnerable code.
            original_code: The original vulnerable code snippet.
            patched_code: The AI-generated remediation code.

        Returns:
            PatchEntry if successful, None otherwise.
        """
        target = Path(file_path)
        if not target.exists():
            logger.error("Target file does not exist: %s", file_path)
            return None

        try:
            lines = target.read_text(encoding="utf-8").splitlines(keepends=True)

            # Validate line range
            if line_start < 1 or line_end > len(lines):
                logger.warning(
                    "Line range [%d-%d] out of bounds for %s (%d lines). Falling back to string match.",
                    line_start,
                    line_end,
                    file_path,
                    len(lines),
                )
                return self._apply_patch_string_match(
                    target,
                    finding_id,
                    finding_title,
                    severity,
                    line_start,
                    line_end,
                    original_code,
                    patched_code,
                )

            # Line-range replacement (0-indexed internally)
            before = lines[: line_start - 1]
            after = lines[line_end:]

            # Ensure patched_code ends with newline
            if patched_code and not patched_code.endswith("\n"):
                patched_code += "\n"

            new_content = "".join(before) + patched_code + "".join(after)
            target.write_text(new_content, encoding="utf-8")

            entry = PatchEntry(
                file_path=file_path,
                finding_id=finding_id,
                finding_title=finding_title,
                severity=severity,
                line_start=line_start,
                line_end=line_end,
                original_code=original_code,
                patched_code=patched_code,
            )
            self.ledger.add(entry)
            logger.info(
                "Patch applied: %s @ L%d-%d (%s)",
                file_path,
                line_start,
                line_end,
                finding_title,
            )
            return entry

        except Exception as e:
            logger.error("Failed to apply patch to %s: %s", file_path, e)
            return None

    def _apply_patch_string_match(
        self,
        target: Path,
        finding_id: str,
        finding_title: str,
        severity: str,
        line_start: int,
        line_end: int,
        original_code: str,
        patched_code: str,
    ) -> Optional[PatchEntry]:
        """Fallback: apply patch via string replacement when line numbers are unreliable."""
        try:
            content = target.read_text(encoding="utf-8")
            if original_code and original_code in content:
                new_content = content.replace(original_code, patched_code, 1)
                target.write_text(new_content, encoding="utf-8")
                entry = PatchEntry(
                    file_path=str(target),
                    finding_id=finding_id,
                    finding_title=finding_title,
                    severity=severity,
                    line_start=line_start,
                    line_end=line_end,
                    original_code=original_code,
                    patched_code=patched_code,
                )
                self.ledger.add(entry)
                logger.info(
                    "Patch applied (string match fallback): %s (%s)",
                    target,
                    finding_title,
                )
                return entry
            else:
                logger.warning(
                    "Original code snippet not found in %s for finding %s",
                    target,
                    finding_id,
                )
                return None
        except Exception as e:
            logger.error("String-match patch failed for %s: %s", target, e)
            return None

    def rollback(self) -> bool:
        """Restore workspace from snapshot."""
        if not self.backup_dir or not self.backup_dir.exists():
            logger.error("No snapshot available for rollback.")
            return False
        try:
            shutil.rmtree(self.workspace_path)
            shutil.copytree(self.backup_dir, self.workspace_path)
            for entry in self.ledger.entries:
                entry.status = "rolled_back"
            self.ledger.save()
            logger.info("Workspace rolled back from %s", self.backup_dir)
            return True
        except Exception as e:
            logger.error("Rollback failed: %s", e)
            return False

    def generate_fix_plan(
        self, findings: list, severity_threshold: str = "medium"
    ) -> str:
        """Generate a token-efficient, LLM-readable fix plan from findings."""
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        target_val = severity_map.get(severity_threshold.lower(), 2)

        plan_lines = []
        for f in findings:
            f_sev_val = severity_map.get(str(getattr(f, "severity", "")).lower(), 0)
            if f_sev_val < target_val:
                continue

            rem_code = getattr(f, "remediation_code", None)
            if not rem_code:
                continue

            file_p = getattr(f, "file_path", "unknown")
            line_s = getattr(f, "line_start", 0)
            title = getattr(f, "title", "Unknown Finding")
            severity = getattr(f, "severity", "unknown")

            plan_lines.append(
                f"--- {file_p} (Line {line_s})\n"
                f"+++ Fix: {title} ({severity})\n"
                f"{rem_code}\n"
            )

        if not plan_lines:
            return "No automated remediations available for findings at the specified severity threshold."

        return "Vexa Autonomous Agency — Fix Plan\n\n" + "\n".join(plan_lines)

    def finalize(self) -> None:
        """Save ledger to disk at end of session."""
        self.ledger.save()
