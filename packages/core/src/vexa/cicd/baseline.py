"""
Baseline Comparison Engine for CI/CD Pipelines.

CI-FR-024: Compare against .vexa-baseline.json to detect regressions.
CI-FR-047: Diff report showing only new findings vs baseline.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Optional, Union

from vexa.common.logging import get_logger
from vexa.common.models import ScanResult, Finding

logger = get_logger(__name__)


@dataclass
class BaselineDiff:
    """Result of baseline comparison."""
    new_findings: List[Finding] = field(default_factory=list)
    fixed_findings: List[Dict] = field(default_factory=list)
    unchanged_findings: List[Finding] = field(default_factory=list)

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def fixed_count(self) -> int:
        return len(self.fixed_findings)

    @property
    def unchanged_count(self) -> int:
        return len(self.unchanged_findings)

    @property
    def summary(self) -> str:
        return (
            f"Baseline Diff: {self.new_count} new, "
            f"{self.fixed_count} fixed, {self.unchanged_count} unchanged"
        )


class BaselineManager:
    """
    Manages baseline files for incremental quality gate checks.

    A baseline file (.vexa-baseline.json) captures the fingerprints
    of all known findings at a point in time, allowing subsequent scans
    to distinguish new regressions from pre-existing issues.
    """

    def __init__(self, baseline_path: Optional[Path] = None):
        """
        Initialize the baseline manager.

        Args:
            baseline_path: Optional default path to .vexa-baseline.json
        """
        self.baseline_path = Path(baseline_path) if baseline_path else None

    @staticmethod
    def _fingerprint(finding_data: dict) -> str:
        """
        Generate a stable fingerprint for a finding.

        Uses scanner + file + line + title as the identity key.
        This allows findings to be matched even if IDs differ between runs.
        """
        scanner = finding_data.get("scanner", "")
        file_path = finding_data.get("file_path", "")
        line = finding_data.get("line_start", 0)
        title = finding_data.get("title", "")
        return f"{scanner}:{file_path}:{line}:{title}"

    def load_baseline(self, path: Path) -> List[Dict]:
        """
        Load baseline findings from a JSON file.

        Args:
            path: Path to .vexa-baseline.json

        Returns:
            List of finding dictionaries from the baseline
        """
        if not path.exists():
            logger.info("No baseline file found at %s, treating as empty baseline", path)
            return []

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Support both flat list and wrapped format
            if isinstance(data, list):
                findings = data
            elif isinstance(data, dict) and "findings" in data:
                findings = data["findings"]
            else:
                logger.warning("Unexpected baseline format, treating as empty")
                return []

            logger.info("Loaded %d findings from baseline %s", len(findings), path)
            return findings

        except (json.JSONDecodeError, IOError) as e:
            logger.error("Failed to load baseline from %s: %s", path, e)
            return []

    def save_baseline(self, scan_result: ScanResult, path: Path, score_grade: Optional[str] = None) -> Path:
        """
        Save current scan findings as a new baseline.

        Args:
            scan_result: The completed scan result
            path: Output path for the baseline file
            score_grade: Optional security score (e.g., 'A', 'B-')

        Returns:
            Path to the saved baseline file
        """
        findings_data = [f.model_dump() for f in scan_result.findings]

        baseline = {
            "version": "1.0",
            "job_id": scan_result.job_id,
            "total_findings": len(findings_data),
            "score": score_grade,
            "findings": findings_data,
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, default=str)

        logger.info("Saved baseline with %d findings to %s", len(findings_data), path)
        return path

    def diff(self, scan_result: Union[ScanResult, List[Finding]], baseline_path: Optional[Path] = None) -> BaselineDiff:
        """
        Compare current scan results against the baseline.

        Args:
            scan_result: Current scan result object or list of findings
            baseline_path: Path to baseline file (optional if provided in __init__)

        Returns:
            BaselineDiff with new, fixed, and unchanged findings
        """
        path = baseline_path or self.baseline_path
        if not path:
            logger.error("No baseline path provided to diff() and none set in __init__")
            return BaselineDiff()

        baseline_findings = self.load_baseline(path)

        # Build fingerprint sets
        baseline_fps: Set[str] = {
            self._fingerprint(f) for f in baseline_findings
        }
        
        current_fps: Dict[str, Finding] = {}
        findings = scan_result.findings if hasattr(scan_result, "findings") else scan_result
        
        for finding in findings:
            # Handle both Finding object and dict
            finding_data = finding.model_dump() if hasattr(finding, "model_dump") else finding
            fp = self._fingerprint(finding_data)
            current_fps[fp] = finding

        current_fp_set = set(current_fps.keys())

        # New = in current but not in baseline
        new_fps = current_fp_set - baseline_fps
        new_findings = [current_fps[fp] for fp in new_fps]

        # Fixed = in baseline but not in current
        fixed_fps = baseline_fps - current_fp_set
        fixed_findings = [
            f for f in baseline_findings
            if self._fingerprint(f) in fixed_fps
        ]

        # Unchanged = in both
        unchanged_fps = current_fp_set & baseline_fps
        unchanged_findings = [current_fps[fp] for fp in unchanged_fps]

        diff = BaselineDiff(
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            unchanged_findings=unchanged_findings,
        )

        logger.info(diff.summary)
        return diff
