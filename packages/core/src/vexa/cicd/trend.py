"""
Vulnerability Trend Analysis for CI/CD Pipelines.

CI-FR-051: Track finding counts over time to detect security trends.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from vexa.common.logging import get_logger
from vexa.common.models import ScanResult

logger = get_logger(__name__)


@dataclass
class TrendPoint:
    """A single data point in a security trend."""
    timestamp: str
    job_id: str
    total: int
    critical: int
    high: int
    medium: int
    low: int
    score: float


@dataclass
class TrendReport:
    """Analysis of security trends over time."""
    history: List[TrendPoint] = field(default_factory=list)
    delta_total: int = 0
    delta_score: float = 0.0
    is_improving: bool = True

    @property
    def summary(self) -> str:
        """Return a human-readable summary of the trend."""
        trend_dir = "↑" if self.delta_total > 0 else "↓"
        status = "improving" if self.is_improving else "regressing"
        return f"📈 Trend: {trend_dir} {abs(self.delta_total)} total findings ({status})"


class TrendAnalyzer:
    """
    Analyzes security trends by tracking scan metrics over time.
    
    KF-051: Provides data for trend charts and identifies improvements/regressions.
    """

    def __init__(self, history_file: Optional[Path] = None):
        self.history_file = history_file

    def record_run(self, result: ScanResult, score: float, path: Optional[Path] = None) -> TrendReport:
        """
        Record the current run and analyze the trend.
        
        Args:
            result: Current ScanResult
            score: Current security score
            path: Path to history file (override)
            
        Returns:
            TrendReport with historical analysis
        """
        history_path = path or self.history_file or Path(".vexa-history.json")
        
        # Load history
        history = self._load_history(history_path)
        
        # Create new point
        counts = result.findings_by_severity
        new_point = TrendPoint(
            timestamp=datetime.now().isoformat(),
            job_id=result.job_id,
            total=result.total_findings,
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
            score=score
        )
        
        # Calculate deltas
        delta_total = 0
        delta_score = 0.0
        is_improving = True
        
        if history:
            prev = history[-1]
            delta_total = new_point.total - prev.total
            delta_score = new_point.score - prev.score
            # Lower findings = improvement, Higher score = improvement
            is_improving = delta_total <= 0
            
        # Add to history and prune (keep last 50 runs)
        history.append(new_point)
        if len(history) > 50:
            history = history[-50:]
            
        # Save history
        self._save_history(history, history_path)
        
        return TrendReport(
            history=history,
            delta_total=delta_total,
            delta_score=delta_score,
            is_improving=is_improving
        )

    def _load_history(self, path: Path) -> List[TrendPoint]:
        """Load history from JSON."""
        if not path.exists():
            return []
            
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [TrendPoint(**p) for p in data]
        except Exception as e:
            logger.warning("Failed to load history from %s: %s", path, e)
            return []

    def _save_history(self, history: List[TrendPoint], path: Path):
        """Save history to JSON."""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump([p.__dict__ for p in history], f, indent=2)
        except Exception as e:
            logger.error("Failed to save history to %s: %s", path, e)
