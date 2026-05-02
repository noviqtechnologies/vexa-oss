"""
Headless CI/CD Runner for Vexa.

Orchestrates the full CI/CD pipeline:
config → scan → baseline diff → score → quality gate → report → PR comment.

Designed for non-interactive, headless execution in CI runners.
"""

import asyncio
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vexa.common.config_manager import VexaConfig, load_config
from vexa.common.logging import get_logger
from vexa.common.models import ScanMode, ScanResult, JobStatus
from vexa.common.cloud_provider import CloudProvider
from vexa.reports.generator import get_report_generator, ReportMetadata

from .baseline import BaselineManager, BaselineDiff
from .quality_gate import QualityGateEvaluator, QualityGateResult
from .security_score import SecurityScorer, SecurityScore
from .pr_decorator import PRDecorator
from .trend import TrendAnalyzer, TrendReport
from .compliance import ComplianceAnalyzer, ComplianceReport

logger = get_logger(__name__)


@dataclass
class CICDResult:
    """Consolidated result of a CI/CD pipeline run."""
    job_id: str
    scan_result: ScanResult
    gate_result: QualityGateResult
    score: SecurityScore
    diff: Optional[BaselineDiff] = None
    trend: Optional[TrendReport] = None
    compliance: Optional[ComplianceReport] = None


class CICDRunner:
    """
    Main orchestrator for Vexa CI/CD pipeline.
    
    This runner wraps the core scanning engine and adds CI-specific logic
    like quality gates, baselining, and PR comments.
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.config = load_config(config_path or Path.cwd())
        self.baseline_manager = BaselineManager(
            baseline_path=Path(self.config.quality_gate.baseline) if self.config.quality_gate.baseline else None
        )
        self.evaluator = QualityGateEvaluator()
        self.scorer = SecurityScorer()
        self.analyzer = ComplianceAnalyzer()
        self.trend_analyzer = TrendAnalyzer()

    async def run(
        self,
        target_path: Path,
        scanners: Optional[List[str]] = None,
        ai_provider: str = "none",
        mode: ScanMode = ScanMode.BALANCED,
    ) -> CICDResult:
        """
        Execute the full CI/CD pipeline.
        """
        job_id = str(uuid.uuid4())
        logger.info("Starting Vexa CI/CD job %s", job_id)

        # 1. Initialize Engine
        from vexa.scanners.engine import get_scanner_engine
        engine = get_scanner_engine()
        
        # 2. Execute Scan
        scan_result = await engine.run_scan_with_progress(
            path=target_path,
            job_id=job_id,
            scanners=scanners,
            mode=ScanMode.LOCAL, # CI runners always run in local mode within the container
            cloud_provider=CloudProvider(ai_provider) if ai_provider != "none" else CloudProvider.NONE
        )

        # 3. Calculate Security Score
        score = self.scorer.calculate(scan_result)

        # 4. Perform Baseline Diff
        diff = None
        if self.baseline_manager.baseline_path:
            diff = self.baseline_manager.diff(scan_result)

        # 5. Trend Analysis
        trend = self.trend_analyzer.record_run(scan_result, score.numeric_score)

        # 6. Compliance Analysis
        compliance = self.analyzer.analyze(scan_result)

        # 7. Evaluate Quality Gate
        new_findings_count = diff.new_count if diff else None
        gate_result = self.evaluator.evaluate(
            scan_result,
            self.config.quality_gate,
            new_findings_count=new_findings_count,
            security_grade=score.grade
        )

        # 8. Generate Reports
        self._generate_reports(scan_result, gate_result, score, diff, trend, compliance)

        return CICDResult(
            job_id=job_id,
            scan_result=scan_result,
            gate_result=gate_result,
            score=score,
            diff=diff,
            trend=trend,
            compliance=compliance
        )

    def _generate_reports(
        self,
        scan_result: ScanResult,
        gate_result: QualityGateResult,
        score: SecurityScore,
        diff: Optional[BaselineDiff] = None,
        trend: Optional[TrendReport] = None,
        compliance: Optional[ComplianceReport] = None
    ):
        """Generate all configured report formats."""
        for fmt in self.config.reports.formats:
            try:
                # get_report_generator() returns the orchestrator in the new core
                generator = get_report_generator()
                metadata = ReportMetadata(
                    job_id=scan_result.job_id
                )
                
                output_path = Path(self.config.reports.output_dir) / f"report_{scan_result.job_id}.{fmt}"
                generator.generate(scan_result, fmt, output_path, metadata)
                logger.info("Generated %s report: %s", fmt.upper(), output_path)
            except Exception as e:
                logger.error("Failed to generate %s report: %s", fmt, e)

    @classmethod
    def run_sync(cls):
        """Entry point for CLI execution."""
        import argparse
        parser = argparse.ArgumentParser(description="Vexa CI/CD Runner")
        parser.add_argument("path", type=str, help="Path to scan")
        parser.add_argument("--scanners", type=str, help="Comma-separated scanners")
        parser.add_argument("--ai-provider", type=str, default="none", help="AI provider")
        parser.add_argument("--config", type=str, help="Path to .vexa.yml")
        parser.add_argument("--shadow", action="store_true", help="Run in shadow mode (decorate PR but exit 0)")

        args = parser.parse_args()
        
        runner = cls(config_path=Path(args.config) if args.config else None)
        scanners = args.scanners.split(",") if args.scanners else None
        
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(runner.run(
            target_path=Path(args.path),
            scanners=scanners,
            ai_provider=args.ai_provider
        ))

        # Handle Shadow Mode / PR Decoration
        if args.shadow or "GITHUB_ACTIONS" in os.environ or "GITLAB_CI" in os.environ:
            from .shadow_decorator import ShadowDecorator
            decorator = ShadowDecorator()
            md = PRDecorator().generate_summary_comment(
                result.scan_result, result.gate_result, result.score, result.diff, result.trend, result.compliance
            )
            decorator.post_or_update_summary(md)

        if not result.gate_result.passed and not args.shadow:
            print(result.gate_result.summary)
            for reason in result.gate_result.reasons:
                print(f"  - {reason}")
            sys.exit(1)
        
        sys.exit(0)
