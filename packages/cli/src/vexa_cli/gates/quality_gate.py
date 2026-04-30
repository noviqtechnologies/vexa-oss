"""Quality Gate logic extraction."""

from rich.console import Console

console = Console()


def evaluate_quality_gate(
    result,
    score_grade,
    new_only,
    baseline_file,
    path,
    fail_on,
    max_findings,
    min_score,
    QualityGateEvaluator,
    BaselineManager,
):
    """Evaluate quality gates and return (gate_failed, diff, gate_status)."""
    gate_failed = False
    diff = None
    gate_status = None

    findings_to_check = result.findings

    if new_only or baseline_file:
        if BaselineManager:
            bm = BaselineManager(baseline_file or (path / ".vexa-baseline.json"))
            diff = bm.diff(result)
            findings_to_check = diff.new_findings
            console.print("\n[dim]Baseline Comparison:[/dim]")
            console.print(f"  • [green]Fixed[/green]: {len(diff.fixed_findings)}")
            console.print(f"  • [yellow]New[/yellow]: {len(diff.new_findings)}")
        else:
            from vexa_cli.ui.output import print_warning

            print_warning(
                "Baseline logic unavailable (cicd package missing). Checking all findings."
            )

    if QualityGateEvaluator:
        from vexa.common.config_manager import QualityGateConfig

        evaluator = QualityGateEvaluator()
        config_kwargs = {
            "fail_on": [s.strip().lower() for s in fail_on.split(",")]
            if fail_on
            else [],
            "max_total": max_findings,
            "new_only": new_only,
        }
        if min_score:
            config_kwargs["min_score"] = min_score
        qg_config = QualityGateConfig(**config_kwargs)
        gate_status = evaluator.evaluate(
            scan_result=result,
            config=qg_config,
            new_findings_count=len(findings_to_check) if new_only else None,
            security_grade=score_grade if score_grade != "N/A" else None,
        )
        gate_failed = not gate_status.passed

        status_text = (
            "[bold spring_green3]PASSED[/bold spring_green3]"
            if gate_status.passed
            else "[bold red]FAILED[/bold red]"
        )
        console.print(f"\n[bold white]⚖️  Quality Gate:[/bold white] {status_text}")
        if not gate_status.passed:
            for reason in gate_status.reasons:
                console.print(f"  [red]✖ {reason}[/red]")
    else:
        # Fallback to simple gate
        if fail_on:
            thresholds = [s.strip().lower() for s in fail_on.split(",")]
            for sev in thresholds:
                if result.findings_by_severity.get(sev, 0) > 0:
                    gate_failed = True
                    break

    return gate_failed, diff, gate_status
