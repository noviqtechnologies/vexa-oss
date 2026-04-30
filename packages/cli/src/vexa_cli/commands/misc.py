"""Miscellaneous commands for the CLI."""

import sys
import click
from pathlib import Path

from vexa_cli.ui.output import print_banner, print_info, print_warning, print_error


@click.command(name="mcp-server", hidden=True)
def mcp_server_command():
    """Internal command to start the MCP server."""
    # Import here to avoid circular dependencies
    from vexa_mcp.scanner.server import main as server_main

    server_main()


@click.command("threat-model", hidden=True)
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--provider",
    "-p",
    type=click.Choice(["google", "aws", "azure"]),
    default="google",
    help="AI provider for analysis",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory",
)
def threat_model(path: Path, provider: str, output: Path):
    """
    Generate STRIDE threat model.
    """
    print_info("Threat model generation using ThreatModel module")
    print_warning("Threat model CLI integration pending TM-001 implementation")


@click.command(hidden=True)
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--type",
    "-t",
    type=click.Choice(["terraform", "cdk", "cloudformation"]),
    default="terraform",
    help="IaC type",
)
def validate(path: Path, type: str):
    """
    Detect infrastructure drift.
    """
    print_info("Drift detection using SecurityValidate module")
    print_warning("Validate CLI integration pending SV-001 implementation")


@click.command(hidden=True)
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def matrix(path: Path):
    """
    Generate DSR Security Matrix via core framework.
    """
    print_info("Security Matrix generation using NeoLifter module")
    print_warning("Matrix CLI integration pending SM-001 implementation")


@click.command()
def list_scanners():
    """List available security scanners from Core."""
    print_banner()

    try:
        from vexa.common.models import ScanMode
        from vexa.scanners.engine import get_scanner_engine

        engine = get_scanner_engine()
        local_scanners = engine.get_available_scanners(ScanMode.LOCAL)
        all_scanners = engine.get_available_scanners(ScanMode.CONTAINER)
    except Exception as e:
        print_error(f"Failed to list scanners: {e}")
        return

    click.echo(click.style("\\n📋 Available Scanners:\\n", bold=True))

    click.echo(click.style("Local + Container Mode:", fg="cyan", bold=True))
    for name in local_scanners:
        click.echo(f"  • {name}")

    click.echo(click.style("\\nContainer Mode Only:", fg="yellow", bold=True))
    container_only = set(all_scanners) - set(local_scanners)
    for name in container_only:
        click.echo(f"  • {name}")

    # Platform specific notes
    if sys.platform == "win32":
        click.echo()
        print_warning("Note for Windows users:")
        click.echo("  • 'semgrep' is not supported natively on Windows.")
        click.echo("  • Use WSL or Docker mode for full coverage.")
