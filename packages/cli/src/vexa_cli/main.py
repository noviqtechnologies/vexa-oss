"""
Vexa CLI - Cross-Platform Security Scanner.

Cross-platform CLI for Windows, Mac, and Linux.
PRD Section 5.1: IDE Integration - "Direct Python"
"""

import os
import sys
import traceback

import click
from rich.prompt import Confirm

from vexa import __version__
from vexa.common.logging import get_logger
from vexa.common.config import is_terms_accepted, accept_terms
from vexa.telemetry.client import TelemetryClient

from vexa_cli.feedback import feedback
from vexa_cli.ui.output import show_beta_terms, console

logger = get_logger(__name__)


@click.group()
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Run without interactive prompts (auto-accepts defaults)",
)
@click.version_option(version=__version__, prog_name="vexa")
@click.pass_context
def cli(ctx, non_interactive):
    """
    Vexa - Enterprise Security Analysis CLI (Beta).

    Cross-platform security scanner for Windows, Mac, and Linux.
    This product is currently in Beta and undergoing active development.
    """
    ctx.ensure_object(dict)
    ctx.obj["non_interactive"] = non_interactive

    if not is_terms_accepted():
        if os.environ.get("CI", "").lower() == "true" or non_interactive:
            accept_terms()
        elif ctx.invoked_subcommand and ctx.invoked_subcommand != "init":
            if not show_beta_terms():
                ctx.exit(0)


# Import subcommands
from vexa_cli.commands.init import init
from vexa_cli.commands.login import login
from vexa_cli.commands.scan import scan
from vexa_cli.commands.fix import fix
from vexa_cli.commands.report import report
from vexa_cli.commands.doctor import doctor
from vexa_cli.commands.misc import (
    mcp_server_command,
    threat_model,
    validate,
    matrix,
    list_scanners,
)

cli.add_command(init)
cli.add_command(login)
cli.add_command(scan)
cli.add_command(fix)
cli.add_command(report)
cli.add_command(doctor)
cli.add_command(mcp_server_command)
cli.add_command(threat_model)
cli.add_command(validate)
cli.add_command(matrix)
cli.add_command(list_scanners)


def main_entry():
    """Main entry point."""
    # Register feedback command
    cli.add_command(feedback)

    try:
        cli()
    except Exception as e:
        if isinstance(e, click.ClickException) or isinstance(e, SystemExit):
            raise

        console.print(f"\\n[bold red]An unexpected error occurred: {e}[/bold red]")

        is_ci = os.environ.get("CI", "").lower() == "true"
        is_non_interactive = "--non-interactive" in sys.argv
        if not is_ci and not is_non_interactive:
            if Confirm.ask(
                "Would you like to send an automated error report to help us fix this?",
                default=True,
                console=console,
            ):
                client = TelemetryClient()
                with console.status(
                    "[bold green]Sending error report...", spinner="dots"
                ):
                    tb = traceback.format_exc()
                    success = client.send_error_report(str(e), tb)

                if success:
                    console.print("[green]Error report sent. Thank you![/green]")
                else:
                    console.print(
                        "[yellow]Failed to send error report, but thank you for trying![/yellow]"
                    )

        sys.exit(1)


if __name__ == "__main__":
    main_entry()
