"""UI helper functions for Vexa CLI."""

import os
import click
from rich.console import Console
from rich.prompt import Confirm

from vexa import __version__
from vexa.common.config import accept_terms

console = Console()


def print_banner(version: str = __version__, is_beta: bool = False):
    """Print the official Vexa premium banner with perfect alignment."""
    title = "Vexa — Security Autopilot"
    version_str = f"v{version}"
    beta_tag = " BETA" if is_beta else ""

    # Professional full-width box (62 chars interior)
    # Alignment: Title (left) + Spacing + Version/Beta (right)
    # [white] title (31 chars) + padding + [dim] version (X chars)
    # Total interior length = 60 chars (plus 2 spaces padding from borders)
    full_str = f"{title} {version_str}{beta_tag}"
    padding_size = 58 - len(full_str)
    padding = " " * padding_size

    banner = (
        f"[bold deep_sky_blue1]╔══════════════════════════════════════════════════════════════╗[/bold deep_sky_blue1]\n"
        f"[bold deep_sky_blue1]║[/bold deep_sky_blue1]  [bold white]{title}[/bold white]{padding}[dim]{version_str}[/dim][bold gold1]{beta_tag}[/bold gold1]  [bold deep_sky_blue1]║[/bold deep_sky_blue1]\n"
        f"[bold deep_sky_blue1]╚══════════════════════════════════════════════════════════════╝[/bold deep_sky_blue1]"
    )
    console.print(banner)


def print_success(message: str):
    """Print success message."""
    console.print(
        f"[bold spring_green3]✔[/bold spring_green3] [white]{message}[/white]"
    )


def print_error(message: str):
    """Print error message."""
    console.print(f"[bold red]✖[/bold red] [orange_red1]{message}[/orange_red1]")


def print_info(message: str):
    """Print info message."""
    console.print(f"[bold sky_blue1]➜[/bold sky_blue1] [grey85]{message}[/grey85]")


def print_warning(message: str):
    """Print warning message."""
    console.print(f"[bold gold1]⚠ {message}[/bold gold1]")


def show_welcome_message():
    """Show welcome message and check terms acceptance."""
    ctx = click.get_current_context(silent=True)
    is_non_interactive = (
        ctx.obj.get("non_interactive", False) if ctx and ctx.obj else False
    )

    # Auto-accept in CI environments or if non-interactive flag is passed
    if os.environ.get("CI", "").lower() == "true" or is_non_interactive:
        accept_terms()
        return True

    console.print("\n[bold white]Welcome to Vexa CLI![/bold white]")
    console.print("─" * 50)
    console.print(
        "[bold green][✓] Privacy First: This tool collects ZERO telemetry or usage data.[/bold green]"
    )
    console.print(
        "\nFor documentation and support, visit: [blue underline]https://vexasec.io[/blue underline]"
    )
    console.print()

    if not os.path.exists(os.path.join(os.path.expanduser("~"), ".vexa", ".terms_accepted")):
        if Confirm.ask("Do you agree to the Terms of Service?", default=True, console=console):
            accept_terms()
            print_success("Terms accepted. Welcome aboard!")
            return True
        else:
            print_error("You must accept the terms to use Vexa CLI.")
            return False
    return True
