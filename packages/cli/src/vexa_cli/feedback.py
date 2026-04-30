
import click
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

from vexa.telemetry.client import TelemetryClient

# Define local helpers to avoid circular import with main.py
console = Console()

def print_success(message: str):
    """Print success message."""
    console.print(f"[green]✔ {message}[/green]")

def print_error(message: str):
    """Print error message."""
    console.print(f"[red]✖ {message}[/red]")

def print_info(message: str):
    """Print info message."""
    console.print(f"[cyan]➜ {message}[/cyan]")

@click.command()
def feedback():
    """
    Share feedback or report bugs to the Vexa team.
    
    We value your input! Usage data and feedback help us improve Vexa.
    """
    console.print(Panel(
        "[bold cyan]Vexa Feedback[/bold cyan]\n"
        "Help us improve by sharing your thoughts, feature requests, or bug reports.",
        border_style="cyan"
    ))
    
    # 1. Collect Feedback
    user_feedback = Prompt.ask("\n[bold]What would you like to tell us?[/bold]")
    
    if not user_feedback.strip():
        print_error("Feedback cannot be empty.")
        return

    # 2. Optional Email
    email = Prompt.ask("[bold]Email (optional, for follow-up)[/bold]", default="")
    
    # 3. Confirm and Send
    if Confirm.ask("\nSend this feedback to the Vexa team?", default=True, console=console):
        # Instantiate client only when needed
        client = TelemetryClient()
        
        with console.status("[bold green]Sending feedback...", spinner="dots"):
            # Mocking the call or actual call
            success = client.send_feedback(improvement=user_feedback, email=email if email else None)
            
        if success:
            print_success("Thank you! Your feedback has been received.")
        else:
            print_error("Failed to send feedback. Please try again later.")
    else:
        print_info("Feedback cancelled.")
