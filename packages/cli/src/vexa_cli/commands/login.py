"""Login command."""
import sys
import click
from vexa_cli.ui.output import print_banner, console

@click.command()
def login():
    """
    Login to AI providers and Vexa services.
    
    This command helps you authenticate with the AI providers used for enrichment.
    """
    print_banner()
    console.print("\n[bold sky_blue1]Authentication Guidance[/bold sky_blue1]")
    console.print("─" * 30)
    
    # Detect platform for correct env var hint
    if sys.platform == "win32":
        e_cmd = ""
        e_pfx = "$env:"
        e_sfx = '="value"'
    else:
        e_cmd = "export "
        e_pfx = ""
        e_sfx = '="value"'

    console.print("\n[bold bright_cyan]Google Gemini (SDK - API Key)[/bold bright_cyan]")
    console.print("  1. Get an API key from [bold white]https://aistudio.google.com/app/apikey[/bold white]")
    console.print(f"  2. Set Env: [bold white]{e_cmd}{e_pfx}GOOGLE_API_KEY{e_sfx}[/bold white]")
    console.print(f"  3. (Optional) Set Env: [bold white]{e_cmd}{e_pfx}GOOGLE_GEMINI_MODEL{e_sfx}[/bold white]")
    console.print('  4. Install SDK: [bold white]pip install "vexa[google]"[/bold white]')

    console.print("\n[bold bright_cyan]Anthropic (Claude 3.5 Sonnet)[/bold bright_cyan]")
    console.print("  1. Get an API key from [bold white]https://console.anthropic.com/[/bold white]")
    console.print(f"  2. Set Env: [bold white]{e_cmd}{e_pfx}VEXA_ANTHROPIC_API_KEY{e_sfx}[/bold white]")
    console.print(f"  3. (Optional) Set Env: [bold white]{e_cmd}{e_pfx}VEXA_ANTHROPIC_MODEL{e_sfx}[/bold white]")
    console.print('  4. Install SDK: [bold white]pip install "vexa[anthropicai]"[/bold white]')

    console.print("\n[bold bright_cyan]OpenAI (GPT-4o / GPT-4o-mini)[/bold bright_cyan]")
    console.print("  1. Get an API key from [bold white]https://platform.openai.com/api-keys[/bold white]")
    console.print(f"  2. Set Env: [bold white]{e_cmd}{e_pfx}VEXA_OPENAI_API_KEY{e_sfx}[/bold white]")
    console.print(f"  3. (Optional) Set Env: [bold white]{e_cmd}{e_pfx}VEXA_OPENAI_MODEL{e_sfx}[/bold white]")
    console.print('  4. Install SDK: [bold white]pip install "vexa[openai]"[/bold white]')
