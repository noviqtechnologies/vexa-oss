"""Init command."""
import os
import sys
import subprocess
import yaml
import click
from rich.prompt import Confirm, Prompt
from vexa.common.config import is_terms_accepted, accept_terms
from vexa_cli.ui.output import print_banner, print_info, print_success, show_beta_terms, console
from vexa.common.models import CloudProvider

# Language → scanner mapping
SCANNER_MAP = {
    "Python": ["semgrep", "bandit", "checkov", "pip-audit", "pip-licenses", "detect-secrets"],
    "JavaScript/TypeScript": ["semgrep", "npm-audit", "detect-secrets"],
    "Go": ["semgrep", "detect-secrets"],
    "Rust": ["semgrep", "detect-secrets"],
    "Infrastructure/DevOps": ["checkov", "terrascan", "tfsec", "trivy"],
    "Container/Image": ["syft", "grype"],
}
DEFAULT_SCANNERS = ["semgrep", "detect-secrets", "syft", "grype"]

def detect_project_type():
    types = []
    # Core Languages
    if any(os.path.exists(f) for f in ["requirements.txt", "pyproject.toml", "setup.py", "uv.lock"]):
        types.append("Python")
    if any(os.path.exists(f) for f in ["package.json", "tsconfig.json", "node_modules"]):
        types.append("JavaScript/TypeScript")
    if os.path.exists("go.mod"):
        types.append("Go")
    if os.path.exists("Cargo.toml"):
        types.append("Rust")
    
    # Infrastructure & Containers
    if any(os.path.exists(f) for f in ["Dockerfile", "docker-compose.yml", "Containerfile"]):
        types.append("Container/Image")
    if any(os.path.exists(f) for f in [".tf", "main.tf", "terragrunt.hcl"]):
        types.append("Infrastructure/DevOps")
        
    return types

def get_scanners_for_project(project_types):
    """Resolve the correct scanner list for detected project types."""
    if not project_types:
        return list(DEFAULT_SCANNERS)
    scanners = set()
    for pt in project_types:
        scanners.update(SCANNER_MAP.get(pt, DEFAULT_SCANNERS))
    return sorted(scanners)

def install_scanners(scanners_to_install):
    # Only offer pip-installable scanners (exclude npm-audit which comes with Node, 
    # and binary-only ones which we might add later)
    pip_installable = [s for s in scanners_to_install if s not in ("npm-audit", "syft", "grype", "trivy")]
    
    if not pip_installable:
        return

    # Check for Python 3.14+ warning
    if sys.version_info >= (3, 14):
        console.print("[yellow]Warning: Python 3.14+ detected. Many security tools (like Semgrep) have dependency conflicts on this version.[/yellow]")
        console.print("[cyan]Recommendation: Use a stable version (Python 3.11/3.12) or install tools via 'pipx' for isolation.[/cyan]\n")

    if Confirm.ask(f"Would you like to auto-install recommended scanners ({', '.join(pip_installable)})?", default=True, console=console):
        with console.status("[bold green]Installing scanners...[/bold green]", spinner="dots"):
            # Try pipx first if available
            try:
                subprocess.check_call(["pipx", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                use_pipx = True
            except (subprocess.CalledProcessError, FileNotFoundError):
                use_pipx = False

            failed = []
            for scanner in pip_installable:
                try:
                    if use_pipx:
                        subprocess.check_call(["pipx", "install", scanner, "--force"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    else:
                        # Replicate semgrep version fix from install_scanners.ps1 if needed
                        if scanner == "semgrep":
                            subprocess.check_call([sys.executable, "-m", "pip", "install", "rich>=13.5.2,<13.6.0", "tomli>=2.0.1,<2.1.0", "--user", "--quiet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        
                        subprocess.check_call([sys.executable, "-m", "pip", "install", scanner, "--user", "--upgrade"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except subprocess.CalledProcessError:
                    failed.append(scanner)

            if failed:
                console.print(f"[yellow]Failed to install some scanners: {', '.join(failed)}[/yellow]")
                console.print("[dim]This is often due to Python version mismatches. Try installing them manually or using 'pipx'.[/dim]")
            else:
                print_success("Scanners installed successfully.")

def configure_ai():
    if Confirm.ask("Would you like to use AI-powered analysis for more accurate results?", default=True, console=console):
        # Restricted to supported providers for beta
        choices = ["google", "openai", "anthropic", "ollama"]
        provider = Prompt.ask("Select AI Provider", choices=choices, default="google", console=console)
        
        if provider == "ollama":
            from vexa.ai_providers.ollama_provider import get_ollama_wrapper
            console.print("\n[bold green]✔ Local AI (Ollama) selected.[/bold green]")
            console.print("[dim]Ensure Ollama is running (`ollama serve`) and the model is pulled (`ollama pull llama3:8b`).[/dim]\n")
            return {
                "enabled": True, 
                "provider": "ollama", 
                "model": "llama3:8b",
                "ollama_host": "localhost",
                "ollama_port": 11434,
                "fp_detection": True, 
                "remediation": True
            }

        env_vars = {
            "google": "GOOGLE_API_KEY",
            "openai": "VEXA_OPENAI_API_KEY",
            "anthropic": "VEXA_ANTHROPIC_API_KEY"
        }
        key_var = env_vars[provider]

        # Prompt for API Key
        api_key = Prompt.ask(f"Enter your {provider.capitalize()} API Key (leave empty to configure later)", password=True, console=console)

        if api_key:
            # Inform the user how to persist it
            console.print(f"\n[bold green]✔ API Key received![/bold green]")
            console.print(f"[dim]Note: This key is active for the current session. For permanent access, add it to your environment:[/dim]")
            
            masked_key = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "****"
            if sys.platform == "win32":
                console.print(f"  [cyan]PowerShell:[/cyan] [white]$env:{key_var}=\"{masked_key}\"[/white]")
            else:
                console.print(f"  [cyan]Bash/Zsh:[/cyan]   [white]export {key_var}=\"{masked_key}\"[/white]")
            
            # Set in current process environment for immediate subsequent scans
            os.environ[key_var] = api_key
            console.print()
        else:
            # Environment variable hints
            console.print(f"\n[bold white]To complete AI setup later, ensure {key_var} is set in your environment:[/bold white]")
            if sys.platform == "win32":
                console.print(f"  [cyan]PowerShell:[/cyan] [white]$env:{key_var}=\"YOUR_KEY\"[/white]")
                console.print(f"  [cyan]CMD:[/cyan]        [white]set {key_var}=YOUR_KEY[/white]")
            else:
                console.print(f"  [cyan]Bash/Zsh:[/cyan]   [white]export {key_var}=\"YOUR_KEY\"[/white]")
            
            console.print(f"[dim]Obtain your key at the {provider.capitalize()} developer portal.[/dim]\n")
        
        # Verify SDK Installation status (Industry Best Practice: Opt-in Extras)
        missing_sdk = False
        try:
            if provider == "google":
                import google.genai # noqa
            elif provider == "openai":
                import openai # noqa
            elif provider == "anthropic":
                import anthropic # noqa
        except ImportError:
            missing_sdk = True
            
        if missing_sdk:
            # Detect package manager
            installer = "pip install"
            if os.path.exists("uv.lock"):
                installer = "uv add"
            elif os.path.exists("poetry.lock"):
                installer = "poetry add"
            elif os.path.exists("Pipfile.lock") or os.path.exists("Pipfile"):
                installer = "pipenv install"

            if provider == "google":
                install_cmd = f"{installer} google-genai"
            elif provider == "openai":
                install_cmd = f"{installer} openai"
            elif provider == "anthropic":
                install_cmd = f"{installer} anthropic"
            else:
                install_cmd = f"{installer} google-genai"

            console.print(f"\n[bold yellow]⚠ Warning: The {provider.capitalize()} AI SDK is not currently installed.[/bold yellow]")
            console.print("[white]Vexa uses optional AI dependencies to keep your standard CI/CD drops blazing fast without bloat.[/white]")
            console.print("Please run the following command to install the required Python SDK before running 'vexa fix':")
            console.print(f"  [cyan]{install_cmd}[/cyan]\n")

        return {"enabled": True, "provider": provider, "fp_detection": True, "remediation": True}
    return {"enabled": False, "provider": "none", "fp_detection": False, "remediation": False}

def generate_config(ai_config, scanner_list):
    config_path = ".vexa.yml"
    if os.path.exists(config_path):
        if not Confirm.ask(f"[yellow]{config_path} already exists. Overwrite?[/yellow]", default=False, console=console):
            return

    config_data = {
        "scanners": {
            "enabled": scanner_list
        },
        "quality_gate": {
            "fail_on": ["critical", "high"],
            "max_total": 50,
            "new_only": False
        },
        "ai": ai_config,
        "reports": {
            "formats": ["sarif", "html", "json", "markdown"]
        }
    }
    
    with open(config_path, "w") as f:
        yaml.dump(config_data, f, sort_keys=False)
    print_success(f"Generated configuration at {config_path}")

def _install_guardrails():
    from pathlib import Path
    
    git_hooks_dir = Path(".git/hooks")
    if not git_hooks_dir.exists():
        print_warning("No .git/hooks directory found. Ensure you are in the root of a Git repository.")
        return
        
    hook_path = git_hooks_dir / "pre-commit"
    hook_script = """#!/bin/bash
# Vexa Pre-Commit Guardrails
# Automatically generated by `vexa init --guardrails`

echo "🛡️  Running Vexa guardrails..."

# Check if there are staged files to scan
staged_files=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$staged_files" ]; then
  exit 0
fi

vexa scan . --fast --pre-commit --incremental
if [ $? -ne 0 ]; then
  echo ""
  echo "❌ Commit blocked by Vexa. Fix the issues and try again."
  exit 1
fi
"""
    try:
        if hook_path.exists():
            if Confirm.ask(f"[yellow]{hook_path} already exists. Overwrite with Vexa guardrails?[/yellow]", default=False, console=console):
                hook_path.write_text(hook_script.replace('\r\n', '\n'))
                os.chmod(hook_path, 0o755)
                print_success("Pre-commit guardrails updated.")
        else:
            hook_path.write_text(hook_script.replace('\r\n', '\n'))
            os.chmod(hook_path, 0o755)
            print_success("Pre-commit guardrails installed.")
    except Exception as e:
        import traceback
        print_error(f"Failed to install guardrails: {e}")

@click.command()
@click.option("--guardrails", is_flag=True, help="Install pre-commit guardrails hook.")
@click.pass_context
def init(ctx, guardrails: bool):
    """Initialize Vexa and setup your project."""
    print_banner()
    
    non_interactive = ctx.obj.get('non_interactive', False)
    
    if not is_terms_accepted():
        if not show_beta_terms() and not non_interactive:
            sys.exit(1)
            
    print_info("Welcome to the Vexa setup wizard!")
    
    project_types = detect_project_type()
    if project_types:
        print_info(f"Detected project type(s): {', '.join(project_types)}")
    else:
        print_info("Could not auto-detect project type. Proceeding with defaults.")
    
    scanner_list = get_scanners_for_project(project_types)
    print_info(f"Recommended scanners: {', '.join(scanner_list)}")
    
    install_scanners(scanner_list)
    ai_config = configure_ai()
    generate_config(ai_config, scanner_list)
    
    if guardrails:
        _install_guardrails()
    
    print_success("Vexa initialization complete! You can now run `vexa fix .`")
