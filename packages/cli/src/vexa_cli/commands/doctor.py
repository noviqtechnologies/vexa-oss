"""Doctor command."""
import sys
import platform
import click
from pathlib import Path

from vexa_cli.ui.output import print_banner, console

@click.command()
@click.option('--privacy', is_flag=True, help="Verify local AI privacy audit log.")
def doctor(privacy: bool):
    """Diagnostic command to check installation and environment."""
    print_banner()
    
    if privacy:
        return _run_privacy_doctor()
        
    # 1. System info
    console.print("[bold white]🖥️  System Information[/bold white]")
    console.print(f"  • OS: {platform.system()} {platform.release()}")
    console.print(f"  • Python: {platform.python_version()}")
    console.print("─" * 50)
    
    # 2. Scanner Availability
    console.print("[bold white]🔍 Scanner Availability[/bold white]")
    from vexa.scanners.engine import get_scanner_engine
    engine = get_scanner_engine()
    
    # Engine instantiates all scanners in LOCAL mode by default
    for name, scanner_cls in engine.SCANNERS.items():
        try:
            # Check availability
            scanner = scanner_cls()
            if scanner.is_available():
                console.print(f"  [bold green]✔[/bold green] [white]{name:<16}[/white] [dim]Installed[/dim]")
            else:
                if sys.platform == "win32" and name == "semgrep":
                    console.print(f"  [bold red]✖[/bold red] [white]{name:<16}[/white] [dim]Not available on native Windows (Use WSL/Docker)[/dim]")
                else:
                    console.print(f"  [bold yellow]✖[/bold yellow] [white]{name:<16}[/white] [dim]Missing[/dim]")
        except Exception as e:
            console.print(f"  [bold red]✖[/bold red] [white]{name:<16}[/white] [dim]Error: {e}[/dim]")
            
    console.print("─" * 50)

    # 3. AI Providers
    console.print("[bold white]🤖 AI Providers[/bold white]")
    try:
        from vexa.common.config_manager import load_config
        # Standardize provider discovery
        from vexa.common.models import CloudProvider
        import os
        config = load_config(Path("."))
        prov_name = config.ai.provider
        
        # Override via env for current session
        if "VEXA_AI_PROVIDER" in os.environ:
            try:
                prov_name = CloudProvider(os.environ["VEXA_AI_PROVIDER"].lower())
            except ValueError:
                pass
            
        if prov_name and prov_name != CloudProvider.NONE:
            from vexa.common.cloud_provider import PROVIDER_CAPABILITIES
            caps = PROVIDER_CAPABILITIES.get(prov_name)
            console.print(f"  [bold green]✔[/bold green] [white]Provider:[/white]        [dim]{prov_name.value}[/dim]")
            if caps:
                console.print(f"  [bold green]✔[/bold green] [white]Capabilities:[/white]    [dim]Code Review: {'yes' if caps.code_review_enabled else 'no'} | FP Detection: {'yes' if caps.false_positive_detection else 'no'}[/dim]")
        else:
            console.print("  [bold yellow]⬚[/bold yellow] [white]No AI configured[/white] [dim](run 'vexa login')[/dim]")
    except Exception as e:
        console.print(f"  [bold red]✖[/bold red] [white]Error loading AI:[/white] [dim]{e}[/dim]")

    console.print("─" * 50)
    console.print("[bold green]Diagnostic complete.[/bold green]\\n")

def _run_privacy_doctor():
    """Verify the Privacy Vault zero-egress audit log."""
    console.print("[bold white]🔒 Privacy Vault — Audit Log Verification[/bold white]")
    console.print("Checking cryptographic signatures of local AI interactions...")
    
    from vexa.common.config import VEXA_HOME
    import json
    import hmac
    import hashlib
    from datetime import datetime, timezone, timedelta
    
    audit_file = VEXA_HOME / "audit" / "audit.log"
    key_file = VEXA_HOME / "audit.key"
    
    if not audit_file.exists():
        console.print("\\n  [bold yellow]⬚[/bold yellow] [white]No audit log found.[/white] [dim](Ollama provider has not been used yet)[/dim]")
        return
        
    if not key_file.exists():
        console.print("\\n  [bold red]✖[/bold red] [white]Audit key missing![/white] [dim]Cannot verify log integrity.[/dim]")
        return
        
    key = key_file.read_bytes()
    
    total_findings = 0
    external_calls = 0
    invalid_records = 0
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    
    try:
        with open(audit_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    payload = entry.get("payload", {})
                    signature = entry.get("signature", "")
                    
                    # Verify HMAC
                    expected_payload_str = json.dumps(payload, sort_keys=True)
                    expected_signature = hmac.new(key, expected_payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
                    
                    if not hmac.compare_digest(signature, expected_signature):
                        invalid_records += 1
                        continue
                        
                    # Filter for last 30 days
                    ts_str = payload.get("timestamp")
                    if ts_str:
                        # Ensure timezone awareness for python < 3.11 when possible or fallback
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts >= thirty_days_ago:
                            total_findings += payload.get("findings_count", 0)
                            external_calls += payload.get("external_calls", 0)
                except Exception:
                    invalid_records += 1
                    
        console.print("─" * 50)
        if invalid_records > 0:
            console.print(f"  [bold red]✖[/bold red] [red]Verification Failed: {invalid_records} log entries have been tampered with or corrupted![/red]")
        else:
            console.print(f"  [bold green]✔[/bold green] [white]Last 30 days: {total_findings} findings analysed, {external_calls} external API calls, audit log verified[/white]")
        console.print("─" * 50)
        
    except Exception as e:
        console.print(f"\\n  [bold red]✖[/bold red] [white]Failed to read audit log:[/white] {e}")
