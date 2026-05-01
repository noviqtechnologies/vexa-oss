# Model Context Protocol (MCP) Integration 🧩

Vexa exposes a high-performance MCP server that allows AI coding assistants (like Claude Desktop, Cursor, or Antigravity) to perform security scans and apply fixes directly in your IDE.

## 🧠 AI Delegation Architecture

When using Vexa via MCP, there are **two distinct AIs** working together:
1. **The Orchestrator (e.g., Claude):** Understands your chat intent and decides which Vexa tools to run.
2. **The Remediation Engine (Vexa):** Automatically uses the AI provider configured in your `.vexa.yml` file (e.g., local Ollama) to securely analyze vulnerabilities and generate patches.

This ensures you get highly deterministic, enterprise-grade security results regardless of which IDE you are chatting from!

## Configuration

### Global Installation (Pip/Homebrew)
If Vexa is installed globally on your system, configure your client (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vexa": {
      "command": "vexa",
      "args": ["mcp-server"]
    }
  }
}
```

### Running from Source (`uv` Users)
**CRITICAL:** If you run Vexa from source via `uv`, you must use the `--quiet` flag. MCP uses standard output (`stdio`) for JSON-RPC communication. If `uv` prints package resolution logs to the terminal, the connection will crash.

```json
{
  "mcpServers": {
    "vexa": {
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/vexa-oss",
        "run", "--quiet", "vexa", "mcp-server"
      ]
    }
  }
}
```

### Passing Environment Variables (Cloud AI)
Because MCP clients launch servers in a background process, they often **do not inherit your terminal's environment variables**. If your `.vexa.yml` uses Google or Anthropic instead of local Ollama, you must explicitly provide the API keys:

```json
{
  "mcpServers": {
    "vexa": {
      "command": "vexa",
      "args": ["mcp-server"],
      "env": {
        "GOOGLE_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

## Available Tools

Once connected, your AI assistant will have access to:
1. `run_scan_local`: Performs a full security scan of the current workspace.
2. `get_scan_status`: Tracks asynchronous scan progress without blocking the UI.
3. `auto_remediate_workspace`: Autonomous agent tool that scans, analyzes with AI, and applies security patches safely.
4. `get_configuration`: Fetches the `.vexa.yml` to understand the current security posture.

## 💬 Example Chat Prompts

Try these prompts in Claude Desktop once connected:

* **Basic Scan:** *"Use Vexa to scan the `src/` directory for security vulnerabilities."*
* **Full Remediation:** *"Use Vexa to scan and automatically fix any high or critical severity issues it finds in this project."*
* **Dynamic AI Override:** *"Use Vexa to scan and fix this directory, but make sure to pass `cloud_provider="google"` into the MCP tool to temporarily override my local Ollama config."*

---

For troubleshooting MCP connections, run `vexa doctor` in your terminal.
