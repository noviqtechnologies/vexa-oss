# Vexa MCP Server
Model Context Protocol server for Vexa.

This package enables Large Language Models (LLMs) to perform security scans and provide remediation directly within MCP-compatible environments (like Claude Desktop or VS Code).

### Installation
```bash
pip install vexa-mcp
```

### Usage
Add this to your MCP configuration (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vexa": {
      "command": "python",
      "args": ["-m", "vexa_mcp"]
    }
  }
}
```

### Tools provided
- `scan_file`: Analyze a single file for vulnerabilities.
- `scan_workspace`: Perform a full project audit.
- `enrich_findings`: Use AI to generate remediation code for security issues.

### Requirements
- Python 3.9+
- An MCP host environment.
