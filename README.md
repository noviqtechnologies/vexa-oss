# Vexa 🛡️ — Air-Gapped Security Scanning with AI Fixes

[![GA](https://img.shields.io/badge/status-GA-green)](https://vexasec.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)

**Run 9 industry-standard security scanners on your own machine. Generate fix code with your own AI. Zero telemetry. Zero data egress.**

Vexa orchestrates Bandit, Semgrep, Checkov, detect-secrets, npm-audit, pip-audit, pip-licenses, Grype, and Syft into a single command. It deduplicates findings, maps them to CWE/OWASP/MITRE/NIST frameworks, and uses AI (Ollama locally, or Gemini/OpenAI/Anthropic) to generate one-click security fixes.

## 🔒 Why Vexa?

| Feature | Vexa | Provider A | Provider B |
|:---|:---|:---|:---|
| **Zero data egress (Ollama)** | ✅ | ❌ | ❌ |
| **9 scanners in one tool** | ✅ | Partial | Partial |
| **AI fix generation** | ✅ (4 providers) | ✅ (1 vendor) | ✅ (1 vendor) |
| **MCP protocol (IDE-agnostic)** | ✅ | ❌ | ❌ |
| **No account required** | ✅ | ❌ | ❌ |
| **Open source** | ✅ | Partial | Partial |

## 🚀 Quick Start

### Install from PyPI (Stable)

Once published, you can install the latest stable version:

```bash
pip install vexa-core vexa-cli
```

### Install from GitHub (Latest)

To install the current development version directly from GitHub:

```bash
# Install core engine
pip install git+https://github.com/noviqtechnologies/vexa-oss.git#subdirectory=packages/core

# Install CLI tool
pip install git+https://github.com/noviqtechnologies/vexa-oss.git#subdirectory=packages/cli
```

### Install from source (Development)


```bash
git clone https://github.com/noviqtechnologies/vexa-oss.git
cd vexa
pip install -e packages/core -e packages/cli
```

### Homebrew (macOS/Linux)

```bash
brew install noviqtechnologies/tap/vexa
```

### Run your first scan

```bash
# Scan your project
vexa scan .

# Scan and generate AI-powered fixes (using Ollama — 100% local)
vexa fix . --ai-provider ollama

# Scan with a cloud AI provider
vexa fix . --ai-provider google

# Check scanner health
vexa doctor
```

### Development (using uv)

If you are running from source in this repository:

```bash
# Sync the environment
uv sync

# Run scan/fix from source
uv run vexa scan .
uv run vexa fix . --ai-provider ollama
```

## 🛠️ Commands

| Command | Description |
|:---|:---|
| `vexa scan .` | Scan your project with all available scanners |
| `vexa fix .` | Scan and generate AI-powered security fixes |
| `vexa doctor` | Check scanner availability and AI provider status |
| `vexa report` | Generate HTML/JSON/SARIF/Markdown reports |
| `vexa init` | Interactive project setup wizard |
| `vexa list-scanners` | Show all available scanners |

## 🔒 Privacy Modes

Your code is your business. Vexa gives you full control:

1. **Privacy Vault (Local):** Run 100% locally with Ollama. No code snippets or metadata leave your machine. Ever.
   > **Note:** The default model (`gemma4:26b`) requires ~18-32GB of RAM. If you hit out-of-memory errors, configure a smaller model (like `llama3:8b`) in your `.vexa.yml` file. See [QUICKSTART.md](docs/QUICKSTART.md) for setup instructions.
2. **Cloud AI:** Use Gemini, OpenAI, or Anthropic for analysis. Code snippets are sent to the AI provider you choose.
3. **No AI:** Run scanners only. Zero network calls.

## 🧩 Integrations

### VS Code Extension

Coming soon!

### CI/CD (GitHub Actions)

Coming soon!

### MCP Protocol (Claude, Cursor, Antigravity)

Vexa exposes an MCP server that works with any MCP-compatible IDE.

**Important Note on AI Delegation**: When using Vexa via MCP, your chat AI (e.g., Claude) acts only as the *orchestrator*. The actual security analysis and code generation is handled by the AI provider configured in your `.vexa.yml` file (e.g., local Ollama). This ensures consistent, enterprise-grade security results regardless of which IDE you use.

If you installed Vexa globally, configure your client (like Claude Desktop) as follows:
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

**Running from Source / `uv` Users:**
If you are running Vexa from source, you MUST bypass terminal wrappers (like `cmd.exe`) and use the `--quiet` flag to prevent `uv` from polluting standard output and corrupting the JSON-RPC stream:
```json
{
  "mcpServers": {
    "vexa": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/vexa-oss", "run", "--quiet", "vexa", "mcp-server"]
    }
  }
}
```

> 📖 **Read the [Full MCP Documentation](docs/MCP.md)** for advanced setup instructions, handling API environment variables, and copy-paste prompt examples to use with your AI assistant.

### 🧠 Design Philosophy: `scan` vs `fix`
* **`vexa scan`** is designed for Auditing and CI/CD pipelines. It automatically generates a `vexa_scan_reports/` directory containing JSON, HTML, and SARIF artifacts for compliance.
* **`vexa fix`** is designed for a frictionless, interactive developer workflow. It prompts you in real-time and relies on Git to track file changes, deliberately avoiding generating report files to keep your workspace clean. (Use `--dry-run > fixes.patch` if you need a paper trail).

## 📦 Packages

| Package | Description |
|:---|:---|
| `vexa-core` | Scanner engine, AI providers, reports, deduplication |
| `vexa-cli` | Command-line interface (Click + Rich) |
| `vexa-mcp` | MCP server for IDE integration (FastMCP) |

## 💬 Community

* **Discussions**: [GitHub Discussions](https://github.com/noviqtechnologies/vexa-oss/discussions)
* **Issues**: [Bug Reports & Feature Requests](https://github.com/noviqtechnologies/vexa-oss/issues)
* **Website**: [vexasec.io](https://vexasec.io/)

## 📄 License

MIT — see [LICENSE](LICENSE).

---

[Documentation](docs/QUICKSTART.md) | [Website](https://vexasec.io/)

