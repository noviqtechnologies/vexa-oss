# Vexa 🛡️ — Air-Gapped Security Scanning with AI Fixes

[![Beta](https://img.shields.io/badge/status-beta-orange)](https://usevexa.dev)
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

### Install from PyPI

```bash
pip install vexa-core vexa-cli
```

### Install from source (development)

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
vexa fix . --provider ollama

# Scan with a cloud AI provider
vexa fix . --provider google

# Check scanner health
vexa doctor
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
2. **Cloud AI:** Use Gemini, OpenAI, or Anthropic for analysis. Code snippets are sent to the AI provider you choose.
3. **No AI:** Run scanners only. Zero network calls.

## 🧩 Integrations

### VS Code Extension

Coming soon!

### CI/CD (GitHub Actions)

Coming soon!

### MCP Protocol (Claude, Cursor, Antigravity)

Vexa exposes an MCP server that works with any MCP-compatible IDE:

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

## 📦 Packages

| Package | Description |
|:---|:---|
| `vexa-core` | Scanner engine, AI providers, reports, deduplication |
| `vexa-cli` | Command-line interface (Click + Rich) |
| `vexa-mcp` | MCP server for IDE integration (FastMCP) |

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Issues and PRs are welcome.

## 📄 License

MIT — see [LICENSE](LICENSE).

---

[Documentation](docs/QUICKSTART.md) | [Website](https://usevexa.dev)
