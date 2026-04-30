# Vexa CLI
![Vexa Logo](logo.png)
AI-powered security analysis from your terminal.

The Vexa CLI allows you to run professional-grade security audits on your codebase with one-click AI remediation suggestions.

### Installation
```bash
pip install vexa-cli
```

### Quick Start
```bash
# Scan the current directory
vexa scan .

# Scan a specific file and export to HTML
vexa scan main.py --format html --output report.html

# Run a full security audit with AI enrichment
vexa scan . --full --ai google
```

### Features
- **Multi-Scanner**: Orchestrates Bandit, Semgrep, Checkov, and more.
- **AI-Native**: Direct integration with Gemini and Claude for fixing vulnerabilities.
- **Exportable**: Generate SARIF, JSON, and HTML reports.

### Requirements
- Python 3.9+
