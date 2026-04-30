# Vexa Quickstart Guide 🚀

Get up and running with Vexa in minutes.

## Installation

### From PyPI (Recommended)

```bash
pip install vexa-cli
```

### From Source

```bash
git clone https://github.com/noviqtechnologies/vexa-oss.git
cd vexa-oss
pip install -e packages/core -e packages/cli
```

## First Scan

1. Navigate to your project directory:
   ```bash
   cd /path/to/your/project
   ```

2. Run a full security scan:
   ```bash
   vexa scan .
   ```

3. Check for scanner health:
   ```bash
   vexa doctor
   ```

## Using AI Fixes

Vexa can generate code fixes for discovered vulnerabilities.

### Using Ollama (100% Local & Private)

1. [Install Ollama](https://ollama.ai)
2. Run with the ollama provider:
   ```bash
   vexa fix . --provider ollama
   ```

### Using Cloud Providers

Set your API key as an environment variable:

```bash
export GOOGLE_API_KEY="your-key"
vexa fix . --provider google
```

## Next Steps

- Explore [supported scanners](SCANNERS.md)
- Configure [exclusion patterns](EXCLUSIONS.md)
- Integrate with [MCP](MCP.md)
