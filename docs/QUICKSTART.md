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

1. [Install Ollama](https://ollama.ai/download) for your OS (Windows, macOS, Linux).
2. Ensure the Ollama server is running (usually runs in the background automatically, or start it with `ollama serve`).
3. By default, Vexa uses the `gemma4:26b` model (requires ~18-32GB of RAM). If you have less RAM, pull a smaller model:
   ```bash
   ollama pull llama3:8b
   ```
4. If you use a smaller model, create a `.vexa.yml` file in your project root to tell Vexa which model to use:
   ```yaml
   ai:
     provider: "ollama"
     model: "llama3:8b" # Fits easily in 8-16GB RAM
   ```
5. Run the scan with the Ollama provider:
   ```bash
   vexa fix . --ai-provider ollama
   ```

### Using Cloud Providers

Vexa supports Gemini, OpenAI, and Anthropic. You can configure authentication in several ways:

1. **Global Flag (Foolproof)**:
   ```bash
   vexa --api-key "your-key" fix . --ai-provider google
   ```

2. **Environment Variables**:
   Vexa supports standard variables: `GOOGLE_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`.
   ```bash
   export GOOGLE_API_KEY="your-key"
   vexa fix . --ai-provider google
   ```

3. **.env File**:
   Create a `.env` file in your project root. Vexa will automatically load it.
   ```text
   GOOGLE_API_KEY=your-key
   ```

4. **Verify Connectivity**:
   Use the targeted doctor command to test your connection:
   ```bash
   vexa doctor --ai-provider google
   ```

## Next Steps

- Explore [supported scanners](SCANNERS.md)
- Configure [exclusion patterns](EXCLUSIONS.md)
- Integrate with [MCP](MCP.md)
