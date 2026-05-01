# Exclusion Patterns 🛡️

Vexa allows you to exclude files and directories from scans to reduce noise and improve performance.

## Default Exclusions

By default, Vexa excludes common non-source directories:
*   `node_modules/`
*   `.venv/`, `venv/`, `env/`
*   `dist/`, `build/`
*   `.git/`
*   `tests/`, `test/` (can be overridden)
*   `vexa_scan_reports/`

## Custom Exclusions

### Using `.vexaignore`

You can create a `.vexaignore` file in the root of your project. It follows the same glob pattern syntax as `.gitignore`.

```ignore
# Exclude specific files
secret_config.py

# Exclude entire directories
temp_assets/

# Exclude by pattern
*.log
docs/**/*.html
```

### Using the CLI

You can pass exclusions directly to the `scan` command using the `--exclude` flag:

```bash
vexa scan . --exclude "deprecated/*,experimental/*.py"
```

## AI Exclusion

If you want Vexa to scan a file but **NEVER** send it to an AI provider for fixes (Privacy mode), you can use the `--no-ai-files` flag or mark files in your configuration.

---

For more details on global exclusion settings, run `vexa init`.
