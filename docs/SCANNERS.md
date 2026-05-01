# Supported Scanners 🔍

Vexa orchestrates 9 industry-standard security scanners. Each scanner is automatically detected based on your project's technology stack.

## Static Analysis (SAST)

### [Bandit](https://github.com/PyCQA/bandit)
*   **Target**: Python
*   **Focus**: Common security issues in Python code.
*   **Auto-Detection**: Triggered if `.py` files are present.

### [Semgrep](https://github.com/semgrep/semgrep)
*   **Target**: Multi-language (Python, JS, TS, Go, Java, etc.)
*   **Focus**: Pattern-matching engine for finding deep logical vulnerabilities.
*   **Note**: Semgrep is skipped on Windows unless running in WSL.

### [Checkov](https://github.com/bridgecrewio/checkov)
*   **Target**: Infrastructure as Code (Terraform, CloudFormation, Kubernetes)
*   **Focus**: Misconfigurations in cloud infrastructure.

## Dependency Scanning (SCA)

### [pip-audit](https://github.com/pypa/pip-audit)
*   **Target**: Python dependencies.
*   **Focus**: Vulnerabilities in packages listed in `requirements.txt` or `pyproject.toml`.

### [npm-audit](https://docs.npmjs.com/cli/v10/commands/npm-audit)
*   **Target**: JavaScript/Node.js dependencies.
*   **Focus**: Known vulnerabilities in the npm registry.

### [pip-licenses](https://github.com/pypa/pip-licenses)
*   **Target**: Python licenses.
*   **Focus**: Identifying dependencies with restrictive or non-compliant licenses.

## Secret Detection

### [detect-secrets](https://github.com/Yelp/detect-secrets)
*   **Target**: All files.
*   **Focus**: Finding hardcoded passwords, API keys, and tokens.

## Container & SBOM (Experimental)

### [Grype](https://github.com/anchore/grype)
*   **Target**: Container images and filesystems.
*   **Focus**: Vulnerabilities in operating system packages and language artifacts.

### [Syft](https://github.com/anchore/syft)
*   **Target**: Container images and filesystems.
*   **Focus**: Generating Software Bill of Materials (SBOM).

---

## Scanner Configuration

Scanners can be configured globally or per-project. Use `vexa init` to set up your preferences.
