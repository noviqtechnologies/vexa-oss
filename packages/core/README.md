# Vexa Core SDK
![Vexa Logo](logo.png)
The fundamental engine powering AI-native security analysis.

Vexa Core provides the underlying logic for multi-scanner orchestration, AI-powered remediation, and security audit logging.

### Installation
```bash
pip install vexa-core
```

### Getting Started
```python
from vexa.core.engine import ScanEngine
from vexa.ai_providers import AIManager

# Initialize engine with default scanners
engine = ScanEngine(scanners=['bandit', 'semgrep'])

# Run analysis
findings = engine.scan_file("insecure.py")

for finding in findings:
    print(f"[{finding.severity}] {finding.title}: {finding.description}")
```

### Requirements
- Python 3.9+
- Security Scanners (Bandit, Semgrep, etc.) installed on PATH.

### License
MIT License.
