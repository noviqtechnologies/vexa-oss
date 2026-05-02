# Vexa CI/CD
![Vexa Logo](logo.png)
Automated security scanning integration for CI/CD pipelines.

Vexa provides native headless orchestration, quality gates, and automated pull request decoration as part of the **`vexa-core`** engine. While the logic lives in the core package, all CI/CD automation is distributed via the official **Vexa Docker Image** for a zero-setup experience.

## 🐳 Universal Docker Approach

The official Vexa Docker image is the recommended way to run Vexa in CI/CD pipelines. It bundles the full unified scanner engine and CLI into a single, self-contained image.

```bash
docker run --rm -v $(pwd):/workspace \
  ghcr.io/noviqtechnologies/vexa:latest \
  scan /workspace --format sarif,html,json,markdown --output /workspace/vexa_reports
```

### Why Docker?

| Benefit | Details |
|:---|:---|
| **Zero Setup** | No Python, pip, or virtualenv needed on the CI runner |
| **Environment Parity** | Identical behavior across all platforms |
| **All Batteries Included** | Core engine and CLI pre-installed with CI/CD native support |
| **Auto-Detection** | Automatically detects GitHub, GitLab, Azure, Jenkins, or Bitbucket |

## 🚀 Quick Start Templates

Copy the template for your platform into your repository:

### GitHub Actions
```yaml
# .github/workflows/vexa.yml
jobs:
  scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/noviqtechnologies/vexa:latest
    steps:
      - uses: actions/checkout@v4
      - run: vexa scan . --format sarif --fail-on critical,high
```
📄 Full template: [`templates/github-action.yml`](templates/github-action.yml)

### GitLab CI
```yaml
# .gitlab-ci.yml
vexa-scan:
  image: ghcr.io/noviqtechnologies/vexa:latest
  script:
    - vexa scan . --format sarif --fail-on critical,high
```
📄 Full template: [`templates/gitlab-ci.yml`](templates/gitlab-ci.yml)

### Azure Pipelines
```yaml
# azure-pipelines.yml
container:
  image: ghcr.io/noviqtechnologies/vexa:latest
steps:
  - script: vexa scan . --format sarif --fail-on critical,high
```
📄 Full template: [`templates/azure-pipelines.yml`](templates/azure-pipelines.yml)

### Jenkins
```groovy
// Jenkinsfile
pipeline {
    agent {
        docker { image 'ghcr.io/noviqtechnologies/vexa:latest' }
    }
    stages {
        stage('Scan') {
            steps { sh 'vexa scan . --format sarif --fail-on critical,high' }
        }
    }
}
```
📄 Full template: [`templates/Jenkinsfile`](templates/Jenkinsfile)

### Bitbucket Pipelines
```yaml
# bitbucket-pipelines.yml
image: ghcr.io/noviqtechnologies/vexa:latest
pipelines:
  default:
    - step:
        script:
          - vexa scan . --format sarif --fail-on critical,high
```
📄 Full template: [`templates/bitbucket-pipelines.yml`](templates/bitbucket-pipelines.yml)

### Any Other Tool
Any CI/CD tool that can run a Docker container can use Vexa:
```bash
docker run --rm -v $(pwd):/workspace \
  -e GOOGLE_API_KEY="${GOOGLE_API_KEY}" \
  ghcr.io/noviqtechnologies/vexa:latest \
  scan /workspace --fail-on critical,high
```

## ⚙️ Configuration

Place a `.vexa.yml` at your repository root to customize behavior:

```yaml
scanners:
  enabled: [bandit, semgrep, checkov, detect-secrets, pip-audit]

quality_gate:
  fail_on: [critical, high]
  max_total: 50
  min_score: "C"

ai:
  enabled: true
  provider: "google"  # google, openai, anthropic, ollama, none

reports:
  formats: [sarif, html, json, markdown]
```

📄 Full config template: [`templates/.vexa.yml`](templates/.vexa.yml)

## 🔌 Features

- **Quality Gates**: Fail builds on security regressions or baseline deviations.
- **PR Decoration**: Post security findings directly as comments in GitHub or GitLab pull requests.
- **Security Scoring**: Provide industry-standard A-F grading for commits.
- **Baseline Comparison**: Track new vs. existing findings across commits.
- **Compliance Mapping**: Map findings to SOC2, PCI-DSS, HIPAA, and NIST frameworks.
- **Trend Analysis**: Track security posture over time.
- **Shadow Mode**: Run decorations silently without failing the pipeline (`--shadow`).
- **Headless Mode**: Fully automated execution without user intervention.

## 🏗️ Building the Image

To build the Docker image from source:

```bash
cd vexa-oss
docker build -t ghcr.io/noviqtechnologies/vexa:latest -f deployment/Dockerfile .
```

### License
MIT License.

Visit [vexasec.io](https://vexasec.io) for full documentation.
