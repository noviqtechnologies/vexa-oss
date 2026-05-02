# ──────────────────────────────────────────────────
# Vexa — Universal CI/CD Security Scanner Image
# ──────────────────────────────────────────────────
# This image bundles vexa-core and vexa-cli (with native CI/CD logic)
# into a single, self-contained container that runs on
# any CI/CD platform: GitHub Actions, GitLab CI, Azure
# Pipelines, Jenkins, Bitbucket Pipelines, and more.
#
# Usage:
#   docker run --rm -v $(pwd):/workspace vexa:latest scan /workspace
#
# Build:
#   docker build -t vexa:latest -f deployment/Dockerfile .
# ──────────────────────────────────────────────────

FROM python:3.11-slim AS base

LABEL org.opencontainers.image.title="Vexa Security Scanner"
LABEL org.opencontainers.image.description="Universal CI/CD security scanner with quality gates, PR decoration, and AI-powered fixes"
LABEL org.opencontainers.image.url="https://vexasec.io"
LABEL org.opencontainers.image.source="https://github.com/noviqtechnologies/vexa-oss"
LABEL org.opencontainers.image.vendor="Noviq Technologies"
LABEL org.opencontainers.image.licenses="MIT"

# ── System Dependencies ──────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# ── Install Vexa Packages ────────────────────────
COPY packages/core /tmp/vexa-core
COPY packages/cli  /tmp/vexa-cli

RUN pip install --no-cache-dir \
    /tmp/vexa-core \
    /tmp/vexa-cli \
    && rm -rf /tmp/vexa-core /tmp/vexa-cli

# ── Entrypoint ────────────────────────────────────
COPY deployment/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# ── Runtime Configuration ─────────────────────────
# Accept terms automatically in CI environments
ENV CI=true
ENV VEXA_NON_INTERACTIVE=true

WORKDIR /workspace

ENTRYPOINT ["entrypoint.sh"]
CMD ["scan", "/workspace", "--format", "sarif,json,html,markdown", "--output", "/workspace/vexa_reports"]
