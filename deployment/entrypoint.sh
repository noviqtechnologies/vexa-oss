#!/bin/bash
set -e

# ──────────────────────────────────────────────────
# Vexa CI/CD Docker Entrypoint
#
# Handles environment detection and delegates to the
# vexa CLI. Designed for headless, non-interactive
# execution across all CI/CD platforms.
# ──────────────────────────────────────────────────

# Auto-accept terms in CI environments
export VEXA_TERMS_ACCEPTED=true

# Auto-detect CI platform for PR decoration
if [ -n "$GITHUB_ACTIONS" ]; then
    export VEXA_CI_PLATFORM="github"
elif [ -n "$GITLAB_CI" ]; then
    export VEXA_CI_PLATFORM="gitlab"
elif [ -n "$BUILD_DEFINITIONNAME" ]; then
    export VEXA_CI_PLATFORM="azure"
elif [ -n "$JENKINS_URL" ]; then
    export VEXA_CI_PLATFORM="jenkins"
elif [ -n "$BITBUCKET_PIPELINE_UUID" ]; then
    export VEXA_CI_PLATFORM="bitbucket"
else
    export VEXA_CI_PLATFORM="generic"
fi

echo "🛡️  Vexa Security Scanner"
echo "   Platform: ${VEXA_CI_PLATFORM}"
echo "   AI Provider: ${VEXA_AI_PROVIDER:-none}"
echo "──────────────────────────────────────"

# Delegate to vexa CLI
exec vexa --non-interactive "$@"
