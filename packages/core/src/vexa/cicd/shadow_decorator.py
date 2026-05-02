"""
ShadowDecorator for Vexa CI/CD.

Extends the base PRDecorator to perform API-driven pull request 
decorations without risking pipeline failures. All exceptions 
are swallowed and telemetry is prevented to maintain Zero Telemetry standard.
"""

import os
import requests

from vexa.common.logging import get_logger
from .pr_decorator import PRDecorator

logger = get_logger(__name__)


class ShadowDecorator(PRDecorator):
    """
    Applies markdown PR decorations directly to platforms (GitHub/GitLab)
    using REST APIs. Guarantees that exceptions (network, auth, timeout) 
    are caught and swallowed so the CI pipeline exits 0.
    """
    
    SIGNATURE_TAG = "<!-- vexa-shadow-summary -->"

    def __init__(self, platform: str = "auto"):
        super().__init__()
        self.platform = platform
        self.token = ""
        self.repo = ""
        self.pr_id = ""
        self._detect_environment()

    def _detect_environment(self):
        """Automatically detect CI context based on environment variables."""
        if self.platform == "auto":
            if "GITHUB_ACTIONS" in os.environ:
                self.platform = "github"
            elif "GITLAB_CI" in os.environ:
                self.platform = "gitlab"
            else:
                logger.warning("ShadowDecorator: Could not auto-detect CI platform.")
                return

        if self.platform == "github":
            self.token = os.environ.get("GITHUB_TOKEN", "")
            self.repo = os.environ.get("GITHUB_REPOSITORY", "")
            # Extract PR ID from GitHub Ref: refs/pull/123/merge
            ref = os.environ.get("GITHUB_REF", "")
            if ref.startswith("refs/pull/"):
                try:
                    self.pr_id = ref.split("/")[2]
                except IndexError:
                    pass
        elif self.platform == "gitlab":
            self.token = os.environ.get("CI_JOB_TOKEN", os.environ.get("GITLAB_API_TOKEN", ""))
            self.repo = os.environ.get("CI_PROJECT_ID", "")
            self.pr_id = os.environ.get("CI_MERGE_REQUEST_IID", "")

    def post_or_update_summary(self, markdown_content: str) -> bool:
        """
        Executes the REST API call to post or update the PR comment.
        Returns True if successful, False if it failed silently.
        """
        if not self.token or not self.repo or not self.pr_id:
            logger.warning("ShadowDecorator: Missing credentials or PR context. Skipping decoration.")
            return False

        # Prepend the signature for idempotency
        payload_body = f"{self.SIGNATURE_TAG}\n{markdown_content}"

        try:
            if self.platform == "github":
                return self._decorate_github(payload_body)
            elif self.platform == "gitlab":
                return self._decorate_gitlab(payload_body)
            return False
        except Exception as e:
            # The core tenet of Shadow Mode: Fail Silent
            logger.error(f"ShadowDecorator API failed securely: {e}")
            return False

    def _decorate_github(self, body: str) -> bool:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }
        api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
        comments_url = f"{api_url}/repos/{self.repo}/issues/{self.pr_id}/comments"

        # 1. Look for existing comment to deduplicate
        resp = requests.get(comments_url, headers=headers, timeout=10)
        resp.raise_for_status()
        
        existing_comment_id = None
        for comment in resp.json():
            if self.SIGNATURE_TAG in comment.get("body", ""):
                existing_comment_id = comment["id"]
                break
        
        # 2. Update or Post
        payload = {"body": body}
        if existing_comment_id:
            update_url = f"{api_url}/repos/{self.repo}/issues/comments/{existing_comment_id}"
            put_resp = requests.patch(update_url, headers=headers, json=payload, timeout=10)
            put_resp.raise_for_status()
        else:
            post_resp = requests.post(comments_url, headers=headers, json=payload, timeout=10)
            post_resp.raise_for_status()
            
        return True

    def _decorate_gitlab(self, body: str) -> bool:
        # Simplified GitLab implementation
        headers = {"PRIVATE-TOKEN": self.token}
        api_url = os.environ.get("CI_API_V4_URL", "https://gitlab.com/api/v4")
        notes_url = f"{api_url}/projects/{self.repo}/merge_requests/{self.pr_id}/notes"
        
        # In a full implementation, we would query the notes endpoint for the signature.
        # For this execution phase, we will issue a simple blind POST to prove the interface.
        post_resp = requests.post(notes_url, headers=headers, json={"body": body}, timeout=10)
        post_resp.raise_for_status()
        return True
