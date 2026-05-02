import os
from unittest.mock import patch

from vexa.cicd.shadow_decorator import ShadowDecorator


def test_shadow_decorator_github_detection():
    """Test auto-detection of GitHub Actions environment."""
    env = {
        "GITHUB_ACTIONS": "true", 
        "GITHUB_TOKEN": "secret-token", 
        "GITHUB_REPOSITORY": "noviqtech/vexa", 
        "GITHUB_REF": "refs/pull/404/merge"
    }
    with patch.dict(os.environ, env, clear=True):
        decorator = ShadowDecorator(platform="auto")
        assert decorator.platform == "github"
        assert decorator.token == "secret-token"
        assert decorator.repo == "noviqtech/vexa"
        assert decorator.pr_id == "404"


def test_shadow_decorator_gitlab_detection():
    """Test auto-detection of GitLab CI environment."""
    env = {
        "GITLAB_CI": "true",
        "CI_JOB_TOKEN": "gl-token",
        "CI_PROJECT_ID": "123456",
        "CI_MERGE_REQUEST_IID": "88"
    }
    with patch.dict(os.environ, env, clear=True):
        decorator = ShadowDecorator(platform="auto")
        assert decorator.platform == "gitlab"
        assert decorator.token == "gl-token"
        assert decorator.repo == "123456"
        assert decorator.pr_id == "88"


@patch("vexa.cicd.shadow_decorator.requests.get")
@patch("vexa.cicd.shadow_decorator.requests.post")
def test_shadow_decorator_post_success(mock_post, mock_get):
    """Test a successful POST when no existing comment is found."""
    mock_get.return_value.json.return_value = []
    
    decorator = ShadowDecorator(platform="github")
    decorator.token = "fake"
    decorator.repo = "org/repo"
    decorator.pr_id = "1"
    
    result = decorator.post_or_update_summary("Security Scan Passed")
    assert result is True
    mock_post.assert_called_once()


@patch("vexa.cicd.shadow_decorator.requests.get")
def test_shadow_decorator_failure_swallowed_securely(mock_get):
    """
    CRITICAL: Ensure that if the API is down or token is invalid, 
    the decorator swallows the exception and returns False without crashing.
    """
    mock_get.side_effect = Exception("GitHub API is down for maintenance")
    
    decorator = ShadowDecorator(platform="github")
    decorator.token = "fake"
    decorator.repo = "org/repo"
    decorator.pr_id = "1"
    
    # Must not raise an exception
    result = decorator.post_or_update_summary("Security Scan Passed")
    assert result is False
