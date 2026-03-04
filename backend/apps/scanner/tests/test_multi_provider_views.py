"""Tests for multi-provider AI fix generation via the API views."""

import uuid
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import UserProfile
from apps.scanner.models import Finding, Scan

User = get_user_model()


@pytest.fixture
def user_with_profile(db):
    """Create a user with profile configured for OpenAI."""
    user = User.objects.create_user(
        username="provider_test@example.com",
        email="provider_test@example.com",
        password="testpass123",
    )
    profile = user.profile
    profile.ai_provider = "openai"
    profile.openai_api_key = "sk-test-key"
    profile.save(update_fields=["ai_provider", "openai_api_key"])
    return user


@pytest.fixture
def auth_client_provider(user_with_profile):
    client = APIClient()
    refresh = RefreshToken.for_user(user_with_profile)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client


@pytest.fixture
def scan_for_provider(user_with_profile):
    return Scan.objects.create(
        user=user_with_profile,
        source_type="git",
        source_url="https://github.com/example/repo.git",
        status="completed",
        security_score=80.0,
        workspace_path="/tmp/fake",
    )


@pytest.fixture
def finding_for_provider(scan_for_provider):
    return Finding.objects.create(
        scan=scan_for_provider,
        tool="semgrep",
        rule_id="test-rule",
        file_path="app.py",
        line_start=10,
        line_end=10,
        code_snippet="exec(user_input)",
        severity="high",
        owasp_category="A05",
        title="Dangerous exec()",
        description="User input in exec().",
    )


# ---------------------------------------------------------------------------
# MeView — provider fields
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestMeViewProviderFields:
    def test_get_returns_provider_fields(self, auth_client_provider):
        resp = auth_client_provider.get("/api/accounts/me/")
        assert resp.status_code == 200
        assert "ai_provider" in resp.data
        assert "openai_api_key" in resp.data
        assert "anthropic_api_key" in resp.data
        assert resp.data["ai_provider"] == "openai"
        assert resp.data["openai_api_key"] == "********"  # masked

    def test_patch_updates_provider(self, auth_client_provider):
        resp = auth_client_provider.patch(
            "/api/accounts/me/",
            {"ai_provider": "anthropic"},
            format="json",
        )
        assert resp.status_code == 200
        assert resp.data["ai_provider"] == "anthropic"

    def test_patch_updates_openai_key(self, auth_client_provider):
        resp = auth_client_provider.patch(
            "/api/accounts/me/",
            {"openai_api_key": "sk-new-key"},
            format="json",
        )
        assert resp.status_code == 200
        assert resp.data["openai_api_key"] == "********"

    def test_patch_updates_anthropic_key(self, auth_client_provider):
        resp = auth_client_provider.patch(
            "/api/accounts/me/",
            {"anthropic_api_key": "sk-ant-new"},
            format="json",
        )
        assert resp.status_code == 200
        assert resp.data["anthropic_api_key"] == "********"

    def test_patch_invalid_provider_ignored(self, auth_client_provider):
        resp = auth_client_provider.patch(
            "/api/accounts/me/",
            {"ai_provider": "invalid_provider"},
            format="json",
        )
        assert resp.status_code == 200
        assert resp.data["ai_provider"] == "openai"  # unchanged


# ---------------------------------------------------------------------------
# generate_fix view — provider dispatch
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestGenerateFixViewProvider:
    @patch("apps.scanner.services.autofix.generate_fix")
    def test_uses_profile_provider(self, mock_fix, auth_client_provider, finding_for_provider):
        mock_fix.return_value = {
            "fixed_code": "fixed()",
            "fix_explanation": "Fixed it.",
            "original_code": "exec(user_input)",
            "file_path": "app.py",
            "line_start": 10,
            "cached": False,
        }
        resp = auth_client_provider.post(
            f"/api/scanner/findings/{finding_for_provider.id}/fix/",
            format="json",
        )
        assert resp.status_code == 200
        mock_fix.assert_called_once()
        call_kwargs = mock_fix.call_args
        assert call_kwargs.kwargs.get("provider") == "openai" or call_kwargs[1].get("provider") == "openai"

    @patch("apps.scanner.services.autofix.generate_fix")
    def test_request_can_override_provider(self, mock_fix, auth_client_provider, finding_for_provider):
        mock_fix.return_value = {
            "fixed_code": "fixed()",
            "fix_explanation": "Fixed.",
            "original_code": "exec(user_input)",
            "file_path": "app.py",
            "line_start": 10,
            "cached": False,
        }
        resp = auth_client_provider.post(
            f"/api/scanner/findings/{finding_for_provider.id}/fix/",
            {"provider": "anthropic"},
            format="json",
        )
        assert resp.status_code == 200
        call_kwargs = mock_fix.call_args
        assert call_kwargs.kwargs.get("provider") == "anthropic" or call_kwargs[1].get("provider") == "anthropic"

    @patch("apps.scanner.services.autofix.generate_fix", side_effect=ValueError("No OpenAI API key configured."))
    def test_missing_key_returns_400(self, mock_fix, auth_client_provider, finding_for_provider):
        resp = auth_client_provider.post(
            f"/api/scanner/findings/{finding_for_provider.id}/fix/",
            format="json",
        )
        assert resp.status_code == 400
        assert "API key" in resp.data["detail"]


# ---------------------------------------------------------------------------
# UserProfile model — provider choices
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestUserProfileProviderModel:
    def test_default_provider_is_gemini(self, user):
        assert user.profile.ai_provider == "gemini"

    def test_can_set_openai(self, user):
        user.profile.ai_provider = "openai"
        user.profile.save(update_fields=["ai_provider"])
        user.profile.refresh_from_db()
        assert user.profile.ai_provider == "openai"

    def test_can_set_anthropic(self, user):
        user.profile.ai_provider = "anthropic"
        user.profile.save(update_fields=["ai_provider"])
        user.profile.refresh_from_db()
        assert user.profile.ai_provider == "anthropic"

    def test_can_store_openai_key(self, user):
        user.profile.openai_api_key = "sk-test-123"
        user.profile.save(update_fields=["openai_api_key"])
        user.profile.refresh_from_db()
        assert user.profile.openai_api_key == "sk-test-123"

    def test_can_store_anthropic_key(self, user):
        user.profile.anthropic_api_key = "sk-ant-test"
        user.profile.save(update_fields=["anthropic_api_key"])
        user.profile.refresh_from_db()
        assert user.profile.anthropic_api_key == "sk-ant-test"
