"""Shared pytest fixtures for the SecureScan backend test suite."""

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.test")

import django  # noqa: E402

django.setup()

import pytest  # noqa: E402
from django.contrib.auth import get_user_model  # noqa: E402
from rest_framework.test import APIClient  # noqa: E402
from rest_framework_simplejwt.tokens import RefreshToken  # noqa: E402

User = get_user_model()


@pytest.fixture
def user(db):
    """Create a standard test user."""
    return User.objects.create_user(
        username="testuser@example.com",
        email="testuser@example.com",
        password="testpass123",
        first_name="Test",
    )


@pytest.fixture
def auth_client(user):
    """Return an APIClient authenticated with a Bearer JWT for *user*."""
    client = APIClient()
    refresh = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
    return client


@pytest.fixture
def scan(user, db):
    """Create a completed Scan owned by *user*."""
    from apps.scanner.models import Scan

    return Scan.objects.create(
        user=user,
        source_type="git",
        source_url="https://github.com/example/repo.git",
        status="completed",
        security_score=85.0,
        total_findings=3,
        critical_count=0,
        high_count=1,
        medium_count=1,
        low_count=1,
        workspace_path="/tmp/securescan_test_workspaces/fake",
    )


@pytest.fixture
def finding(scan, db):
    """Create a Semgrep Finding attached to *scan*."""
    from apps.scanner.models import Finding

    return Finding.objects.create(
        scan=scan,
        tool="semgrep",
        rule_id="python.lang.security.audit.dangerous-exec-use",
        file_path="app.py",
        line_start=10,
        line_end=10,
        code_snippet="exec(user_input)",
        severity="high",
        owasp_category="A05",
        title="Dangerous exec() usage",
        description="User input passed to exec().",
    )


@pytest.fixture
def workspace(tmp_path):
    """Create a temporary workspace with sample Python and JS files."""
    # Python file
    (tmp_path / "app.py").write_text("print('hello')\n")
    (tmp_path / "requirements.txt").write_text("django\n")

    # JavaScript file
    (tmp_path / "index.js").write_text("console.log('hi');\n")

    return tmp_path
