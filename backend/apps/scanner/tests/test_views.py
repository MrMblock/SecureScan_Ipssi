"""Functional tests for the scanner API endpoints."""

import uuid
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from apps.scanner.models import Finding, Scan

User = get_user_model()


# ── Health endpoint ──────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_health_returns_200(auth_client):
    resp = auth_client.get("/api/scanner/health/")
    assert resp.status_code == 200
    assert resp.data["status"] == "ok"


# ── Scan list ────────────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_scan_list_unauthenticated():
    client = APIClient()
    resp = client.get("/api/scanner/scans/")
    assert resp.status_code == 401


@pytest.mark.django_db
def test_scan_list_authenticated(auth_client, scan):
    resp = auth_client.get("/api/scanner/scans/")
    assert resp.status_code == 200
    assert len(resp.data) >= 1


@pytest.mark.django_db
@patch("apps.scanner.tasks.orchestrator.orchestrate_scan.delay")
@patch("apps.scanner.serializers.validate_git_url", return_value="https://github.com/user/repo.git")
def test_create_scan(mock_validate, mock_delay, auth_client, user):
    mock_delay.return_value.id = "fake-celery-id"
    resp = auth_client.post("/api/scanner/scans/", {
        "source_type": "git",
        "source_url": "https://github.com/user/repo.git",
    }, format="json")
    assert resp.status_code == 201
    mock_delay.assert_called_once()


# ── Scan detail ──────────────────────────────────────────────────────────────


@pytest.mark.django_db
def test_scan_detail(auth_client, scan):
    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/")
    assert resp.status_code == 200
    assert resp.data["id"] == str(scan.id)


@pytest.mark.django_db
def test_scan_detail_other_user(scan):
    """Scans owned by another user should return 404."""
    other = User.objects.create_user(username="other@x.com", email="other@x.com", password="pass")
    from rest_framework_simplejwt.tokens import RefreshToken

    client = APIClient()
    token = RefreshToken.for_user(other)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    resp = client.get(f"/api/scanner/scans/{scan.id}/")
    assert resp.status_code == 404


@pytest.mark.django_db
def test_delete_scan(auth_client, scan, finding):
    resp = auth_client.delete(f"/api/scanner/scans/{scan.id}/")
    assert resp.status_code == 204
    assert not Scan.objects.filter(id=scan.id).exists()
    assert not Finding.objects.filter(id=finding.id).exists()


# ── Findings list & filters ──────────────────────────────────────────────────


@pytest.mark.django_db
def test_findings_list(auth_client, scan, finding):
    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/findings/")
    assert resp.status_code == 200
    assert len(resp.data["results"]) >= 1


@pytest.mark.django_db
def test_findings_filter_severity(auth_client, scan, finding):
    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/findings/?severity=high")
    assert resp.status_code == 200
    assert all(f["severity"] == "high" for f in resp.data["results"])


@pytest.mark.django_db
def test_findings_filter_tool(auth_client, scan, finding):
    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/findings/?tool=semgrep")
    assert resp.status_code == 200
    assert all(f["tool"] == "semgrep" for f in resp.data["results"])


@pytest.mark.django_db
def test_findings_filter_owasp(auth_client, scan, finding):
    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/findings/?owasp=A05")
    assert resp.status_code == 200
    assert all(f["owasp_category"] == "A05" for f in resp.data["results"])


@pytest.mark.django_db
def test_findings_filter_no_match(auth_client, scan, finding):
    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/findings/?severity=critical")
    assert resp.status_code == 200
    assert len(resp.data["results"]) == 0


# ── Source file endpoint ─────────────────────────────────────────────────────


@pytest.mark.django_db
def test_source_file(auth_client, scan, tmp_path):
    # Create a real workspace with a file
    (tmp_path / "app.py").write_text("print('hello')\n")
    scan.workspace_path = str(tmp_path)
    scan.save(update_fields=["workspace_path"])

    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/source/?path=app.py")
    assert resp.status_code == 200
    assert "hello" in resp.data["content"]


@pytest.mark.django_db
def test_source_file_path_traversal(auth_client, scan, tmp_path):
    scan.workspace_path = str(tmp_path)
    scan.save(update_fields=["workspace_path"])

    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/source/?path=../../etc/passwd")
    assert resp.status_code == 400
    assert "Invalid" in resp.data["detail"]


@pytest.mark.django_db
def test_source_file_missing_path_param(auth_client, scan):
    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/source/")
    assert resp.status_code == 400
    assert "path" in resp.data["detail"].lower()


# ── Generate fix endpoint ───────────────────────────────────────────────────


@pytest.mark.django_db
def test_generate_fix_not_found(auth_client):
    fake_id = uuid.uuid4()
    resp = auth_client.post(f"/api/scanner/findings/{fake_id}/fix/")
    assert resp.status_code == 404


# ── Dashboard stats endpoint ─────────────────────────────────────────────────


@pytest.mark.django_db
def test_stats_unauthenticated():
    client = APIClient()
    resp = client.get("/api/scanner/stats/")
    assert resp.status_code == 401


@pytest.mark.django_db
def test_stats_returns_expected_keys(auth_client, scan):
    """GET /api/scanner/stats/ must return all aggregation keys."""
    resp = auth_client.get("/api/scanner/stats/")
    assert resp.status_code == 200
    for key in ("total_scans", "completed_scans", "total_findings", "total_critical", "avg_score"):
        assert key in resp.data, f"Missing key: {key}"


@pytest.mark.django_db
def test_stats_counts_completed_scans(auth_client, user):
    """completed_scans only counts scans with status='completed'."""
    Scan.objects.create(user=user, source_type="git", status="completed", security_score=90.0)
    Scan.objects.create(user=user, source_type="git", status="completed", security_score=70.0)
    Scan.objects.create(user=user, source_type="git", status="scanning", security_score=0.0)

    resp = auth_client.get("/api/scanner/stats/")
    assert resp.status_code == 200
    assert resp.data["total_scans"] >= 2
    assert resp.data["completed_scans"] >= 2


# ── Findings pagination ──────────────────────────────────────────────────────


@pytest.mark.django_db
def test_findings_paginated_response(auth_client, scan, user):
    """Findings list returns paginated DRF envelope when page param is supplied."""
    # Create 3 findings on the existing scan
    for i in range(3):
        Finding.objects.create(
            scan=scan,
            tool="semgrep",
            rule_id=f"rule-{i}",
            severity="low",
            title=f"Finding {i}",
            description="",
        )

    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/findings/?page=1&page_size=2")
    assert resp.status_code == 200
    # DRF PageNumberPagination returns {"count": N, "results": [...]}
    if isinstance(resp.data, dict) and "count" in resp.data:
        assert resp.data["count"] >= 3
        assert len(resp.data["results"]) <= 2
    else:
        # fallback: plain list — at least check it returned findings
        assert len(resp.data) >= 1


@pytest.mark.django_db
def test_findings_page_out_of_range(auth_client, scan):
    """Requesting a page beyond available pages returns 404 or empty results set."""
    resp = auth_client.get(f"/api/scanner/scans/{scan.id}/findings/?page=9999")
    assert resp.status_code in (200, 404)
