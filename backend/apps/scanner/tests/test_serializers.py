"""Unit tests for scanner serializers."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from apps.scanner.models import Finding, Scan
from apps.scanner.serializers import FindingSerializer, ScanCreateSerializer


@pytest.mark.django_db
class TestScanCreateSerializer:
    def test_git_without_url_errors(self):
        data = {"source_type": "git"}
        serializer = ScanCreateSerializer(data=data)
        assert not serializer.is_valid()
        assert "source_url" in serializer.errors

    def test_zip_without_file_errors(self):
        data = {"source_type": "zip"}
        serializer = ScanCreateSerializer(data=data)
        assert not serializer.is_valid()
        assert "source_file" in serializer.errors

    def test_file_over_50mb_errors(self):
        big_file = SimpleUploadedFile("big.zip", b"x" * 100, content_type="application/zip")
        big_file.size = 51 * 1024 * 1024  # Fake 51 MB
        data = {"source_type": "zip", "source_file": big_file}
        serializer = ScanCreateSerializer(data=data)
        assert not serializer.is_valid()

    @patch("apps.scanner.serializers.validate_git_url", return_value="https://github.com/user/repo.git")
    def test_valid_git_data(self, mock_validate):
        data = {"source_type": "git", "source_url": "https://github.com/user/repo.git"}
        serializer = ScanCreateSerializer(data=data)
        assert serializer.is_valid(), serializer.errors


@pytest.mark.django_db
class TestFindingSerializer:
    def test_has_fix_true(self, scan):
        finding = Finding.objects.create(
            scan=scan,
            tool="semgrep",
            title="Test",
            severity="medium",
            fix_generated_at=timezone.now(),
            fixed_code="safe_code()",
            fix_explanation="Fixed it",
        )
        serializer = FindingSerializer(finding)
        assert serializer.data["has_fix"] is True

    def test_has_fix_false(self, scan):
        finding = Finding.objects.create(
            scan=scan,
            tool="semgrep",
            title="Test",
            severity="medium",
            fix_generated_at=None,
        )
        serializer = FindingSerializer(finding)
        assert serializer.data["has_fix"] is False
