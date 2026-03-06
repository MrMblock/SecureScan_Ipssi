"""Integration tests for Celery tasks (run synchronously with CELERY_TASK_ALWAYS_EAGER)."""

import io
import subprocess
import uuid
import zipfile
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model

from apps.scanner.models import Finding, Scan
from apps.scanner.tasks.orchestrator import (
    _extract_zip,
    aggregate_results,
    orchestrate_scan,
    run_analyzer_task,
)

User = get_user_model()


@pytest.mark.django_db
class TestAggregateResults:
    def test_creates_findings_and_computes_score(self, scan):
        tool_results = [
            {
                "tool": "semgrep",
                "error": None,
                "findings": [
                    {
                        "tool": "semgrep",
                        "rule_id": "python.lang.sql-injection",
                        "file_path": "app.py",
                        "line_start": 5,
                        "severity": "high",
                        "title": "SQL Injection",
                        "description": "User input in SQL query",
                    },
                    {
                        "tool": "semgrep",
                        "rule_id": "python.crypto.weak-hash",
                        "file_path": "utils.py",
                        "line_start": 20,
                        "severity": "medium",
                        "title": "Weak hash",
                        "description": "MD5 used for hashing",
                    },
                ],
            },
        ]
        # Reset counts from fixture defaults
        scan.total_findings = 0
        scan.save()

        aggregate_results(tool_results, str(scan.id))

        scan.refresh_from_db()
        assert scan.status == "completed"
        assert scan.total_findings == 2
        assert scan.high_count == 1
        assert scan.medium_count == 1
        assert scan.security_score == 100 - 8 - 3  # high=-8, medium=-3
        assert scan.completed_at is not None
        assert Finding.objects.filter(scan=scan).count() == 2

    def test_zero_findings_score_100(self, scan):
        aggregate_results([], str(scan.id))
        scan.refresh_from_db()
        assert scan.status == "completed"
        assert scan.total_findings == 0
        assert scan.security_score == 100.0

    def test_severity_weights(self, scan):
        """1 critical + 1 high + 1 medium + 1 low → 100 - 15 - 8 - 3 - 1 = 73."""
        tool_results = [
            {
                "tool": "bandit",
                "error": None,
                "findings": [
                    {"tool": "bandit", "rule_id": "B301", "severity": "critical", "title": "x", "description": ""},
                    {"tool": "bandit", "rule_id": "B302", "severity": "high", "title": "x", "description": ""},
                    {"tool": "bandit", "rule_id": "B303", "severity": "medium", "title": "x", "description": ""},
                    {"tool": "bandit", "rule_id": "B104", "severity": "low", "title": "x", "description": ""},
                ],
            },
        ]
        aggregate_results(tool_results, str(scan.id))
        scan.refresh_from_db()
        assert scan.security_score == 100 - 15 - 8 - 3 - 1

    def test_empty_tool_results(self, scan):
        """None entries in tool_results are skipped gracefully."""
        aggregate_results([None, {}, {"findings": []}], str(scan.id))
        scan.refresh_from_db()
        assert scan.status == "completed"
        assert scan.total_findings == 0


@pytest.mark.django_db
class TestRunAnalyzerTask:
    def test_missing_workspace(self, user):
        scan = Scan.objects.create(user=user, source_type="git", status="scanning", workspace_path="")
        result = run_analyzer_task(str(scan.id), "semgrep")
        assert result["error"] == "No workspace"
        assert result["findings"] == []

    def test_nonexistent_scan(self):
        result = run_analyzer_task(str(uuid.uuid4()), "semgrep")
        assert result["error"] is not None
        assert result["findings"] == []

    def test_returns_findings_from_mocked_run_analyzer(self, user, tmp_path):
        """run_analyzer_task should return findings produced by the analyzer."""
        scan = Scan.objects.create(
            user=user,
            source_type="git",
            status="scanning",
            workspace_path=str(tmp_path),
        )
        fake_findings = [
            {
                "tool": "semgrep",
                "rule_id": "test-rule",
                "file_path": "app.py",
                "line_start": 1,
                "severity": "high",
                "title": "Test",
                "description": "Mock finding",
            }
        ]
        with patch("apps.scanner.tasks.analyzers.run_analyzer", return_value=fake_findings):
            result = run_analyzer_task(str(scan.id), "semgrep")

        assert result["error"] is None
        assert len(result["findings"]) == 1
        assert result["findings"][0]["rule_id"] == "test-rule"


# ── ZIP protection ───────────────────────────────────────────────────────────


class TestZipProtection:
    def _make_zip_bytes(self, members: list[tuple[str, bytes, int]]) -> bytes:
        """Build an in-memory ZIP; members is [(name, data, file_size_override)]."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            for name, data, _override in members:
                zf.writestr(name, data)
        raw = buf.getvalue()

        # Patch file_size in ZIP central-directory when a large override is needed.
        # For simplicity we rely on the actual size — tests that need inflated size
        # use many real bytes or test the path-traversal path.
        return raw

    def test_zip_slip_raises(self, tmp_path):
        """ZIP with path-traversal member must raise ValueError."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("../../evil.py")
            zf.writestr(info, "print('pwned')")
        zip_path = tmp_path / "slip.zip"
        zip_path.write_bytes(buf.getvalue())

        workspace = tmp_path / "out"
        workspace.mkdir()
        with pytest.raises(ValueError, match="[Zz]ip slip"):
            _extract_zip(str(zip_path), workspace)

    def test_zip_too_many_members_raises(self, tmp_path):
        """ZIP with member count > ZIP_MAX_MEMBERS must raise ValueError."""
        from apps.scanner.tasks.orchestrator import ZIP_MAX_MEMBERS

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            # Write enough entries to exceed the limit; use empty data for speed
            for i in range(ZIP_MAX_MEMBERS + 1):
                zf.writestr(f"file_{i}.txt", "")
        zip_path = tmp_path / "bomb.zip"
        zip_path.write_bytes(buf.getvalue())

        workspace = tmp_path / "out"
        workspace.mkdir()
        with pytest.raises(ValueError, match="members"):
            _extract_zip(str(zip_path), workspace)

    def test_valid_zip_extracts_ok(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("hello.py", "print('hello')")
        zip_path = tmp_path / "ok.zip"
        zip_path.write_bytes(buf.getvalue())

        workspace = tmp_path / "out"
        workspace.mkdir()
        _extract_zip(str(zip_path), workspace)
        assert (workspace / "hello.py").exists()


# ── orchestrate_scan failure paths ───────────────────────────────────────────


@pytest.mark.django_db
class TestOrchestrateScanFailures:
    def test_git_clone_failure_marks_scan_failed(self, user):
        scan = Scan.objects.create(
            user=user,
            source_type="git",
            source_url="https://example.com/repo.git",
            status="queued",
        )
        exc = subprocess.CalledProcessError(128, "git", stderr="repo not found")
        with patch("apps.scanner.tasks.orchestrator._clone_repo", side_effect=exc):
            result = orchestrate_scan(str(scan.id))

        scan.refresh_from_db()
        assert scan.status == "failed"
        assert result["status"] == "failed"

    def test_git_clone_timeout_marks_scan_failed(self, user):
        scan = Scan.objects.create(
            user=user,
            source_type="git",
            source_url="https://example.com/slow.git",
            status="queued",
        )
        with patch(
            "apps.scanner.tasks.orchestrator._clone_repo",
            side_effect=subprocess.TimeoutExpired("git", 120),
        ):
            result = orchestrate_scan(str(scan.id))

        scan.refresh_from_db()
        assert scan.status == "failed"
        assert result["status"] == "failed"
