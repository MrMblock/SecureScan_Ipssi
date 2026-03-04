"""Periodic Celery task to purge stale scan workspaces.

Registered with Celery Beat in settings.CELERY_BEAT_SCHEDULE (added in Plan 02).
Runs hourly to remove workspaces that are older than SCANNER_WORKSPACE_RETENTION_HOURS.
"""

import shutil
from datetime import timedelta
from pathlib import Path

from celery import shared_task
from django.conf import settings
from django.utils import timezone


@shared_task
def purge_stale_workspaces() -> dict:
    """Remove workspaces for completed/failed scans older than the retention window.

    For each matching Scan:
      - shutil.rmtree the workspace directory
      - Clear the workspace_path field so re-runs know the workspace is gone

    Returns a summary dict with counts for monitoring.
    """
    from apps.scanner.models import Scan  # noqa: PLC0415  (avoid circular at module load)

    retention_hours: int = getattr(settings, "SCANNER_WORKSPACE_RETENTION_HOURS", 48)
    cutoff = timezone.now() - timedelta(hours=retention_hours)

    stale_scans = Scan.objects.filter(
        status__in=["completed", "failed"],
        completed_at__lt=cutoff,
    ).exclude(workspace_path="")

    purged = 0
    errors = 0

    for scan in stale_scans:
        workspace = Path(scan.workspace_path)
        try:
            if workspace.exists():
                shutil.rmtree(workspace)
            scan.workspace_path = ""
            scan.save(update_fields=["workspace_path"])
            purged += 1
        except Exception:  # noqa: BLE001
            errors += 1

    return {"purged": purged, "errors": errors, "retention_hours": retention_hours}
