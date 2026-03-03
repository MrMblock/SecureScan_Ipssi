"""Celery orchestrator task for the full scan pipeline.

Pipeline:
  1. Clone / extract / copy uploaded files into a sandboxed workspace
  2. Detect programming languages in the workspace
  3. Dispatch a Celery chord of analyzer stubs (one per tool) followed by
     aggregate_results as the callback

Research pitfalls addressed:
  - Pitfall 1: use subprocess.run() for git clone — GitPython hangs indefinitely
  - Pitfall 2: every chord group task wraps its body in try/except so that a
    single tool failure does not silently swallow the chord callback
"""

import logging
import shutil
import subprocess
import zipfile
from pathlib import Path

from celery import chord, group, shared_task
from django.conf import settings
from django.utils import timezone

from ..services.language_detector import detect_languages, get_analyzers_for_languages

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WORKSPACE_ROOT: Path = Path(settings.SCANNER_WORKSPACE_ROOT)

ZIP_MAX_COMPRESSED_BYTES: int = 50 * 1024 * 1024   # 50 MB
ZIP_MAX_UNCOMPRESSED_BYTES: int = 500 * 1024 * 1024  # 500 MB
ZIP_MAX_MEMBERS: int = 10_000


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _clone_repo(url: str, workspace: Path) -> None:
    """Clone a Git repository (shallow, single branch) into *workspace*.

    Uses subprocess.run() — NOT GitPython — to avoid an indefinite hang on
    large or slow remotes (research Pitfall 1).
    """
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", url, str(workspace)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return result


def _extract_zip(zip_path: str, workspace: Path) -> None:
    """Extract a ZIP archive into *workspace* with zip-bomb and zip-slip protection."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()

        # Bomb check — member count
        if len(members) > ZIP_MAX_MEMBERS:
            raise ValueError(
                f"ZIP archive has {len(members)} members (limit {ZIP_MAX_MEMBERS})"
            )

        # Bomb check — total uncompressed size
        total_size = sum(m.file_size for m in members)
        if total_size > ZIP_MAX_UNCOMPRESSED_BYTES:
            raise ValueError(
                f"ZIP archive uncompressed size {total_size} exceeds "
                f"limit {ZIP_MAX_UNCOMPRESSED_BYTES}"
            )

        # Zip-slip check — every resolved member path must stay inside workspace
        resolved_workspace = workspace.resolve()
        for member in members:
            resolved_member = (workspace / member.filename).resolve()
            if not str(resolved_member).startswith(str(resolved_workspace)):
                raise ValueError(
                    f"Zip slip detected: member '{member.filename}' would escape workspace"
                )

        zf.extractall(workspace)

    # If the ZIP contains a single top-level directory, flatten it so the
    # workspace root contains the actual source files (matches git clone behavior).
    entries = list(workspace.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        nested = entries[0]
        for item in nested.iterdir():
            shutil.move(str(item), str(workspace / item.name))
        nested.rmdir()


def _copy_uploaded_files(scan, workspace: Path) -> None:
    """Copy the uploaded source_file into the sandboxed workspace."""
    if not scan.source_file:
        return

    source_path = Path(scan.source_file.path)
    destination = workspace / source_path.name
    shutil.copy2(source_path, destination)


def _dispatch_analyzer_chord(scan_id: str, languages: list) -> None:
    """Build and dispatch the Celery chord of analyzer stubs."""
    analyzers = get_analyzers_for_languages(languages)

    pipeline = chord(
        group(run_analyzer_task.s(scan_id, tool) for tool in analyzers),
        aggregate_results.s(scan_id),
    ).on_error(on_chord_error.s())

    pipeline.apply_async()


# ---------------------------------------------------------------------------
# Celery tasks
# ---------------------------------------------------------------------------

@shared_task(bind=True, max_retries=0)
def orchestrate_scan(self, scan_id: str) -> dict:
    """Orchestrate the full scan pipeline for a given scan ID.

    Steps:
      1. Clone / extract / copy files into workspace
      2. Detect languages
      3. Dispatch analyzer chord
    """
    from ..models import Scan  # noqa: PLC0415  (local import to avoid circular deps)

    workspace: Path | None = None

    try:
        scan = Scan.objects.get(id=scan_id)

        # Create workspace directory
        workspace = WORKSPACE_ROOT / str(scan_id)
        workspace.mkdir(parents=True, exist_ok=True)

        # ------------------------------------------------------------------
        # Step 1 — Clone / extract / copy
        # ------------------------------------------------------------------
        scan.status = "cloning"
        scan.save(update_fields=["status"])

        if scan.source_type == "git":
            # Re-validate DNS to prevent TOCTOU / DNS rebinding attacks
            from ..services.url_validator import revalidate_host_at_execution_time  # noqa: PLC0415
            revalidate_host_at_execution_time(scan.source_url)
            _clone_repo(scan.source_url, workspace)
        elif scan.source_type == "zip":
            _extract_zip(scan.source_file.path, workspace)
        elif scan.source_type == "files":
            _copy_uploaded_files(scan, workspace)

        # ------------------------------------------------------------------
        # Step 2 — Language detection
        # ------------------------------------------------------------------
        scan.status = "detecting"
        scan.save(update_fields=["status"])

        languages = detect_languages(workspace)

        scan.detected_languages = languages
        scan.workspace_path = str(workspace)
        scan.status = "scanning"
        scan.save(update_fields=["detected_languages", "workspace_path", "status"])

        # ------------------------------------------------------------------
        # Step 3 — Dispatch chord
        # ------------------------------------------------------------------
        _dispatch_analyzer_chord(str(scan_id), languages)

        return {"scan_id": scan_id, "status": "scanning", "languages": languages}

    except subprocess.TimeoutExpired:
        _fail_scan(scan_id, "Clone timed out", workspace)
        return {"scan_id": scan_id, "status": "failed"}

    except subprocess.CalledProcessError as exc:
        error_msg = (exc.stderr or str(exc))[:500]
        _fail_scan(scan_id, error_msg, workspace)
        return {"scan_id": scan_id, "status": "failed"}

    except Exception as exc:
        _fail_scan(scan_id, str(exc)[:500], workspace)
        raise


def _fail_scan(scan_id: str, error_message: str, workspace: Path | None) -> None:
    """Mark a scan as failed and clean up its workspace."""
    from ..models import Scan  # noqa: PLC0415

    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = "failed"
        scan.error_message = error_message
        scan.save(update_fields=["status", "error_message"])
    except Scan.DoesNotExist:
        pass

    if workspace and workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)


@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=10,
    autoretry_for=(subprocess.TimeoutExpired,),
    retry_backoff=True,
)
def run_analyzer_task(self, scan_id: str, tool_name: str) -> dict:
    """Run a real analyzer tool on the scan workspace.

    Wrapped in try/except so that an unexpected error returns an error dict
    rather than raising — a chord group task that raises an unhandled exception
    prevents the chord callback from firing (research Pitfall 2).

    Automatically retries up to 3 times (with exponential back-off) when the
    subprocess times out.  All failures are logged with the Celery task-id for
    easy traceability in production logs.
    """
    from ..models import Scan  # noqa: PLC0415
    from .analyzers import run_analyzer  # noqa: PLC0415

    try:
        scan = Scan.objects.get(id=scan_id)
        workspace = scan.workspace_path
        if not workspace:
            return {"tool": tool_name, "error": "No workspace", "findings": []}

        findings = run_analyzer(tool_name, workspace)
        return {"tool": tool_name, "error": None, "findings": findings}

    except subprocess.TimeoutExpired as exc:
        logger.warning(
            "Task %s: analyzer '%s' timed out (attempt %d/%d) — will retry",
            self.request.id,
            tool_name,
            self.request.retries + 1,
            self.max_retries,
        )
        raise  # autoretry_for=(subprocess.TimeoutExpired,) handles the retry

    except Exception as exc:  # noqa: BLE001
        logger.error(
            "Task %s: analyzer '%s' raised %s: %s",
            self.request.id,
            tool_name,
            type(exc).__name__,
            exc,
        )
        return {"tool": tool_name, "error": str(exc), "findings": []}


CVSS_BASE = {
    "critical": 9.5,  # CVSS 9.0-10.0
    "high": 7.5,      # CVSS 7.0-8.9
    "medium": 4.5,    # CVSS 4.0-6.9
    "low": 2.0,       # CVSS 0.1-3.9
    "info": 0.0,
}
SEVERITY_WEIGHT = {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}


@shared_task
def aggregate_results(tool_results: list, scan_id: str) -> dict:
    """Chord callback: aggregate analyzer results, create Finding objects, compute score."""
    from ..models import Finding, Scan  # noqa: PLC0415

    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = "aggregating"
        scan.save(update_fields=["status"])

        # Collect all findings from all tools
        all_findings = []
        for result in tool_results:
            if result and isinstance(result, dict):
                all_findings.extend(result.get("findings", []))

        from ..services.owasp_mapper import classify_finding  # noqa: PLC0415

        # Bulk create Finding objects
        finding_objects = []
        for f in all_findings:
            tool = f.get("tool", "")
            rule_id = f.get("rule_id", "")
            title = f.get("title", "")
            desc = f.get("description", "")
            owasp, confidence = classify_finding(tool, rule_id, title, desc)

            finding_objects.append(Finding(
                scan=scan,
                tool=tool,
                rule_id=rule_id,
                file_path=f.get("file_path", ""),
                line_start=f.get("line_start"),
                line_end=f.get("line_end"),
                code_snippet=f.get("code_snippet", ""),
                severity=f.get("severity", "info"),
                owasp_category=owasp,
                owasp_confidence=confidence,
                title=f.get("title", ""),
                description=f.get("description", ""),
            ))

        if finding_objects:
            Finding.objects.bulk_create(finding_objects)

        # ── Auto-detect false positives ──
        from ..services.false_positive_detector import is_false_positive  # noqa: PLC0415

        fp_ids = []
        for f_obj in finding_objects:
            if is_false_positive({
                "rule_id": f_obj.rule_id,
                "tool": f_obj.tool,
                "code_snippet": f_obj.code_snippet,
                "title": f_obj.title,
                "description": f_obj.description,
                "file_path": f_obj.file_path,
            }):
                fp_ids.append(f_obj.id)

        if fp_ids:
            Finding.objects.filter(id__in=fp_ids).update(status="false_positive")

        # Count severities (excluding false positives)
        real_findings = [f for f in finding_objects if f.id not in set(fp_ids)]
        total = len(real_findings)
        critical = sum(1 for f in real_findings if f.severity == "critical")
        high = sum(1 for f in real_findings if f.severity == "high")
        medium = sum(1 for f in real_findings if f.severity == "medium")
        low = sum(1 for f in real_findings if f.severity == "low")

        # Compute security score (100 = perfect, 0 = terrible)
        penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in real_findings)
        score = max(0.0, 100.0 - penalty)

        # Compute CVSS max score (worst individual finding)
        cvss_max = max(
            (CVSS_BASE.get(f.severity, 0.0) for f in real_findings),
            default=0.0,
        )

        scan.status = "completed"
        scan.total_findings = total
        scan.critical_count = critical
        scan.high_count = high
        scan.medium_count = medium
        scan.low_count = low
        scan.security_score = score
        scan.cvss_max_score = cvss_max
        scan.completed_at = timezone.now()
        scan.save(update_fields=[
            "status", "total_findings", "critical_count", "high_count",
            "medium_count", "low_count", "security_score", "cvss_max_score",
            "completed_at",
        ])

        return {"scan_id": scan_id, "status": "completed", "total_findings": total}

    except Exception as exc:  # noqa: BLE001
        return {"scan_id": scan_id, "error": str(exc)}


@shared_task
def on_chord_error(request, exc, traceback) -> None:
    """Fallback error handler for chord failures (research Pitfall 2).

    Called when the chord callback itself raises or when a group task raises
    an unhandled exception.  Marks the scan as failed with a descriptive
    error message.
    """
    from ..models import Scan  # noqa: PLC0415

    # request.args[1] is scan_id when called via aggregate_results.s(scan_id)
    # Attempt to extract scan_id from the request kwargs or args
    scan_id = None
    if request and hasattr(request, "kwargs") and request.kwargs:
        scan_id = request.kwargs.get("scan_id")
    if not scan_id and request and hasattr(request, "args") and request.args:
        # args may be (tool_results_list, scan_id) depending on chord signature
        args = request.args
        if len(args) >= 2:
            scan_id = args[1]
        elif len(args) == 1 and isinstance(args[0], str):
            scan_id = args[0]

    if not scan_id:
        return

    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = "failed"
        scan.error_message = f"Chord error: {exc!s}"[:500]
        scan.save(update_fields=["status", "error_message"])
    except Scan.DoesNotExist:
        pass
