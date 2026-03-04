"""Celery orchestrator for PWN Mon Site — full automated pentest pipeline.

Pipeline (sequential for linear 0→100% progress):
  1. Recon + Crawl        0→10%   — Crawler + tech fingerprint
  2. Port Scan           10→25%   — nmap
  3. SSL/TLS             25→35%   — sslyze
  4. Vuln Scan           35→70%   — nuclei
  5. Web App Test        70→95%   — DAST modules (headers, CORS, XSS, SQLi, dirs, redirect)
  6. Aggregation         95→100%  — aggregate findings, compute scores
"""

import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


# Phase definitions: (phase_key, label, start_percent, end_percent)
PHASES = [
    ("recon", "Recon & Crawl", 0, 10),
    ("nmap", "Port Scanning", 10, 25),
    ("ssl", "SSL/TLS Analysis", 25, 35),
    ("nuclei", "Vulnerability Scan", 35, 70),
    ("dast", "Web App Testing", 70, 95),
    ("aggregate", "Aggregating Results", 95, 100),
]


def _send_progress(scan_id: str, percent: int, phase: str, label: str, message: str, findings_so_far: int = 0):
    """Persist progress and push via WebSocket."""
    from ..models import Scan  # noqa: PLC0415

    progress_data = {
        "percent": percent,
        "phase": phase,
        "phase_label": label,
        "message": message,
        "findings_so_far": findings_so_far,
    }

    # Persist for polling fallback
    try:
        Scan.objects.filter(id=scan_id).update(progress=progress_data)
    except Exception:  # noqa: BLE001
        pass

    # Push via WebSocket
    try:
        from channels.layers import get_channel_layer  # noqa: PLC0415
        from asgiref.sync import async_to_sync  # noqa: PLC0415

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"scan_{scan_id}",
            {
                "type": "scan.progress",
                **progress_data,
            },
        )
    except Exception:  # noqa: BLE001
        pass


def _send_completed(scan_id: str, total_findings: int):
    """Notify WebSocket clients that the scan completed."""
    try:
        from channels.layers import get_channel_layer  # noqa: PLC0415
        from asgiref.sync import async_to_sync  # noqa: PLC0415

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"scan_{scan_id}",
            {
                "type": "scan.completed",
                "total_findings": total_findings,
            },
        )
    except Exception:  # noqa: BLE001
        pass


def _send_failed(scan_id: str, error: str):
    """Notify WebSocket clients that the scan failed."""
    try:
        from channels.layers import get_channel_layer  # noqa: PLC0415
        from asgiref.sync import async_to_sync  # noqa: PLC0415

        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"scan_{scan_id}",
            {
                "type": "scan.failed",
                "error": error,
            },
        )
    except Exception:  # noqa: BLE001
        pass


def _fail_pwn_scan(scan_id: str, error_message: str):
    """Mark a PWN scan as failed."""
    from ..models import Scan  # noqa: PLC0415

    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = "failed"
        scan.error_message = error_message
        scan.save(update_fields=["status", "error_message"])
    except Exception:  # noqa: BLE001
        pass

    _send_failed(scan_id, error_message)


@shared_task(bind=True, max_retries=0)
def orchestrate_pwn_scan(self, scan_id: str) -> dict:
    """Orchestrate the full PWN Mon Site pentest pipeline."""
    from ..models import Scan  # noqa: PLC0415

    all_findings = []

    try:
        scan = Scan.objects.get(id=scan_id)
        target_url = scan.source_url
        scan.status = "scanning"
        scan.save(update_fields=["status"])

        # Re-validate DNS to prevent TOCTOU / DNS rebinding attacks
        from ..services.url_validator import revalidate_host_at_execution_time  # noqa: PLC0415
        revalidate_host_at_execution_time(target_url)

        # ──────────────────────────────────────────────────
        # Phase 1: Recon & Crawl (0→10%)
        # ──────────────────────────────────────────────────
        _send_progress(scan_id, 0, "recon", "Recon & Crawl", "Starting reconnaissance...", 0)

        crawl_result = None
        crawl_data = None
        try:
            from .dast.crawler import crawl  # noqa: PLC0415

            _send_progress(scan_id, 3, "recon", "Recon & Crawl", "Crawling target website...", 0)
            crawl_result = crawl(target_url)

            if crawl_result and crawl_result.pages:
                scan.detected_languages = [f"{len(crawl_result.pages)} pages, {len(crawl_result.forms)} forms"]
                scan.workspace_path = crawl_result.site_title or ""
                scan.save(update_fields=["detected_languages", "workspace_path"])

                # Serialize for DAST modules later
                crawl_data = {
                    "pages": crawl_result.pages,
                    "forms": [
                        {"url": f.url, "action": f.action, "method": f.method, "inputs": f.inputs}
                        for f in crawl_result.forms
                    ],
                    "headers": crawl_result.headers,
                    "endpoints": crawl_result.endpoints,
                }
        except Exception as exc:  # noqa: BLE001
            logger.warning("Crawl phase failed (continuing): %s", exc)

        # Tech fingerprinting
        _send_progress(scan_id, 7, "recon", "Recon & Crawl", "Fingerprinting technologies...", 0)
        try:
            from .pwn.tech_fingerprint import run_fingerprint  # noqa: PLC0415

            fp_findings = run_fingerprint(target_url, crawl_data)
            all_findings.extend(fp_findings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Fingerprint phase failed (continuing): %s", exc)

        _send_progress(scan_id, 10, "recon", "Recon & Crawl", "Recon complete.", len(all_findings))

        # ──────────────────────────────────────────────────
        # Phase 2: Port Scan — nmap (10→25%)
        # ──────────────────────────────────────────────────
        _send_progress(scan_id, 10, "nmap", "Port Scanning", "Starting nmap scan...", len(all_findings))

        try:
            from .pwn.nmap_scanner import run_nmap  # noqa: PLC0415

            _send_progress(scan_id, 15, "nmap", "Port Scanning", "Scanning top 1000 ports...", len(all_findings))
            nmap_findings = run_nmap(target_url)
            all_findings.extend(nmap_findings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("nmap phase failed (continuing): %s", exc)

        _send_progress(scan_id, 25, "nmap", "Port Scanning", "Port scan complete.", len(all_findings))

        # ──────────────────────────────────────────────────
        # Phase 3: SSL/TLS — sslyze (25→35%)
        # ──────────────────────────────────────────────────
        _send_progress(scan_id, 25, "ssl", "SSL/TLS Analysis", "Analyzing SSL/TLS...", len(all_findings))

        try:
            from .pwn.sslyze_scanner import run_sslyze  # noqa: PLC0415

            _send_progress(scan_id, 30, "ssl", "SSL/TLS Analysis", "Checking protocols and ciphers...", len(all_findings))
            ssl_findings = run_sslyze(target_url)
            all_findings.extend(ssl_findings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("sslyze phase failed (continuing): %s", exc)

        _send_progress(scan_id, 35, "ssl", "SSL/TLS Analysis", "SSL/TLS analysis complete.", len(all_findings))

        # ──────────────────────────────────────────────────
        # Phase 4: Vuln Scan — nuclei (35→70%)
        # ──────────────────────────────────────────────────
        _send_progress(scan_id, 35, "nuclei", "Vulnerability Scan", "Starting nuclei scan...", len(all_findings))

        try:
            from .pwn.nuclei_scanner import run_nuclei  # noqa: PLC0415

            def nuclei_progress(findings_count):
                # Map nuclei progress to 35→70% range
                pct = min(70, 35 + int(findings_count * 0.5))
                _send_progress(
                    scan_id, pct, "nuclei", "Vulnerability Scan",
                    f"Found {findings_count} issues so far...",
                    len(all_findings) + findings_count,
                )

            nuclei_findings = run_nuclei(target_url, progress_callback=nuclei_progress)
            all_findings.extend(nuclei_findings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("nuclei phase failed (continuing): %s", exc)

        _send_progress(scan_id, 70, "nuclei", "Vulnerability Scan", "Nuclei scan complete.", len(all_findings))

        # ──────────────────────────────────────────────────
        # Phase 5: Web App Test — DAST modules (70→95%)
        # ──────────────────────────────────────────────────
        _send_progress(scan_id, 70, "dast", "Web App Testing", "Running DAST modules...", len(all_findings))

        if crawl_result and crawl_data:
            dast_modules = [
                ("headers", "apps.scanner.tasks.dast.modules.headers", "run_headers"),
                ("ssl_check", "apps.scanner.tasks.dast.modules.ssl_check", "run_ssl"),
                ("dir_bruteforce", "apps.scanner.tasks.dast.modules.dir_bruteforce", "run_dirs"),
                ("cors_check", "apps.scanner.tasks.dast.modules.cors_check", "run_cors"),
                ("xss_test", "apps.scanner.tasks.dast.modules.xss_test", "run_xss"),
                ("sqli_test", "apps.scanner.tasks.dast.modules.sqli_test", "run_sqli"),
                ("open_redirect", "apps.scanner.tasks.dast.modules.open_redirect", "run_redirect"),
            ]

            from .dast.crawler import CrawlResult as CrawlResultClass, FormInfo  # noqa: PLC0415

            cr = CrawlResultClass(
                pages=crawl_data["pages"],
                forms=[
                    FormInfo(url=f["url"], action=f["action"], method=f["method"], inputs=f["inputs"])
                    for f in crawl_data["forms"]
                ],
                headers=crawl_data["headers"],
                endpoints=crawl_data["endpoints"],
            )

            for i, (mod_name, mod_path, func_name) in enumerate(dast_modules):
                pct = 70 + int((i / len(dast_modules)) * 25)
                _send_progress(
                    scan_id, pct, "dast", "Web App Testing",
                    f"Running {mod_name}...", len(all_findings),
                )

                try:
                    import importlib  # noqa: PLC0415

                    module = importlib.import_module(mod_path)
                    func = getattr(module, func_name)
                    dast_findings = func(cr, target_url)
                    all_findings.extend(dast_findings)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("DAST module '%s' failed: %s", mod_name, exc)

        _send_progress(scan_id, 95, "dast", "Web App Testing", "DAST testing complete.", len(all_findings))

        # ──────────────────────────────────────────────────
        # Phase 6: Aggregation (95→100%)
        # ──────────────────────────────────────────────────
        _send_progress(scan_id, 95, "aggregate", "Aggregating Results", "Computing scores...", len(all_findings))

        _aggregate_pwn_results(scan_id, all_findings)

        scan.refresh_from_db()
        _send_progress(scan_id, 100, "aggregate", "Aggregating Results", "Scan complete!", scan.total_findings)
        _send_completed(scan_id, scan.total_findings)

        return {"scan_id": scan_id, "status": "completed", "total_findings": scan.total_findings}

    except Exception as exc:
        error_msg = str(exc)[:500]
        _fail_pwn_scan(scan_id, error_msg)
        logger.error("PWN scan %s failed: %s", scan_id, exc)
        raise


def _aggregate_pwn_results(scan_id: str, all_findings: list[dict]):
    """Create Finding objects and compute scan scores — mirrors aggregate_results logic."""
    from ..models import Finding, Scan  # noqa: PLC0415
    from ..services.owasp_mapper import classify_finding  # noqa: PLC0415

    scan = Scan.objects.get(id=scan_id)
    scan.status = "aggregating"
    scan.save(update_fields=["status"])

    SEVERITY_WEIGHT = {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}
    CVSS_BASE = {"critical": 9.5, "high": 7.5, "medium": 4.5, "low": 2.0, "info": 0.0}

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
            title=title,
            description=desc,
        ))

    if finding_objects:
        Finding.objects.bulk_create(finding_objects)

    # Auto-detect false positives
    try:
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
    except Exception:  # noqa: BLE001
        fp_ids = []

    # Compute scores
    real_findings = [f for f in finding_objects if f.id not in set(fp_ids)]
    total = len(real_findings)
    critical = sum(1 for f in real_findings if f.severity == "critical")
    high = sum(1 for f in real_findings if f.severity == "high")
    medium = sum(1 for f in real_findings if f.severity == "medium")
    low = sum(1 for f in real_findings if f.severity == "low")

    penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in real_findings)
    score = max(0.0, 100.0 - penalty)
    cvss_max = max((CVSS_BASE.get(f.severity, 0.0) for f in real_findings), default=0.0)

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
