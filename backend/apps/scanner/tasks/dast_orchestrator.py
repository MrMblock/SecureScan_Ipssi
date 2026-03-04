"""Celery orchestrator for DAST (Dynamic Application Security Testing) scans.

Pipeline:
  1. Crawl the target website
  2. Run all DAST modules in parallel via Celery chord
  3. Aggregate results (reuses existing aggregate_results)
"""

import logging

from celery import chord, group, shared_task

logger = logging.getLogger(__name__)


DAST_MODULES = [
    "headers",
    "ssl_check",
    "dir_bruteforce",
    "cors_check",
    "xss_test",
    "sqli_test",
    "open_redirect",
]


@shared_task(bind=True, max_retries=0)
def orchestrate_dast_scan(self, scan_id: str) -> dict:
    """Orchestrate a full DAST scan pipeline."""
    from ..models import Scan  # noqa: PLC0415

    try:
        scan = Scan.objects.get(id=scan_id)

        # Step 1 — Crawl
        scan.status = "crawling"
        scan.save(update_fields=["status"])

        # Re-validate DNS to prevent TOCTOU / DNS rebinding attacks
        from ..services.url_validator import revalidate_host_at_execution_time  # noqa: PLC0415
        revalidate_host_at_execution_time(scan.source_url)

        from .dast.crawler import crawl  # noqa: PLC0415

        crawl_result = crawl(scan.source_url)

        # Fail early if the crawler found nothing useful
        if not crawl_result.pages:
            _fail_dast_scan(
                scan_id,
                f"Could not crawl {scan.source_url} — the site returned no HTML content. "
                "It may require authentication, block automated requests, or be unreachable.",
            )
            return {"scan_id": scan_id, "status": "failed"}

        # Store discovered info + site title for display
        scan.detected_languages = [f"{len(crawl_result.pages)} pages, {len(crawl_result.forms)} forms"]
        scan.workspace_path = crawl_result.site_title or ""
        scan.save(update_fields=["detected_languages", "workspace_path"])

        # Step 2 — Run DAST modules in parallel
        scan.status = "scanning"
        scan.save(update_fields=["status"])

        from .orchestrator import aggregate_results, on_chord_error  # noqa: PLC0415

        # Serialize crawl_result for Celery
        crawl_data = {
            "pages": crawl_result.pages,
            "forms": [
                {
                    "url": f.url,
                    "action": f.action,
                    "method": f.method,
                    "inputs": f.inputs,
                }
                for f in crawl_result.forms
            ],
            "headers": crawl_result.headers,
            "endpoints": crawl_result.endpoints,
        }

        pipeline = chord(
            group(
                run_dast_module.s(scan_id, module_name, crawl_data, scan.source_url)
                for module_name in DAST_MODULES
            ),
            aggregate_results.s(scan_id),
        ).on_error(on_chord_error.s())

        pipeline.apply_async()

        return {"scan_id": scan_id, "status": "scanning", "pages_found": len(crawl_result.pages)}

    except Exception as exc:
        _fail_dast_scan(scan_id, str(exc)[:500])
        raise


def _fail_dast_scan(scan_id: str, error_message: str) -> None:
    """Mark a DAST scan as failed."""
    from ..models import Scan  # noqa: PLC0415

    try:
        scan = Scan.objects.get(id=scan_id)
        scan.status = "failed"
        scan.error_message = error_message
        scan.save(update_fields=["status", "error_message"])
    except Scan.DoesNotExist:
        pass


@shared_task(bind=True, max_retries=1, default_retry_delay=5)
def run_dast_module(self, scan_id: str, module_name: str, crawl_data: dict, target_url: str) -> dict:
    """Run a single DAST module and return findings."""
    from .dast.crawler import CrawlResult, FormInfo  # noqa: PLC0415

    try:
        # Reconstruct CrawlResult from serialized data
        crawl_result = CrawlResult(
            pages=crawl_data["pages"],
            forms=[
                FormInfo(
                    url=f["url"],
                    action=f["action"],
                    method=f["method"],
                    inputs=f["inputs"],
                )
                for f in crawl_data["forms"]
            ],
            headers=crawl_data["headers"],
            endpoints=crawl_data["endpoints"],
        )

        # Import and run the module
        module_map = {
            "headers": "apps.scanner.tasks.dast.modules.headers",
            "ssl_check": "apps.scanner.tasks.dast.modules.ssl_check",
            "dir_bruteforce": "apps.scanner.tasks.dast.modules.dir_bruteforce",
            "cors_check": "apps.scanner.tasks.dast.modules.cors_check",
            "xss_test": "apps.scanner.tasks.dast.modules.xss_test",
            "sqli_test": "apps.scanner.tasks.dast.modules.sqli_test",
            "open_redirect": "apps.scanner.tasks.dast.modules.open_redirect",
        }

        func_map = {
            "headers": "run_headers",
            "ssl_check": "run_ssl",
            "dir_bruteforce": "run_dirs",
            "cors_check": "run_cors",
            "xss_test": "run_xss",
            "sqli_test": "run_sqli",
            "open_redirect": "run_redirect",
        }

        import importlib

        module = importlib.import_module(module_map[module_name])
        func = getattr(module, func_map[module_name])
        findings = func(crawl_result, target_url)

        return {"tool": f"dast_{module_name.split('_')[0] if '_' in module_name else module_name}", "error": None, "findings": findings}

    except Exception as exc:  # noqa: BLE001
        logger.error("DAST module '%s' failed: %s", module_name, exc)
        return {"tool": f"dast_{module_name}", "error": str(exc), "findings": []}
