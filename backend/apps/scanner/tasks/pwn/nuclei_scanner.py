"""PWN module: nuclei vulnerability scanner with streaming progress."""

import json
import logging
import subprocess
from typing import Callable

logger = logging.getLogger(__name__)

# Severity mapping from nuclei to our format
NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
    "unknown": "low",
}


def run_nuclei(target_url: str, progress_callback: Callable | None = None) -> list[dict]:
    """Run nuclei against the target URL with streaming JSON output.

    Args:
        target_url: The URL to scan.
        progress_callback: Optional callback(current, total) for progress reporting.

    Returns:
        List of standardised finding dicts.
    """
    findings = []

    try:
        proc = subprocess.Popen(
            [
                "nuclei",
                "-u", target_url,
                "-jsonl",
                "-silent",
                "-rate-limit", "100",
                "-bulk-size", "50",
                "-concurrency", "25",
                "-timeout", "7",
                "-retries", "0",
                "-severity", "critical,high,medium,low",
                "-exclude-type", "dns",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        line_count = 0
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue

            line_count += 1
            finding = _parse_nuclei_result(result)
            if finding:
                findings.append(finding)

            if progress_callback and line_count % 5 == 0:
                progress_callback(len(findings))

        proc.wait(timeout=120)

        if progress_callback:
            progress_callback(len(findings))

    except FileNotFoundError:
        logger.warning("nuclei binary not found — skipping nuclei scan")
    except subprocess.TimeoutExpired:
        logger.error("nuclei scan timed out after 120s")
        if proc:
            proc.kill()
    except Exception as exc:  # noqa: BLE001
        logger.error("nuclei unexpected error: %s", exc)

    return findings


def _parse_nuclei_result(result: dict) -> dict | None:
    """Parse a single nuclei JSONL result into a standardised finding."""
    template_id = result.get("template-id", result.get("templateID", ""))
    info = result.get("info", {})
    name = info.get("name", template_id)
    severity = info.get("severity", "low")
    description = info.get("description", "")
    matched_at = result.get("matched-at", result.get("matched", ""))
    matcher_name = result.get("matcher-name", result.get("matcher_name", ""))
    extracted = result.get("extracted-results", [])

    nuclei_severity = NUCLEI_SEVERITY_MAP.get(severity.lower(), "low")

    snippet_parts = []
    if matched_at:
        snippet_parts.append(f"Matched at: {matched_at}")
    if matcher_name:
        snippet_parts.append(f"Matcher: {matcher_name}")
    if extracted:
        snippet_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")

    return {
        "tool": "pwn_nuclei",
        "rule_id": template_id,
        "file_path": matched_at or "",
        "line_start": None,
        "line_end": None,
        "code_snippet": "\n".join(snippet_parts) or f"Template: {template_id}",
        "severity": nuclei_severity,
        "title": name,
        "description": description or f"Nuclei template {template_id} matched at {matched_at}",
    }
