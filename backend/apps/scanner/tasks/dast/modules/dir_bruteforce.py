"""DAST module: Directory/File Bruteforce (OWASP A01)."""

import logging
from urllib.parse import urljoin

import httpx

from ..crawler import CrawlResult

logger = logging.getLogger(__name__)

# Common sensitive paths to check
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.htaccess",
    "/.htpasswd",
    "/admin/",
    "/admin/login/",
    "/wp-admin/",
    "/wp-login.php",
    "/administrator/",
    "/phpmyadmin/",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/backup/",
    "/backup.sql",
    "/backup.zip",
    "/database.sql",
    "/dump.sql",
    "/config.php",
    "/config.yml",
    "/config.json",
    "/wp-config.php",
    "/web.config",
    "/.well-known/security.txt",
    "/api/",
    "/api/v1/",
    "/api/docs",
    "/swagger.json",
    "/swagger-ui/",
    "/graphql",
    "/debug/",
    "/trace",
    "/elmah.axd",
    "/console/",
]

# Paths that, if found accessible, are security-critical
CRITICAL_PATHS = {"/.env", "/.git/config", "/.git/HEAD", "/.htpasswd", "/backup.sql", "/database.sql", "/dump.sql"}
HIGH_PATHS = {"/phpinfo.php", "/server-status", "/server-info", "/wp-config.php", "/debug/", "/console/", "/elmah.axd"}


def run_dirs(crawl_result: CrawlResult, target_url: str) -> list[dict]:
    """Test for exposed sensitive directories and files."""
    findings = []

    client = httpx.Client(
        timeout=5.0,
        follow_redirects=True,
        verify=True,
        headers={"User-Agent": "SecureScan-DAST/1.0"},
    )

    try:
        for path in SENSITIVE_PATHS:
            url = urljoin(target_url, path)
            try:
                response = client.get(url)
            except (httpx.RequestError, httpx.HTTPStatusError):
                continue

            # Only flag 200 OK responses that have meaningful content
            if response.status_code == 200 and len(response.content) > 0:
                # Skip generic error pages (simple heuristic)
                text_lower = response.text[:500].lower()
                if "404" in text_lower and "not found" in text_lower:
                    continue

                if path in CRITICAL_PATHS:
                    severity = "critical"
                elif path in HIGH_PATHS:
                    severity = "high"
                else:
                    severity = "medium"

                # Lower severity for non-sensitive informational paths
                if path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
                    severity = "info"
                    continue  # Skip purely informational findings

                snippet = response.text[:300].replace("\n", "\n  ")
                findings.append({
                    "tool": "dast_dirs",
                    "rule_id": f"exposed-path-{path.strip('/').replace('/', '-')}",
                    "file_path": url,
                    "line_start": None,
                    "line_end": None,
                    "code_snippet": f"GET {url} → {response.status_code}\nResponse preview:\n  {snippet}",
                    "severity": severity,
                    "title": f"Exposed sensitive path: {path}",
                    "description": f"The path {path} is accessible and returned HTTP {response.status_code}. "
                                   "This may expose sensitive configuration, backups, or administrative interfaces.",
                })
    finally:
        client.close()

    return findings
