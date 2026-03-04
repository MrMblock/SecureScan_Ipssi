"""DAST module: Open Redirect Testing (OWASP A01)."""

import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from ..crawler import CrawlResult

logger = logging.getLogger(__name__)

# Parameters commonly used for redirects
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnTo", "return_to", "next", "goto", "target", "destination", "dest",
    "redir", "out", "continue", "link", "forward", "ref", "callback",
]

EXTERNAL_URL = "https://evil.example.com/pwned"


def run_redirect(crawl_result: CrawlResult, target_url: str) -> list[dict]:
    """Test for open redirect vulnerabilities."""
    findings = []

    client = httpx.Client(
        timeout=5.0,
        follow_redirects=False,
        verify=True,
        headers={"User-Agent": "SecureScan-DAST/1.0"},
    )

    tested: set[str] = set()

    try:
        # Test existing URL parameters
        for page in crawl_result.pages[:20]:
            parsed = urlparse(page["url"])
            params = parse_qs(parsed.query)
            url_base = urlunparse(parsed._replace(query=""))

            for param_name in params:
                if param_name.lower() not in REDIRECT_PARAMS:
                    continue

                test_key = f"{url_base}:{param_name}"
                if test_key in tested:
                    continue
                tested.add(test_key)

                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = EXTERNAL_URL

                try:
                    response = client.get(url_base, params=test_params)
                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue

                if _is_redirect_to_external(response):
                    findings.append(_make_finding(url_base, param_name, page["url"]))

        # Test common redirect parameters on discovered pages
        for page in crawl_result.pages[:10]:
            page_url = page["url"]
            parsed = urlparse(page_url)
            url_base = urlunparse(parsed._replace(query=""))

            for param_name in REDIRECT_PARAMS[:8]:
                test_key = f"{url_base}:{param_name}"
                if test_key in tested:
                    continue
                tested.add(test_key)

                try:
                    response = client.get(url_base, params={param_name: EXTERNAL_URL})
                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue

                if _is_redirect_to_external(response):
                    findings.append(_make_finding(url_base, param_name, page_url))
    finally:
        client.close()

    return findings


def _is_redirect_to_external(response: httpx.Response) -> bool:
    """Check if the response redirects to an external URL."""
    if response.status_code not in (301, 302, 303, 307, 308):
        return False
    location = response.headers.get("location", "")
    return "evil.example.com" in location


def _make_finding(url_base: str, param_name: str, page_url: str) -> dict:
    return {
        "tool": "dast_redirect",
        "rule_id": "open-redirect",
        "file_path": f"{url_base}?{param_name}=",
        "line_start": None,
        "line_end": None,
        "code_snippet": (
            f"Page: {page_url}\n"
            f"Test: GET {url_base}?{param_name}={EXTERNAL_URL}\n\n"
            f"Server redirected to external URL"
        ),
        "severity": "medium",
        "title": f"Open redirect via parameter '{param_name}'",
        "description": (
            f"The parameter '{param_name}' on {url_base} allows redirecting users to arbitrary external URLs. "
            "An attacker could craft a phishing link that appears to come from a trusted domain."
        ),
    }
