"""DAST module: Reflected XSS Testing (OWASP A05)."""

import logging
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

from ..crawler import CrawlResult

logger = logging.getLogger(__name__)

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
    "'-alert(1)-'",
]

# Unique marker to detect reflection
REFLECTION_MARKER = "SecureScan7x5s"


def run_xss(crawl_result: CrawlResult, target_url: str) -> list[dict]:
    """Test for reflected XSS in forms and URL parameters."""
    findings = []

    client = httpx.Client(
        timeout=5.0,
        follow_redirects=True,
        verify=True,
        headers={"User-Agent": "SecureScan-DAST/1.0"},
    )

    try:
        # Test forms
        for form in crawl_result.forms[:20]:
            for payload in XSS_PAYLOADS:
                form_data = {}
                for inp in form.inputs:
                    name = inp.get("name")
                    if not name:
                        continue
                    form_data[name] = payload

                if not form_data:
                    continue

                try:
                    if form.method == "POST":
                        response = client.post(form.action, data=form_data)
                    else:
                        response = client.get(form.action, params=form_data)
                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue

                # Check if payload is reflected in response
                if payload in response.text:
                    findings.append({
                        "tool": "dast_xss",
                        "rule_id": "reflected-xss-form",
                        "file_path": form.action,
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": (
                            f"Form on: {form.url}\n"
                            f"Action: {form.method} {form.action}\n"
                            f"Payload: {payload}\n"
                            f"Fields: {list(form_data.keys())}\n\n"
                            f"Payload reflected in response body"
                        ),
                        "severity": "high",
                        "title": f"Reflected XSS via form on {form.url}",
                        "description": (
                            f"The payload '{payload[:40]}...' submitted to {form.action} "
                            "is reflected unescaped in the response. An attacker could exploit "
                            "this to execute arbitrary JavaScript in victims' browsers."
                        ),
                    })
                    break  # One payload per form is enough

        # Test URL parameters
        tested_urls: set[str] = set()
        for page in crawl_result.pages[:15]:
            parsed = urlparse(page["url"])
            params = parse_qs(parsed.query)
            if not params:
                continue

            url_base = urlunparse(parsed._replace(query=""))
            if url_base in tested_urls:
                continue
            tested_urls.add(url_base)

            for param_name in params:
                test_payload = f"{REFLECTION_MARKER}<script>alert(1)</script>"
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = test_payload

                try:
                    response = client.get(url_base, params=test_params)
                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue

                if REFLECTION_MARKER in response.text and "<script>" in response.text:
                    findings.append({
                        "tool": "dast_xss",
                        "rule_id": "reflected-xss-param",
                        "file_path": f"{url_base}?{param_name}=",
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": (
                            f"URL: {url_base}\n"
                            f"Parameter: {param_name}\n"
                            f"Payload: {test_payload}\n\n"
                            f"Payload reflected in response body"
                        ),
                        "severity": "high",
                        "title": f"Reflected XSS via URL parameter '{param_name}'",
                        "description": (
                            f"The parameter '{param_name}' reflects user input unescaped. "
                            "An attacker could craft a malicious URL to execute JavaScript in victims' browsers."
                        ),
                    })
                    break  # One param per URL is enough
    finally:
        client.close()

    return findings
