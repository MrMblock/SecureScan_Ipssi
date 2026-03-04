"""DAST module: CORS Misconfiguration Check (OWASP A02)."""

import logging

import httpx

from ..crawler import CrawlResult

logger = logging.getLogger(__name__)

MALICIOUS_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


def run_cors(crawl_result: CrawlResult, target_url: str) -> list[dict]:
    """Check for CORS misconfigurations by sending crafted Origin headers."""
    findings = []
    tested_urls: set[str] = set()

    # Test the main URL + first few discovered endpoints
    urls_to_test = [target_url]
    for page in crawl_result.pages[:10]:
        if page["url"] not in tested_urls:
            urls_to_test.append(page["url"])

    client = httpx.Client(
        timeout=5.0,
        follow_redirects=True,
        verify=True,
        headers={"User-Agent": "SecureScan-DAST/1.0"},
    )

    try:
        for url in urls_to_test:
            if url in tested_urls:
                continue
            tested_urls.add(url)

            for origin in MALICIOUS_ORIGINS:
                try:
                    response = client.get(url, headers={"Origin": origin})
                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue

                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")

                # Check if origin is reflected
                if acao == origin or acao == "*":
                    severity = "high" if acac.lower() == "true" else "medium"

                    if acao == "*" and acac.lower() != "true":
                        severity = "medium"

                    findings.append({
                        "tool": "dast_cors",
                        "rule_id": "cors-misconfiguration",
                        "file_path": url,
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": (
                            f"Request: GET {url}\n"
                            f"Origin: {origin}\n\n"
                            f"Response:\n"
                            f"  Access-Control-Allow-Origin: {acao}\n"
                            f"  Access-Control-Allow-Credentials: {acac}"
                        ),
                        "severity": severity,
                        "title": "CORS misconfiguration: origin reflected or wildcard",
                        "description": (
                            f"The server reflects the Origin header '{origin}' in Access-Control-Allow-Origin"
                            f"{' with credentials allowed' if acac.lower() == 'true' else ''}. "
                            "This can allow malicious websites to make authenticated cross-origin requests."
                        ),
                    })
                    break  # One finding per URL is enough
    finally:
        client.close()

    return findings
