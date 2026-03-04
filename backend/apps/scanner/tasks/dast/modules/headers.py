"""DAST module: HTTP Security Header Analysis (OWASP A02)."""

from ..crawler import CrawlResult

REQUIRED_HEADERS = {
    "content-security-policy": {
        "title": "Missing Content-Security-Policy header",
        "description": "The Content-Security-Policy (CSP) header helps prevent XSS, clickjacking, and other code injection attacks.",
        "severity": "medium",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options header",
        "description": "The X-Frame-Options header prevents clickjacking attacks by controlling whether the page can be embedded in frames.",
        "severity": "medium",
    },
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "description": "HSTS ensures browsers only connect via HTTPS, preventing protocol downgrade attacks and cookie hijacking.",
        "severity": "high",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options header",
        "description": "Without 'nosniff', browsers may MIME-sniff responses, potentially executing malicious content.",
        "severity": "low",
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy header",
        "description": "The Permissions-Policy header controls which browser features and APIs can be used on the page.",
        "severity": "low",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy header",
        "description": "Without Referrer-Policy, sensitive URLs may leak to third-party sites via the Referer header.",
        "severity": "low",
    },
}


def run_headers(crawl_result: CrawlResult, target_url: str) -> list[dict]:
    """Check for missing security headers on crawled pages."""
    findings = []
    checked_headers: set[str] = set()

    for page_url, headers in crawl_result.headers.items():
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, info in REQUIRED_HEADERS.items():
            if header_name in checked_headers:
                continue

            if header_name not in headers_lower:
                checked_headers.add(header_name)
                findings.append({
                    "tool": "dast_headers",
                    "rule_id": f"missing-{header_name}",
                    "file_path": page_url,
                    "line_start": None,
                    "line_end": None,
                    "code_snippet": f"Response headers from {page_url}:\n"
                                    + "\n".join(f"  {k}: {v}" for k, v in list(headers.items())[:15]),
                    "severity": info["severity"],
                    "title": info["title"],
                    "description": info["description"],
                })

    return findings
