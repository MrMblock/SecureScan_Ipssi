"""PWN module: technology fingerprinting via HTTP headers and HTML content."""

import logging
import re

import httpx

logger = logging.getLogger(__name__)

# Header patterns that reveal technology versions
HEADER_PATTERNS = {
    "x-powered-by": {
        "title": "Technology version disclosed via X-Powered-By",
        "severity": "medium",
        "rule_id": "x-powered-by-disclosure",
    },
    "server": {
        "title": "Server version disclosed via Server header",
        "severity": "low",
        "rule_id": "server-version-disclosure",
    },
    "x-aspnet-version": {
        "title": "ASP.NET version disclosed",
        "severity": "medium",
        "rule_id": "aspnet-version-disclosure",
    },
    "x-generator": {
        "title": "CMS/Generator disclosed via X-Generator header",
        "severity": "medium",
        "rule_id": "generator-disclosure",
    },
}

# Regex patterns to detect CMS/framework in HTML
HTML_FINGERPRINTS = [
    (re.compile(r'wp-content|wp-includes|wordpress', re.I), "WordPress", "medium"),
    (re.compile(r'sites/default/files|drupal', re.I), "Drupal", "medium"),
    (re.compile(r'Joomla!', re.I), "Joomla", "medium"),
    (re.compile(r'content="Laravel"', re.I), "Laravel", "low"),
    (re.compile(r'csrfmiddlewaretoken|__django', re.I), "Django", "low"),
    (re.compile(r'__next|_next/static', re.I), "Next.js", "low"),
    (re.compile(r'ng-version=', re.I), "Angular", "low"),
    (re.compile(r'data-reactroot|__NEXT_DATA__', re.I), "React", "low"),
    (re.compile(r'data-vue-|Vue\.js', re.I), "Vue.js", "low"),
    (re.compile(r'Shopify\.', re.I), "Shopify", "low"),
    (re.compile(r'X-Wix-', re.I), "Wix", "low"),
]


def run_fingerprint(target_url: str, crawl_result: dict | None = None) -> list[dict]:
    """Detect exposed technology information from headers and HTML content."""
    findings = []

    try:
        with httpx.Client(timeout=15, follow_redirects=True, verify=True) as client:
            resp = client.get(target_url)

            # Check response headers for version disclosure
            for header_name, info in HEADER_PATTERNS.items():
                value = resp.headers.get(header_name, "")
                if value and _has_version(value):
                    findings.append({
                        "tool": "pwn_fingerprint",
                        "rule_id": info["rule_id"],
                        "file_path": target_url,
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": f"{header_name}: {value}",
                        "severity": info["severity"],
                        "title": f"{info['title']}: {value}",
                        "description": (
                            f"The response header '{header_name}' discloses version information: "
                            f"'{value}'. Attackers can use this to find known vulnerabilities "
                            "for this specific version. Remove or obscure version information."
                        ),
                    })

            # Check HTML body for CMS/framework fingerprints
            body = resp.text[:50000]  # Only check first 50KB
            detected = set()
            for pattern, name, severity in HTML_FINGERPRINTS:
                if name in detected:
                    continue
                if pattern.search(body):
                    detected.add(name)
                    findings.append({
                        "tool": "pwn_fingerprint",
                        "rule_id": f"tech-detected-{name.lower().replace('.', '').replace(' ', '-')}",
                        "file_path": target_url,
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": f"Technology detected: {name}",
                        "severity": severity,
                        "title": f"Technology detected: {name}",
                        "description": (
                            f"The website appears to use {name}. While not a direct vulnerability, "
                            "technology disclosure helps attackers target specific exploits. "
                            "Ensure all components are up to date."
                        ),
                    })

    except httpx.HTTPError as exc:
        logger.error("Fingerprint HTTP error: %s", exc)
    except Exception as exc:  # noqa: BLE001
        logger.error("Fingerprint unexpected error: %s", exc)

    return findings


def _has_version(value: str) -> bool:
    """Check if a header value contains meaningful version information."""
    # Match patterns like "Apache/2.4.41", "PHP/8.1", "Express", etc.
    return bool(re.search(r'\d+\.\d+', value)) or len(value) > 2
