"""DAST module: SQL Injection Testing (OWASP A05)."""

import logging
import re

import httpx

from ..crawler import CrawlResult

logger = logging.getLogger(__name__)

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    '" OR "1"="1',
    "1' OR '1'='1' /*",
    "' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
]

# SQL error patterns indicating injection success
SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning.*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"pg_exec\(\)", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"microsoft.*odbc.*driver", re.IGNORECASE),
    re.compile(r"oracle.*error", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"mysqli_", re.IGNORECASE),
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"SQLSTATE\[", re.IGNORECASE),
    re.compile(r"syntax error at or near", re.IGNORECASE),
]


def _detect_sql_error(response_text: str) -> str | None:
    """Check if the response contains SQL error messages."""
    for pattern in SQL_ERROR_PATTERNS:
        match = pattern.search(response_text)
        if match:
            return match.group()
    return None


def run_sqli(crawl_result: CrawlResult, target_url: str) -> list[dict]:
    """Test for SQL injection in forms and URL parameters."""
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
            for payload in SQLI_PAYLOADS:
                form_data = {}
                for inp in form.inputs:
                    name = inp.get("name")
                    if not name:
                        continue
                    inp_type = inp.get("type", "text")
                    if inp_type in ("submit", "button", "hidden", "checkbox", "radio"):
                        form_data[name] = inp.get("value", "")
                    else:
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

                error_match = _detect_sql_error(response.text)
                if error_match:
                    findings.append({
                        "tool": "dast_sqli",
                        "rule_id": "sql-injection-form",
                        "file_path": form.action,
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": (
                            f"Form on: {form.url}\n"
                            f"Action: {form.method} {form.action}\n"
                            f"Payload: {payload}\n"
                            f"Fields: {list(form_data.keys())}\n\n"
                            f"SQL error detected: {error_match}"
                        ),
                        "severity": "critical",
                        "title": f"SQL Injection via form on {form.url}",
                        "description": (
                            f"SQL injection payload '{payload}' triggered a database error: '{error_match}'. "
                            "This indicates user input is not properly sanitized before being included in SQL queries. "
                            "An attacker could extract, modify, or delete database contents."
                        ),
                    })
                    break  # One payload per form is enough

        # Test URL parameters
        from urllib.parse import urlparse, parse_qs, urlunparse

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
                for payload in SQLI_PAYLOADS[:3]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload

                    try:
                        response = client.get(url_base, params=test_params)
                    except (httpx.RequestError, httpx.HTTPStatusError):
                        continue

                    error_match = _detect_sql_error(response.text)
                    if error_match:
                        findings.append({
                            "tool": "dast_sqli",
                            "rule_id": "sql-injection-param",
                            "file_path": f"{url_base}?{param_name}=",
                            "line_start": None,
                            "line_end": None,
                            "code_snippet": (
                                f"URL: {url_base}\n"
                                f"Parameter: {param_name}\n"
                                f"Payload: {payload}\n\n"
                                f"SQL error detected: {error_match}"
                            ),
                            "severity": "critical",
                            "title": f"SQL Injection via URL parameter '{param_name}'",
                            "description": (
                                f"SQL injection payload in parameter '{param_name}' triggered a database error. "
                                "Use parameterized queries to prevent SQL injection."
                            ),
                        })
                        break
    finally:
        client.close()

    return findings
