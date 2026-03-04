"""DAST crawler — discovers pages, forms, parameters, and headers from a live website."""

import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

MAX_DEPTH = 3
MAX_PAGES = 100
REQUEST_TIMEOUT = 10.0


@dataclass
class FormInfo:
    url: str
    action: str
    method: str
    inputs: list[dict]


@dataclass
class CrawlResult:
    pages: list[dict] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    headers: dict[str, dict] = field(default_factory=dict)
    endpoints: list[str] = field(default_factory=list)
    site_title: str = ""


def _same_origin(base_url: str, url: str) -> bool:
    """Check if url belongs to the same origin as base_url."""
    base = urlparse(base_url)
    target = urlparse(url)
    return base.netloc == target.netloc


def _extract_links(soup: BeautifulSoup, page_url: str) -> list[str]:
    """Extract all same-origin links from a page."""
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        absolute = urljoin(page_url, href)
        # Strip fragment
        absolute = absolute.split("#")[0]
        if absolute and _same_origin(page_url, absolute):
            links.append(absolute)
    return links


def _extract_forms(soup: BeautifulSoup, page_url: str) -> list[FormInfo]:
    """Extract all forms from a page."""
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        action_url = urljoin(page_url, action) if action else page_url
        method = (form.get("method") or "get").upper()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })
        forms.append(FormInfo(url=page_url, action=action_url, method=method, inputs=inputs))
    return forms


def crawl(target_url: str) -> CrawlResult:
    """Crawl a website starting from target_url.

    Returns a CrawlResult with discovered pages, forms, headers, and endpoints.
    """
    result = CrawlResult()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(target_url, 0)]

    client = httpx.Client(
        timeout=REQUEST_TIMEOUT,
        follow_redirects=True,
        verify=True,
        headers={"User-Agent": "SecureScan-DAST/1.0"},
    )

    try:
        while queue and len(visited) < MAX_PAGES:
            url, depth = queue.pop(0)

            # Normalize URL
            url = url.split("#")[0]
            if url in visited:
                continue

            visited.add(url)

            try:
                response = client.get(url)
            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                logger.debug("Crawl error on %s: %s", url, exc)
                continue

            # Skip non-200 or non-HTML
            if response.status_code in (401, 403):
                logger.info("Access denied on %s (HTTP %d)", url, response.status_code)
                continue

            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type:
                continue

            # Detect access-blocked pages (200 OK but body says "not authorized")
            body_lower = response.text[:5000].lower()
            blocked_markers = [
                "not authorized",
                "access denied",
                "please log in",
                "please authenticate",
                "you need to authenticate",
                "ip address",
                "forbidden",
            ]
            if any(marker in body_lower for marker in blocked_markers):
                # Count real <a> links — a real page will have navigation
                link_count = body_lower.count("<a ")
                if link_count < 3:
                    logger.info("Page %s looks access-blocked, skipping", url)
                    continue

            # Store page info
            result.pages.append({
                "url": url,
                "status_code": response.status_code,
                "content_type": content_type,
            })

            # Store response headers per page
            result.headers[url] = dict(response.headers)

            # Add to endpoints
            result.endpoints.append(url)

            # Parse HTML
            try:
                soup = BeautifulSoup(response.text, "lxml")
            except Exception:
                soup = BeautifulSoup(response.text, "html.parser")

            # Extract site title from the first page
            if not result.site_title:
                title_tag = soup.find("title")
                if title_tag and title_tag.string:
                    result.site_title = title_tag.string.strip()[:200]

            # Extract forms
            forms = _extract_forms(soup, url)
            result.forms.extend(forms)

            # Extract and queue links
            if depth < MAX_DEPTH:
                links = _extract_links(soup, url)
                for link in links:
                    if link not in visited:
                        queue.append((link, depth + 1))
    finally:
        client.close()

    logger.info(
        "Crawl complete: %d pages, %d forms, %d endpoints",
        len(result.pages), len(result.forms), len(result.endpoints),
    )
    return result
