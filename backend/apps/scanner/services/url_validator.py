import ipaddress
import socket
from urllib.parse import urlparse

import httpx
from rest_framework import serializers

# Private / reserved IP networks that must never be reached by the scanner
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0:0/96"),
]


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address falls in a blocked range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → block
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _check_host_not_private(hostname: str) -> None:
    """Resolve hostname and reject if any resolved IP is private/reserved."""
    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise serializers.ValidationError("Could not resolve hostname.")

    for family, _type, _proto, _canonname, sockaddr in addrinfos:
        ip = sockaddr[0]
        if _is_private_ip(ip):
            raise serializers.ValidationError(
                "URLs pointing to private or reserved IP addresses are not allowed."
            )


def validate_git_url(url: str) -> str:
    """Validate a Git repository URL.

    Checks:
    - Scheme must be https
    - URL must have a host
    - Resolved IPs must not be private/reserved (SSRF protection)
    - Repository must be reachable (HTTP HEAD check without following redirects,
      then validate redirect target before following)

    Returns the URL on success. Raises ValidationError on failure.
    """
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise serializers.ValidationError("Only https:// URLs are supported.")

    if not parsed.netloc:
        raise serializers.ValidationError("URL has no host.")

    # --- SSRF: resolve DNS and block private IPs ---
    hostname = parsed.hostname
    if not hostname:
        raise serializers.ValidationError("URL has no host.")
    _check_host_not_private(hostname)

    try:
        # First request without following redirects
        response = httpx.head(url, timeout=5.0, follow_redirects=False)

        # If redirect, validate the target before following
        if response.is_redirect:
            location = response.headers.get("location", "")
            if location:
                redirect_parsed = urlparse(location)
                redirect_host = redirect_parsed.hostname
                if redirect_host:
                    _check_host_not_private(redirect_host)
            # Now follow the redirect
            response = httpx.head(url, timeout=5.0, follow_redirects=True)

        if response.status_code == 404:
            raise serializers.ValidationError(
                "Repository not found. Check the URL and ensure it is public."
            )
        if response.status_code >= 500:
            raise serializers.ValidationError(
                "Git host returned a server error. Try again in a moment."
            )
    except serializers.ValidationError:
        raise
    except httpx.TimeoutException:
        raise serializers.ValidationError(
            "Could not reach the repository host (timeout)."
        )
    except httpx.RequestError as exc:
        raise serializers.ValidationError(
            f"Could not connect to repository host: {exc}"
        )

    return url


def validate_web_url(url: str) -> str:
    """Validate a web URL for DAST scanning.

    Same SSRF protections as validate_git_url but accepts any HTTPS website,
    not just Git repositories.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("https", "http"):
        raise serializers.ValidationError("Only http:// and https:// URLs are supported.")

    if not parsed.netloc:
        raise serializers.ValidationError("URL has no host.")

    hostname = parsed.hostname
    if not hostname:
        raise serializers.ValidationError("URL has no host.")
    _check_host_not_private(hostname)

    try:
        response = httpx.head(url, timeout=10.0, follow_redirects=False)

        if response.is_redirect:
            location = response.headers.get("location", "")
            if location:
                redirect_parsed = urlparse(location)
                redirect_host = redirect_parsed.hostname
                if redirect_host:
                    _check_host_not_private(redirect_host)
            response = httpx.head(url, timeout=10.0, follow_redirects=True)

        if response.status_code >= 500:
            raise serializers.ValidationError(
                "Target website returned a server error. Try again in a moment."
            )
    except serializers.ValidationError:
        raise
    except httpx.TimeoutException:
        raise serializers.ValidationError(
            "Could not reach the target website (timeout)."
        )
    except httpx.RequestError as exc:
        raise serializers.ValidationError(
            f"Could not connect to target website: {exc}"
        )

    return url


def revalidate_host_at_execution_time(url: str) -> None:
    """Re-check DNS resolution just before execution to prevent DNS rebinding.

    Call this from Celery tasks right before running git clone, nmap, nuclei,
    or any network operation — it defeats TOCTOU attacks where the DNS record
    is changed between validation (serializer) and execution (worker).

    Raises ValueError if the host now resolves to a private IP.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no host.")

    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")

    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        ip = sockaddr[0]
        if _is_private_ip(ip):
            raise ValueError(
                f"DNS rebinding detected: {hostname} now resolves to private IP {ip}. "
                "Scan aborted for security."
            )
