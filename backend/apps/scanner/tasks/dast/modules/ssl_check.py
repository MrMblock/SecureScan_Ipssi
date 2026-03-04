"""DAST module: SSL/TLS Certificate and Protocol Check (OWASP A04)."""

import logging
import socket
import ssl
from urllib.parse import urlparse

from ..crawler import CrawlResult

logger = logging.getLogger(__name__)


def run_ssl(crawl_result: CrawlResult, target_url: str) -> list[dict]:
    """Check SSL/TLS configuration of the target."""
    findings = []
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "tool": "dast_ssl",
            "rule_id": "no-https",
            "file_path": target_url,
            "line_start": None,
            "line_end": None,
            "code_snippet": f"Target URL uses {parsed.scheme}:// instead of https://",
            "severity": "high",
            "title": "Website does not use HTTPS",
            "description": "The target website is served over unencrypted HTTP. All data transmitted is vulnerable to interception.",
        })
        return findings

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()

                # Check for weak protocols
                weak_protocols = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
                if protocol in weak_protocols:
                    findings.append({
                        "tool": "dast_ssl",
                        "rule_id": "weak-tls-protocol",
                        "file_path": target_url,
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": f"Negotiated protocol: {protocol}\nCipher: {cipher}",
                        "severity": "high",
                        "title": f"Weak TLS protocol: {protocol}",
                        "description": f"The server negotiated {protocol} which is considered insecure. Use TLS 1.2 or TLS 1.3.",
                    })

                # Check cipher suite
                if cipher:
                    cipher_name = cipher[0] if cipher else ""
                    weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5")
                    for weak in weak_ciphers:
                        if weak in cipher_name.upper():
                            findings.append({
                                "tool": "dast_ssl",
                                "rule_id": "weak-cipher",
                                "file_path": target_url,
                                "line_start": None,
                                "line_end": None,
                                "code_snippet": f"Cipher suite: {cipher_name}",
                                "severity": "high",
                                "title": f"Weak cipher suite: {cipher_name}",
                                "description": f"The cipher suite contains {weak} which is cryptographically weak.",
                            })
                            break

                # Check certificate expiry
                if cert:
                    import datetime

                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = ssl.cert_time_to_seconds(not_after)
                            expiry_dt = datetime.datetime.fromtimestamp(expiry, tz=datetime.timezone.utc)
                            now = datetime.datetime.now(tz=datetime.timezone.utc)
                            if expiry_dt < now:
                                findings.append({
                                    "tool": "dast_ssl",
                                    "rule_id": "expired-certificate",
                                    "file_path": target_url,
                                    "line_start": None,
                                    "line_end": None,
                                    "code_snippet": f"Certificate expired: {not_after}",
                                    "severity": "critical",
                                    "title": "SSL certificate has expired",
                                    "description": f"The SSL certificate expired on {not_after}. Expired certificates break HTTPS trust.",
                                })
                            elif (expiry_dt - now).days < 30:
                                findings.append({
                                    "tool": "dast_ssl",
                                    "rule_id": "expiring-certificate",
                                    "file_path": target_url,
                                    "line_start": None,
                                    "line_end": None,
                                    "code_snippet": f"Certificate expires: {not_after} ({(expiry_dt - now).days} days remaining)",
                                    "severity": "medium",
                                    "title": "SSL certificate expiring soon",
                                    "description": f"The SSL certificate expires on {not_after}. Renew it before expiry.",
                                })
                        except Exception:
                            pass

    except ssl.SSLCertVerificationError as exc:
        findings.append({
            "tool": "dast_ssl",
            "rule_id": "invalid-certificate",
            "file_path": target_url,
            "line_start": None,
            "line_end": None,
            "code_snippet": str(exc),
            "severity": "critical",
            "title": "Invalid SSL certificate",
            "description": f"SSL certificate verification failed: {exc}. The connection is not secure.",
        })
    except Exception as exc:
        logger.warning("SSL check failed for %s: %s", target_url, exc)

    return findings
