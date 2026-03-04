"""PWN module: SSL/TLS analysis using sslyze."""

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def run_sslyze(target_url: str) -> list[dict]:
    """Analyse SSL/TLS configuration of the target. Returns standardised findings."""
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        return []

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # If the target is HTTP-only, flag it immediately
    if parsed.scheme == "http" and port == 80:
        return [{
            "tool": "pwn_sslyze",
            "rule_id": "no-https",
            "file_path": target_url,
            "line_start": None,
            "line_end": None,
            "code_snippet": f"Scheme: {parsed.scheme}",
            "severity": "high",
            "title": "No HTTPS — site served over plain HTTP",
            "description": (
                f"The target {target_url} does not use HTTPS. All traffic is transmitted "
                "in cleartext, making it vulnerable to eavesdropping and man-in-the-middle attacks."
            ),
        }]

    findings = []

    try:
        from sslyze import (  # noqa: PLC0415
            Scanner,
            ServerScanRequest,
            ServerNetworkLocation,
            ScanCommand,
        )

        location = ServerNetworkLocation(hostname=hostname, port=port)
        request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.HEARTBLEED,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([request])

        for result in scanner.get_results():
            # Check connectivity errors
            if result.connectivity_error_trace:
                logger.warning("sslyze connectivity error: %s", result.connectivity_error_trace)
                continue

            scan_results = result.scan_result

            # Deprecated protocols
            _check_deprecated_protocol(
                scan_results, "ssl_2_0_cipher_suites", "SSL 2.0", "critical", findings, target_url
            )
            _check_deprecated_protocol(
                scan_results, "ssl_3_0_cipher_suites", "SSL 3.0", "critical", findings, target_url
            )
            _check_deprecated_protocol(
                scan_results, "tls_1_0_cipher_suites", "TLS 1.0", "high", findings, target_url
            )
            _check_deprecated_protocol(
                scan_results, "tls_1_1_cipher_suites", "TLS 1.1", "high", findings, target_url
            )

            # Heartbleed
            heartbleed = getattr(scan_results, "heartbleed", None)
            if heartbleed and not heartbleed.error_reason:
                hb_result = heartbleed.result
                if hb_result and hb_result.is_vulnerable_to_heartbleed:
                    findings.append({
                        "tool": "pwn_sslyze",
                        "rule_id": "heartbleed",
                        "file_path": target_url,
                        "line_start": None,
                        "line_end": None,
                        "code_snippet": "Heartbleed (CVE-2014-0160) — VULNERABLE",
                        "severity": "critical",
                        "title": "Server vulnerable to Heartbleed (CVE-2014-0160)",
                        "description": (
                            "The server is vulnerable to the Heartbleed bug which allows "
                            "attackers to read server memory, potentially exposing private keys "
                            "and sensitive data."
                        ),
                    })

            # Certificate issues
            cert_info = getattr(scan_results, "certificate_info", None)
            if cert_info and not cert_info.error_reason:
                cert_result = cert_info.result
                if cert_result:
                    for deployment in cert_result.certificate_deployments:
                        if not deployment.verified_certificate_chain:
                            findings.append({
                                "tool": "pwn_sslyze",
                                "rule_id": "invalid-cert-chain",
                                "file_path": target_url,
                                "line_start": None,
                                "line_end": None,
                                "code_snippet": "Certificate chain validation failed",
                                "severity": "high",
                                "title": "Invalid or untrusted SSL certificate chain",
                                "description": (
                                    "The server's certificate chain could not be verified. "
                                    "This may indicate a self-signed certificate, expired certificate, "
                                    "or missing intermediate certificates."
                                ),
                            })

    except ImportError:
        logger.warning("sslyze not installed — skipping SSL/TLS analysis")
    except Exception as exc:  # noqa: BLE001
        logger.error("sslyze error: %s", exc)

    return findings


def _check_deprecated_protocol(
    scan_results, attr_name: str, proto_name: str, severity: str,
    findings: list, target_url: str,
) -> None:
    """Check if a deprecated TLS/SSL protocol is accepted and add a finding if so."""
    proto_result = getattr(scan_results, attr_name, None)
    if not proto_result or proto_result.error_reason:
        return

    result = proto_result.result
    if result and result.accepted_cipher_suites:
        cipher_names = [cs.cipher_suite.name for cs in result.accepted_cipher_suites[:5]]
        findings.append({
            "tool": "pwn_sslyze",
            "rule_id": f"deprecated-{proto_name.lower().replace(' ', '-').replace('.', '')}",
            "file_path": target_url,
            "line_start": None,
            "line_end": None,
            "code_snippet": f"{proto_name} accepted ciphers: {', '.join(cipher_names)}",
            "severity": severity,
            "title": f"Deprecated protocol {proto_name} supported",
            "description": (
                f"The server accepts connections using {proto_name}, which is deprecated "
                "and has known vulnerabilities. Disable this protocol and use TLS 1.2+ only."
            ),
        })
