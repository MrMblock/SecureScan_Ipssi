"""PWN module: nmap port scanning and service detection."""

import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Ports that are dangerous to expose publicly
DANGEROUS_PORTS = {
    21: ("FTP", "critical"),
    23: ("Telnet", "critical"),
    445: ("SMB", "critical"),
    1433: ("MSSQL", "high"),
    1521: ("Oracle DB", "high"),
    3306: ("MySQL", "high"),
    3389: ("RDP", "high"),
    5432: ("PostgreSQL", "high"),
    5900: ("VNC", "high"),
    6379: ("Redis", "critical"),
    11211: ("Memcached", "high"),
    27017: ("MongoDB", "critical"),
    9200: ("Elasticsearch", "high"),
    2375: ("Docker API", "critical"),
    2376: ("Docker API", "critical"),
}


def run_nmap(target_url: str) -> list[dict]:
    """Run nmap against the target host. Returns standardised findings."""
    try:
        import nmap  # noqa: PLC0415
    except ImportError:
        logger.warning("python-nmap not installed — skipping nmap scan")
        return []

    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        return []

    findings = []

    try:
        nm = nmap.PortScanner()
        nm.scan(
            hosts=host,
            arguments="-sV --top-ports 1000 --script=vuln -T4 --open",
            timeout=120,
        )

        for scanned_host in nm.all_hosts():
            for proto in nm[scanned_host].all_protocols():
                ports = nm[scanned_host][proto].keys()
                for port in ports:
                    port_info = nm[scanned_host][proto][port]
                    state = port_info.get("state", "")
                    if state != "open":
                        continue

                    service = port_info.get("name", "unknown")
                    version = port_info.get("version", "")
                    product = port_info.get("product", "")
                    service_desc = f"{product} {version}".strip() or service

                    # Check for dangerous exposed ports
                    if port in DANGEROUS_PORTS:
                        svc_name, severity = DANGEROUS_PORTS[port]
                        findings.append({
                            "tool": "pwn_nmap",
                            "rule_id": f"dangerous-port-{port}",
                            "file_path": f"{host}:{port}",
                            "line_start": None,
                            "line_end": None,
                            "code_snippet": f"Port {port}/{proto} OPEN — {service_desc}",
                            "severity": severity,
                            "title": f"Dangerous port exposed: {port} ({svc_name})",
                            "description": (
                                f"Port {port} ({svc_name}) is publicly accessible on {host}. "
                                f"Service detected: {service_desc}. "
                                "This port should not be exposed to the internet as it may "
                                "allow unauthorized access or data exfiltration."
                            ),
                        })

                    # Parse NSE script results for vulnerabilities
                    script_results = port_info.get("script", {})
                    for script_name, output in script_results.items():
                        if not output or "ERROR" in str(output):
                            continue
                        # NSE vuln scripts typically contain VULNERABLE
                        output_str = str(output)
                        if "VULNERABLE" in output_str.upper() or "CVE-" in output_str.upper():
                            severity = "high"
                            if "CVE-" in output_str.upper():
                                severity = "critical"

                            findings.append({
                                "tool": "pwn_nmap",
                                "rule_id": f"nse-{script_name}",
                                "file_path": f"{host}:{port}",
                                "line_start": None,
                                "line_end": None,
                                "code_snippet": output_str[:500],
                                "severity": severity,
                                "title": f"NSE vulnerability: {script_name} on port {port}",
                                "description": (
                                    f"Nmap script '{script_name}' detected a vulnerability "
                                    f"on {host}:{port} ({service_desc}).\n\n{output_str[:1000]}"
                                ),
                            })

    except nmap.PortScannerError as exc:
        logger.error("nmap scan failed: %s", exc)
    except Exception as exc:  # noqa: BLE001
        logger.error("nmap unexpected error: %s", exc)

    return findings
