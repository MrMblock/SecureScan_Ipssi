"""Real analyzer adapters — run security tools and parse their JSON output.

Each function takes a workspace path and returns a list of finding dicts
compatible with the Finding model fields.
"""

import json
import logging
import os
import re
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------

_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
_BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _rel_path(filepath: str, workspace: str) -> str:
    """Make path relative to workspace for cleaner display."""
    try:
        return str(Path(filepath).relative_to(workspace))
    except ValueError:
        return filepath


def _read_snippet(filepath: str, line_start: int | None, line_end: int | None, context: int = 8) -> str:
    """Read source lines from *filepath* around the given range.

    Returns up to *context* lines before/after the finding range.
    Falls back to '' if the file can't be read.
    """
    if not filepath or not line_start:
        return ""
    try:
        lines = Path(filepath).read_text(errors="replace").splitlines()
    except Exception:
        return ""
    start = max(0, line_start - 1 - context)
    end = min(len(lines), (line_end or line_start) + context)
    return "\n".join(lines[start:end])[:2000]


# ---------------------------------------------------------------------------
# HTML inline script extraction
# ---------------------------------------------------------------------------

_SCRIPT_TAG_RE = re.compile(
    r"<script[^>]*>(.*?)</script>",
    re.DOTALL | re.IGNORECASE,
)


def _extract_html_scripts(workspace: str) -> dict[str, str]:
    """Extract inline <script> blocks from HTML files into temporary .js files.

    Returns a mapping from generated .js path → original HTML path so we can
    remap findings back to the correct source file.
    """
    ws = Path(workspace)
    js_map: dict[str, str] = {}

    for html_file in list(ws.rglob("*.html")) + list(ws.rglob("*.htm")):
        try:
            content = html_file.read_text(errors="replace")
        except Exception:
            continue

        scripts = _SCRIPT_TAG_RE.findall(content)
        if not scripts:
            continue

        # Compute the line offset of each <script> block for accurate line numbers
        combined_parts = []
        for match in _SCRIPT_TAG_RE.finditer(content):
            # Number of newlines before this <script> tag = line offset
            offset = content[: match.start()].count("\n")
            script_body = match.group(1)
            # Prepend empty lines so line numbers in the .js match the .html
            combined_parts.append("\n" * offset + script_body)

        js_content = "\n".join(combined_parts)
        js_path = html_file.with_suffix(".inline.js")
        js_path.write_text(js_content)
        js_map[str(js_path)] = str(html_file)

    return js_map


def _cleanup_extracted_scripts(js_map: dict[str, str]) -> None:
    """Remove temporary .inline.js files."""
    for js_path in js_map:
        try:
            Path(js_path).unlink(missing_ok=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------

_CUSTOM_RULES = Path(__file__).resolve().parent.parent / "rules" / "dom_security.yaml"


def run_semgrep(workspace: str) -> list[dict]:
    """Run Semgrep with auto config + custom DOM rules on the workspace."""
    # Extract inline scripts from HTML files so Semgrep can analyze them
    js_map = _extract_html_scripts(workspace)

    cmd = ["semgrep", "scan", "--config", "auto"]
    if _CUSTOM_RULES.is_file():
        cmd += ["--config", str(_CUSTOM_RULES)]
    cmd += ["--json", "-q", str(workspace)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=300,
        )
        # Semgrep returns exit code 1 when findings exist, that's normal
        output = result.stdout
        if not output.strip():
            return []

        data = json.loads(output)
        findings = []
        for r in data.get("results", []):
            raw_path = r.get("path", "")
            # Remap .inline.js paths back to original HTML files
            display_path = js_map.get(raw_path, raw_path)
            line_start = r.get("start", {}).get("line")
            line_end = r.get("end", {}).get("line")
            # extra.lines requires Semgrep login in v1.x — read source directly
            snippet = r.get("extra", {}).get("lines", "")
            if not snippet or snippet == "requires login":
                snippet = _read_snippet(display_path, line_start, line_end)
            findings.append({
                "tool": "semgrep",
                "rule_id": r.get("check_id", ""),
                "file_path": _rel_path(display_path, workspace),
                "line_start": line_start,
                "line_end": line_end,
                "code_snippet": snippet[:2000],
                "severity": _SEMGREP_SEV.get(r.get("extra", {}).get("severity", ""), "info"),
                "title": r.get("check_id", "").split(".")[-1].replace("-", " ").title(),
                "description": r.get("extra", {}).get("message", ""),
            })
        return findings
    except Exception as exc:
        logger.warning("Semgrep failed: %s", exc)
        return []
    finally:
        _cleanup_extracted_scripts(js_map)


# ---------------------------------------------------------------------------
# Bandit (Python only)
# ---------------------------------------------------------------------------

def run_bandit(workspace: str) -> list[dict]:
    """Run Bandit on the workspace."""
    try:
        result = subprocess.run(
            ["bandit", "-r", "-f", "json", "-q", str(workspace)],
            capture_output=True, text=True, timeout=180,
        )
        output = result.stdout
        if not output.strip():
            return []

        data = json.loads(output)
        findings = []
        for r in data.get("results", []):
            findings.append({
                "tool": "bandit",
                "rule_id": r.get("test_id", ""),
                "file_path": _rel_path(r.get("filename", ""), workspace),
                "line_start": r.get("line_number"),
                "line_end": r.get("end_col_offset"),
                "code_snippet": (
                    _read_snippet(
                        r.get("filename", ""),
                        r.get("line_number"),
                        r.get("line_number"),
                    ) or r.get("code", "")[:2000]
                ),
                "severity": _BANDIT_SEV.get(r.get("issue_severity", ""), "info"),
                "title": r.get("test_name", ""),
                "description": r.get("issue_text", ""),
            })
        return findings
    except Exception as exc:
        logger.warning("Bandit failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# TruffleHog (secrets detection)
# ---------------------------------------------------------------------------

def run_trufflehog(workspace: str) -> list[dict]:
    """Run TruffleHog filesystem scan with JSON output."""
    try:
        result = subprocess.run(
            ["trufflehog", "filesystem", "--json", "--only-verified=false", str(workspace)],
            capture_output=True, text=True, timeout=180,
        )
        output = result.stdout
        if not output.strip():
            return []

        findings = []
        for line in output.strip().splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue

            source_meta = r.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            filepath = source_meta.get("file", "")
            line_num = source_meta.get("line")

            findings.append({
                "tool": "trufflehog",
                "rule_id": r.get("DetectorName", ""),
                "file_path": _rel_path(filepath, workspace),
                "line_start": line_num,
                "line_end": None,
                "code_snippet": r.get("Raw", "")[:500],
                "severity": "critical" if r.get("Verified") else "high",
                "title": f"Secret detected: {r.get('DetectorName', 'Unknown')}",
                "description": f"{'Verified' if r.get('Verified') else 'Unverified'} secret found by TruffleHog",
            })
        return findings
    except Exception as exc:
        logger.warning("TruffleHog failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# ESLint Security (JS only)
# ---------------------------------------------------------------------------

def run_eslint(workspace: str) -> list[dict]:
    """Run ESLint with security plugin on JS/TS files."""
    ws = Path(workspace)
    js_files = list(ws.rglob("*.js")) + list(ws.rglob("*.jsx")) + list(ws.rglob("*.ts")) + list(ws.rglob("*.tsx"))
    # Filter out node_modules
    js_files = [f for f in js_files if "node_modules" not in str(f)]
    if not js_files:
        return []

    try:
        if len(js_files) > 100:
            logger.warning(
                "ESLint: workspace has %d JS/TS files; analysing only the first 100. "
                "Files beyond this limit are skipped.",
                len(js_files),
            )
        file_args = [str(f) for f in js_files[:100]]
        result = subprocess.run(
            ["eslint", "--no-eslintrc",
             "--plugin", "security",
             "--rule", '{"security/detect-eval-with-expression": "warn", '
                       '"security/detect-non-literal-regexp": "warn", '
                       '"security/detect-non-literal-fs-filename": "warn", '
                       '"security/detect-non-literal-require": "warn", '
                       '"security/detect-object-injection": "warn", '
                       '"security/detect-possible-timing-attacks": "warn", '
                       '"security/detect-pseudoRandomBytes": "warn", '
                       '"security/detect-unsafe-regex": "warn", '
                       '"security/detect-buffer-noassert": "warn", '
                       '"security/detect-child-process": "warn", '
                       '"security/detect-disable-mustache-escape": "warn", '
                       '"security/detect-no-csrf-before-method-override": "warn", '
                       '"security/detect-new-buffer": "warn"}',
             "-f", "json"] + file_args,
            capture_output=True, text=True, timeout=120,
        )
        output = result.stdout
        if not output.strip():
            return []

        data = json.loads(output)
        findings = []
        for file_result in data:
            fpath = file_result.get("filePath", "")
            for msg in file_result.get("messages", []):
                if not msg.get("ruleId", "").startswith("security/"):
                    continue
                findings.append({
                    "tool": "eslint",
                    "rule_id": msg.get("ruleId", ""),
                    "file_path": _rel_path(fpath, workspace),
                    "line_start": msg.get("line"),
                    "line_end": msg.get("endLine"),
                    "code_snippet": (
                        _read_snippet(
                            fpath, msg.get("line"),
                            msg.get("endLine"),
                        ) or msg.get("source", "")[:2000]
                    ),
                    "severity": "medium" if msg.get("severity", 1) >= 2 else "low",
                    "title": msg.get("ruleId", "").replace("security/", "").replace("-", " ").title(),
                    "description": msg.get("message", ""),
                })
        return findings
    except Exception as exc:
        logger.warning("ESLint failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# npm audit (JS only)
# ---------------------------------------------------------------------------

def run_npm_audit(workspace: str) -> list[dict]:
    """Run npm audit if package.json + package-lock.json exist."""
    ws = Path(workspace)
    pkg_json = ws / "package.json"
    if not pkg_json.exists():
        return []

    # Remove potentially malicious .npmrc to prevent supply-chain attacks
    npmrc = ws / ".npmrc"
    if npmrc.exists():
        npmrc.unlink()

    # npm audit needs package-lock.json; generate if missing
    lock_file = ws / "package-lock.json"
    if not lock_file.exists():
        try:
            subprocess.run(
                ["npm", "install", "--package-lock-only", "--ignore-scripts",
                 "--no-optional", "--no-fund"],
                cwd=str(ws), capture_output=True, text=True, timeout=30,
                env={**os.environ, "NODE_ENV": "production"},
            )
        except Exception:
            return []

    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=str(ws), capture_output=True, text=True, timeout=60,
        )
        output = result.stdout
        if not output.strip():
            return []

        data = json.loads(output)
        findings = []

        # npm v7+ format with vulnerabilities dict
        vulns = data.get("vulnerabilities", {})
        for pkg_name, vuln in vulns.items():
            sev_raw = vuln.get("severity", "info")
            severity = sev_raw if sev_raw in ("critical", "high", "medium", "low") else "info"
            via = vuln.get("via", [])
            desc_parts = []
            for v in via:
                if isinstance(v, dict):
                    desc_parts.append(v.get("title", v.get("url", "")))
                elif isinstance(v, str):
                    desc_parts.append(v)

            findings.append({
                "tool": "npm_audit",
                "rule_id": f"npm-{pkg_name}",
                "file_path": "package.json",
                "line_start": None,
                "line_end": None,
                "code_snippet": "",
                "severity": severity,
                "title": f"Vulnerable dependency: {pkg_name}",
                "description": "; ".join(desc_parts)[:1000] if desc_parts else f"{pkg_name} has known vulnerabilities",
            })

        return findings
    except Exception as exc:
        logger.warning("npm audit failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# pip-audit (Python dependencies)
# ---------------------------------------------------------------------------

def run_pip_audit(workspace: str) -> list[dict]:
    """Run pip-audit if requirements.txt / pyproject.toml / Pipfile exists."""
    ws = Path(workspace)
    has_pip = (
        (ws / "requirements.txt").exists()
        or (ws / "pyproject.toml").exists()
        or (ws / "Pipfile").exists()
        or (ws / "setup.py").exists()
    )
    if not has_pip:
        return []

    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json", "--progress-spinner", "off", "-r", str(ws / "requirements.txt")]
            if (ws / "requirements.txt").exists()
            else ["pip-audit", "--format", "json", "--progress-spinner", "off"],
            cwd=str(ws),
            capture_output=True, text=True, timeout=120,
        )
        output = result.stdout
        if not output.strip():
            return []

        data = json.loads(output)
        findings = []
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                # Derive severity from description/alias text — pip-audit doesn't
                # expose CVSS scores in its JSON output, but the description and
                # CVE aliases often contain severity keywords.
                desc = vuln.get("description", "").lower()
                aliases = " ".join(vuln.get("aliases", [])).lower()
                text = desc + " " + aliases
                if "critical" in text:
                    sev = "critical"
                elif any(k in text for k in ("high", "remote code execution", " rce", "arbitrary code")):
                    sev = "high"
                elif any(k in text for k in ("medium", "moderate")):
                    sev = "medium"
                elif "low" in text:
                    sev = "low"
                else:
                    sev = "high"  # any known CVE without indication defaults to high
                findings.append({
                    "tool": "pip_audit",
                    "rule_id": vuln.get("id", ""),
                    "file_path": "requirements.txt",
                    "line_start": None,
                    "line_end": None,
                    "code_snippet": "",
                    "severity": sev,
                    "title": f"Vulnerable dependency: {dep.get('name', '')} {dep.get('version', '')}",
                    "description": vuln.get("description", vuln.get("id", "")),
                })
        return findings
    except FileNotFoundError:
        logger.info("pip-audit not installed, skipping")
        return []
    except Exception as exc:
        logger.warning("pip-audit failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Composer Audit (PHP dependencies)
# ---------------------------------------------------------------------------

def run_composer_audit(workspace: str) -> list[dict]:
    """Run composer audit if composer.json exists."""
    ws = Path(workspace)
    if not (ws / "composer.json").exists():
        return []

    try:
        result = subprocess.run(
            ["composer", "audit", "--format=json", "--no-interaction"],
            cwd=str(ws),
            capture_output=True, text=True, timeout=120,
        )
        output = result.stdout
        if not output.strip():
            return []

        data = json.loads(output)
        findings = []
        advisories_raw = data.get("advisories", {})
        advisory_list = (
            advisories_raw.values()
            if isinstance(advisories_raw, dict)
            else advisories_raw
        )
        for advisory in advisory_list:
            if isinstance(advisory, dict):
                pkg = advisory.get("packageName", "") or advisory.get("package", {}).get("name", "")
                title = advisory.get("title", advisory.get("cve", "Unknown vulnerability"))
                description = advisory.get("link", "") or advisory.get("url", "")
                findings.append({
                    "tool": "composer_audit",
                    "rule_id": advisory.get("cve", advisory.get("advisoryId", "")),
                    "file_path": "composer.json",
                    "line_start": None,
                    "line_end": None,
                    "code_snippet": "",
                    "severity": "high",
                    "title": f"Vulnerable dependency: {pkg} — {title}",
                    "description": description,
                })
        return findings
    except FileNotFoundError:
        logger.info("composer not installed, skipping")
        return []
    except Exception as exc:
        logger.warning("Composer audit failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

ANALYZER_MAP = {
    "semgrep": run_semgrep,
    "bandit": run_bandit,
    "trufflehog": run_trufflehog,
    "eslint": run_eslint,
    "npm_audit": run_npm_audit,
    "pip_audit": run_pip_audit,
    "composer_audit": run_composer_audit,
}


def run_analyzer(tool_name: str, workspace: str) -> list[dict]:
    """Run a single analyzer and return its findings."""
    func = ANALYZER_MAP.get(tool_name)
    if not func:
        logger.warning("Unknown analyzer: %s", tool_name)
        return []
    return func(workspace)
