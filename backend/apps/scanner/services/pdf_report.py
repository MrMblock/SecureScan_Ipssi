"""PDF/HTML report generation using WeasyPrint."""

from collections import defaultdict
from io import BytesIO

from django.template.loader import render_to_string
from django.utils import timezone
from weasyprint import HTML

from .owasp_mapper import OWASP_CATEGORIES, get_owasp_recommendation

TOOL_NAMES = {
    "semgrep": "Semgrep",
    "bandit": "Bandit",
    "trufflehog": "TruffleHog",
    "eslint": "ESLint Security",
    "npm_audit": "npm audit",
    "pip_audit": "pip-audit",
    "composer_audit": "Composer Audit",
}

# Ordered A01–A10
OWASP_ORDER = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]


def build_report_context(scan) -> dict:
    """Build the template context shared by both PDF and HTML report generation."""
    findings = list(scan.findings.all().order_by("owasp_category", "severity", "file_path"))

    # Project name
    if scan.source_type == "dast":
        project_name = scan.workspace_path or scan.source_url or "DAST Scan"
    elif scan.source_url:
        project_name = scan.source_url.rstrip("/").rstrip(".git").split("/")[-1]
    else:
        project_name = scan.source_type.upper() + " Upload"

    # Duration
    if scan.completed_at and scan.created_at:
        duration = int((scan.completed_at - scan.created_at).total_seconds())
    else:
        duration = 0

    # Languages
    langs = [l for l in (scan.detected_languages or []) if l != "any"]
    languages = ", ".join(l.capitalize() for l in langs) or "N/A"

    # --- OWASP overview (bar chart data) ---
    owasp_counts = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
    for f in findings:
        cat = f.owasp_category if f.owasp_category in OWASP_CATEGORIES else "UNK"
        if cat == "UNK":
            continue
        owasp_counts[cat]["total"] += 1
        if f.severity in ("critical", "high", "medium", "low"):
            owasp_counts[cat][f.severity] += 1

    max_total = max((c["total"] for c in owasp_counts.values()), default=1) or 1

    owasp_overview = []
    for code in OWASP_ORDER:
        counts = owasp_counts.get(code, {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
        total = counts["total"] or 1  # avoid div by zero in pct calc
        scale = (counts["total"] / max_total) * 100  # scale bar to max category
        owasp_overview.append({
            "code": code,
            "name": OWASP_CATEGORIES[code],
            "total": counts["total"],
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "critical_pct": (counts["critical"] / total) * scale if counts["total"] else 0,
            "high_pct": (counts["high"] / total) * scale if counts["total"] else 0,
            "medium_pct": (counts["medium"] / total) * scale if counts["total"] else 0,
            "low_pct": (counts["low"] / total) * scale if counts["total"] else 0,
        })

    # --- OWASP detailed findings grouped ---
    owasp_grouped = defaultdict(list)
    for f in findings:
        cat = f.owasp_category if f.owasp_category in OWASP_CATEGORIES else "UNK"
        owasp_grouped[cat].append(f)

    # Sort within each group: critical first
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for cat_findings in owasp_grouped.values():
        cat_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    owasp_findings = []
    for code in OWASP_ORDER:
        if code in owasp_grouped:
            owasp_findings.append({
                "code": code,
                "name": OWASP_CATEGORIES[code],
                "findings": owasp_grouped[code],
                "recommendation": get_owasp_recommendation(code),
            })
    # Add UNK at the end if any
    if "UNK" in owasp_grouped:
        owasp_findings.append({
            "code": "—",
            "name": "Uncategorized",
            "findings": owasp_grouped["UNK"],
            "recommendation": "",
        })

    # --- Tool summary ---
    tool_data = defaultdict(lambda: {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
    for f in findings:
        tool_data[f.tool]["total"] += 1
        if f.severity in tool_data[f.tool]:
            tool_data[f.tool][f.severity] += 1

    tool_summary = []
    for tool, counts in sorted(tool_data.items(), key=lambda x: x[1]["total"], reverse=True):
        tool_summary.append({"name": TOOL_NAMES.get(tool, tool), **counts})

    return {
        "scan": scan,
        "project_name": project_name,
        "languages": languages,
        "duration": duration,
        "generated_at": timezone.now(),
        "owasp_overview": owasp_overview,
        "owasp_findings": owasp_findings,
        "tool_summary": tool_summary,
    }


def render_report_html(scan) -> str:
    """Render the HTML report string for a scan."""
    context = build_report_context(scan)
    return render_to_string("scanner/report.html", context)


def generate_report_pdf(scan) -> bytes:
    """Generate a PDF security audit report for a scan and return PDF bytes."""
    html_string = render_report_html(scan)
    pdf_buffer = BytesIO()
    HTML(string=html_string).write_pdf(pdf_buffer)
    return pdf_buffer.getvalue()
