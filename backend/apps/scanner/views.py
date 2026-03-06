from django.db.models import Avg, Count, Max, Sum
from django.http import HttpResponse
from rest_framework.decorators import api_view
from rest_framework.decorators import permission_classes as perm_classes
from rest_framework.generics import ListAPIView, ListCreateAPIView, RetrieveAPIView, RetrieveDestroyAPIView
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from .models import Finding, Scan
from .serializers import FindingSerializer, FindingUpdateSerializer, ScanCreateSerializer, ScanStatusSerializer


class FindingPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200


@api_view(["GET"])
def health(request):
    return Response({"status": "ok", "app": "scanner"})


@api_view(["GET"])
@perm_classes([IsAuthenticated])
def owasp_chart_data(request):
    """GET /api/scanner/owasp-chart/ — OWASP 2025 distribution (stacked by severity) for all user scans."""
    from django.db.models import Count  # noqa: PLC0415

    owasp_labels = {
        "A01": "A01 Access Control",
        "A02": "A02 Misconfiguration",
        "A03": "A03 Supply Chain",
        "A04": "A04 Cryptographic",
        "A05": "A05 Injection",
        "A06": "A06 Insecure Design",
        "A07": "A07 Auth Failures",
        "A08": "A08 Integrity",
        "A09": "A09 Logging",
        "A10": "A10 Exceptions",
    }

    counts = (
        Finding.objects
        .filter(scan__user=request.user, scan__status="completed", owasp_category__in=list(owasp_labels))
        .exclude(status="false_positive")
        .values("owasp_category", "severity")
        .annotate(count=Count("id"))
    )

    data: dict[str, dict] = {
        code: {"name": label, "critical": 0, "high": 0, "medium": 0, "low": 0}
        for code, label in owasp_labels.items()
    }
    for row in counts:
        cat = row["owasp_category"]
        sev = row["severity"]
        if sev in ("critical", "high", "medium", "low"):
            data[cat][sev] = row["count"]

    return Response(list(data.values()))


@api_view(["GET"])
@perm_classes([IsAuthenticated])
def dashboard_stats(request):
    """GET /api/scanner/stats/ — Aggregate stats for the current user's dashboard."""
    qs = Scan.objects.filter(user=request.user)

    completed = qs.filter(status="completed")
    aggregates = completed.aggregate(
        total_findings=Sum("total_findings"),
        total_critical=Sum("critical_count"),
        total_high=Sum("high_count"),
        total_medium=Sum("medium_count"),
        total_low=Sum("low_count"),
        avg_score=Avg("security_score"),
        max_cvss=Max("cvss_max_score"),
    )

    return Response({
        "total_scans": qs.count(),
        "completed_scans": completed.count(),
        "total_findings": aggregates["total_findings"] or 0,
        "total_critical": aggregates["total_critical"] or 0,
        "total_high": aggregates["total_high"] or 0,
        "total_medium": aggregates["total_medium"] or 0,
        "total_low": aggregates["total_low"] or 0,
        "avg_score": round(aggregates["avg_score"] or 0, 1),
        "max_cvss": aggregates["max_cvss"] or 0,
    })


@api_view(["GET"])
@perm_classes([IsAuthenticated])
def top_vulnerable_files(request):
    """GET /api/scanner/top-files/ — Top 5 most vulnerable files across user's scans."""
    files = (
        Finding.objects.filter(scan__user=request.user, scan__status="completed")
        .exclude(status="false_positive")
        .values("file_path")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    return Response(list(files))


class ScanCreateThrottle(ScopedRateThrottle):
    """Only throttle POST (scan creation), not GET (listing)."""
    scope = "scan_create"

    def allow_request(self, request, view):
        if request.method != "POST":
            return True
        return super().allow_request(request, view)


class ScanListCreateView(ListCreateAPIView):
    """GET  /api/scanner/scans/ — List current user's scans, newest first.
    POST /api/scanner/scans/ — Create a new scan job.
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    throttle_classes = [ScanCreateThrottle]

    def get_queryset(self):
        return Scan.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.request.method == "POST":
            return ScanCreateSerializer
        return ScanStatusSerializer

    def perform_create(self, serializer):
        instance = serializer.save(user=self.request.user, status="pending")

        if instance.source_type == "pwn":
            from .tasks.pwn_orchestrator import orchestrate_pwn_scan  # noqa: PLC0415

            result = orchestrate_pwn_scan.delay(str(instance.id))
        elif instance.source_type == "dast":
            from .tasks.dast_orchestrator import orchestrate_dast_scan  # noqa: PLC0415

            result = orchestrate_dast_scan.delay(str(instance.id))
        else:
            # Local import to avoid circular dependency between views and tasks
            from .tasks import orchestrate_scan  # noqa: PLC0415

            result = orchestrate_scan.delay(str(instance.id))

        instance.celery_task_id = result.id
        instance.save(update_fields=["celery_task_id"])


class ScanDetailView(RetrieveDestroyAPIView):
    """GET    /api/scanner/scans/<uuid>/ — Retrieve scan status and results.
    DELETE /api/scanner/scans/<uuid>/ — Delete a scan and all its findings.
    """

    serializer_class = ScanStatusSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Scan.objects.filter(user=self.request.user)


@api_view(["GET"])
@perm_classes([IsAuthenticated])
def scan_owasp_chart(request, scan_id):
    """GET /api/scanner/scans/<uuid>/owasp-chart/ — OWASP 2025 breakdown for a single scan."""
    owasp_labels = {
        "A01": "A01 Access Control",
        "A02": "A02 Misconfiguration",
        "A03": "A03 Supply Chain",
        "A04": "A04 Cryptographic",
        "A05": "A05 Injection",
        "A06": "A06 Insecure Design",
        "A07": "A07 Auth Failures",
        "A08": "A08 Integrity",
        "A09": "A09 Logging",
        "A10": "A10 Exceptions",
    }

    counts = (
        Finding.objects
        .filter(scan_id=scan_id, scan__user=request.user, owasp_category__in=list(owasp_labels))
        .exclude(status="false_positive")
        .values("owasp_category", "severity")
        .annotate(count=Count("id"))
    )

    data: dict[str, dict] = {
        code: {"name": label, "critical": 0, "high": 0, "medium": 0, "low": 0}
        for code, label in owasp_labels.items()
    }
    for row in counts:
        cat = row["owasp_category"]
        sev = row["severity"]
        if sev in ("critical", "high", "medium", "low"):
            data[cat][sev] = row["count"]

    # Only return categories that have at least one finding
    result = [v for v in data.values() if v["critical"] + v["high"] + v["medium"] + v["low"] > 0]
    return Response(result)


class FindingDetailView(RetrieveAPIView):
    """GET /api/scanner/findings/<uuid>/ — Retrieve a single finding."""

    serializer_class = FindingSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Finding.objects.filter(scan__user=self.request.user)


class FindingListView(ListAPIView):
    """GET /api/scanner/scans/<uuid>/findings/ — List findings for a scan.

    Supports ?page=N&page_size=50 pagination.
    Filters: ?severity=high|medium|low|critical  ?tool=semgrep  ?owasp=A05
    """

    serializer_class = FindingSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = FindingPagination

    def get_queryset(self):
        scan_id = self.kwargs["scan_id"]
        qs = Finding.objects.filter(scan_id=scan_id, scan__user=self.request.user)

        # Exclude false positives by default
        show_all = self.request.query_params.get("show_all", "").lower() in ("true", "1")
        if not show_all:
            qs = qs.exclude(status="false_positive")

        # Optional filters
        severity = self.request.query_params.get("severity")
        tool = self.request.query_params.get("tool")
        owasp = self.request.query_params.get("owasp")
        status = self.request.query_params.get("status")
        if severity:
            qs = qs.filter(severity=severity)
        if tool:
            qs = qs.filter(tool=tool)
        if owasp:
            qs = qs.filter(owasp_category=owasp)
        if status:
            qs = qs.filter(status=status)

        return qs


@api_view(["POST"])
@perm_classes([IsAuthenticated])
def generate_fix(request, finding_id):
    """POST /api/scanner/findings/<uuid>/fix/ — Generate AI fix for a finding."""
    try:
        finding = Finding.objects.select_related("scan").get(id=finding_id, scan__user=request.user)
    except Finding.DoesNotExist:
        return Response({"detail": "Finding not found."}, status=404)

    from .services.autofix import generate_fix as do_generate_fix  # noqa: PLC0415
    from .services.autofix import get_api_key_for_provider

    lang = request.data.get("lang") or request.query_params.get("lang", "en")

    # Resolve provider and API key from user profile
    profile = getattr(request.user, "profile", None)
    provider = request.data.get("provider") or (profile.ai_provider if profile else "gemini")
    api_key = request.headers.get("X-AI-API-Key", "") or request.headers.get("X-Gemini-API-Key", "")
    if not api_key and profile:
        keys = {
            "gemini_api_key": profile.gemini_api_key or "",
            "openai_api_key": profile.openai_api_key or "",
            "anthropic_api_key": profile.anthropic_api_key or "",
        }
        api_key = get_api_key_for_provider(provider, keys)

    try:
        force = request.data.get("force", False)
        result = do_generate_fix(finding, lang=lang, provider=provider, api_key=api_key, force=force)
    except ValueError as exc:
        return Response({"detail": str(exc)}, status=400)

    return Response(result)


@api_view(["POST"])
@perm_classes([IsAuthenticated])
def apply_fix(request, finding_id):
    """POST /api/scanner/findings/<uuid>/apply/ — Apply fix, push branch, create PR."""
    try:
        finding = Finding.objects.select_related("scan").get(id=finding_id, scan__user=request.user)
    except Finding.DoesNotExist:
        return Response({"detail": "Finding not found."}, status=404)

    # Récupère le token GitHub de l'utilisateur connecté via OAuth
    github_token = ""
    if request.user and request.user.is_authenticated:
        try:
            github_token = request.user.profile.github_access_token
        except Exception:
            github_token = ""

    from .services.apply_fix import apply_fix_and_create_pr  # noqa: PLC0415

    try:
        result = apply_fix_and_create_pr(finding, github_token=github_token)
    except ValueError as exc:
        return Response({"detail": str(exc)}, status=400)

    return Response(result)


@api_view(["GET"])
@perm_classes([IsAuthenticated])
def source_file(request, scan_id):
    """GET /api/scanner/scans/<uuid>/source/?path=<filepath> — Read full source file."""
    import os

    try:
        scan = Scan.objects.get(id=scan_id, user=request.user)
    except Scan.DoesNotExist:
        return Response({"detail": "Scan not found."}, status=404)

    file_path = request.query_params.get("path", "")
    if not file_path:
        return Response({"detail": "Missing 'path' parameter."}, status=400)

    workspace = scan.workspace_path
    if not workspace:
        return Response({"detail": "Workspace not available."}, status=404)

    full_path = os.path.join(workspace, file_path)
    # Prevent path traversal
    if not os.path.realpath(full_path).startswith(os.path.realpath(workspace)):
        return Response({"detail": "Invalid file path."}, status=400)

    if not os.path.isfile(full_path):
        return Response({"detail": "File not found."}, status=404)

    try:
        with open(full_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return Response({"detail": "Could not read file."}, status=500)

    return Response({"content": content, "path": file_path})


@api_view(["GET"])
@perm_classes([IsAuthenticated])
def download_report(request, scan_id):
    """GET /api/scanner/scans/<uuid>/report/pdf/ — Generate and download PDF report."""
    try:
        scan = Scan.objects.get(id=scan_id, user=request.user)
    except Scan.DoesNotExist:
        return Response({"detail": "Scan not found."}, status=404)

    if scan.status != "completed":
        return Response({"detail": "Scan is not completed yet."}, status=400)

    from .services.pdf_report import generate_report_pdf  # noqa: PLC0415

    pdf_bytes = generate_report_pdf(scan)

    # Derive filename
    if scan.source_url:
        name = scan.source_url.rstrip("/").rstrip(".git").split("/")[-1]
    else:
        name = "scan"
    filename = f"SecureScan-{name}-{scan.created_at.strftime('%Y%m%d')}.pdf"

    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@api_view(["GET"])
@perm_classes([IsAuthenticated])
def download_report_html(request, scan_id):
    """GET /api/scanner/scans/<uuid>/report/html/ — Download HTML report."""
    try:
        scan = Scan.objects.get(id=scan_id, user=request.user)
    except Scan.DoesNotExist:
        return Response({"detail": "Scan not found."}, status=404)

    if scan.status != "completed":
        return Response({"detail": "Scan is not completed yet."}, status=400)

    from .services.pdf_report import build_report_context, render_report_html  # noqa: PLC0415

    ctx = build_report_context(scan)
    html_string = render_report_html(scan)

    filename = f"SecureScan-{ctx['project_name']}-{scan.created_at.strftime('%Y%m%d')}.html"
    response = HttpResponse(html_string, content_type="text/html; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@api_view(["PATCH"])
@perm_classes([IsAuthenticated])
def update_finding_status(request, finding_id):
    """PATCH /api/scanner/findings/<uuid>/status/ — Update finding status."""
    try:
        finding = Finding.objects.select_related("scan").get(id=finding_id, scan__user=request.user)
    except Finding.DoesNotExist:
        return Response({"detail": "Finding not found."}, status=404)

    serializer = FindingUpdateSerializer(finding, data=request.data, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(FindingSerializer(finding).data)


@api_view(["GET"])
@perm_classes([IsAuthenticated])
def compare_scans(request):
    """GET /api/scanner/scans/compare/?scan1=<uuid>&scan2=<uuid> — Compare two scans."""
    scan1_id = request.query_params.get("scan1")
    scan2_id = request.query_params.get("scan2")

    if not scan1_id or not scan2_id:
        return Response({"detail": "Both scan1 and scan2 parameters are required."}, status=400)

    try:
        scan1 = Scan.objects.get(id=scan1_id, user=request.user, status="completed")
        scan2 = Scan.objects.get(id=scan2_id, user=request.user, status="completed")
    except Scan.DoesNotExist:
        return Response({"detail": "One or both scans not found or not completed."}, status=404)

    findings1 = {(f.rule_id, f.file_path): f for f in scan1.findings.exclude(status="false_positive")}
    findings2 = {(f.rule_id, f.file_path): f for f in scan2.findings.exclude(status="false_positive")}

    keys1 = set(findings1.keys())
    keys2 = set(findings2.keys())

    new_keys = keys2 - keys1
    fixed_keys = keys1 - keys2
    unchanged_keys = keys1 & keys2

    def serialize_finding(f):
        return {
            "id": str(f.id), "rule_id": f.rule_id, "file_path": f.file_path,
            "severity": f.severity, "title": f.title, "owasp_category": f.owasp_category,
            "tool": f.tool, "line_start": f.line_start, "status": f.status,
        }

    return Response({
        "scan1": ScanStatusSerializer(scan1).data,
        "scan2": ScanStatusSerializer(scan2).data,
        "delta": {
            "score_change": (scan2.security_score or 0) - (scan1.security_score or 0),
            "findings_change": scan2.total_findings - scan1.total_findings,
            "new_count": len(new_keys),
            "fixed_count": len(fixed_keys),
            "unchanged_count": len(unchanged_keys),
        },
        "new_findings": [serialize_finding(findings2[k]) for k in sorted(new_keys)],
        "fixed_findings": [serialize_finding(findings1[k]) for k in sorted(fixed_keys)],
        "unchanged_findings": [serialize_finding(findings2[k]) for k in sorted(unchanged_keys)],
    })
