from django.urls import path

from . import views

urlpatterns = [
    path("health/", views.health, name="scanner-health"),
    path("stats/", views.dashboard_stats, name="scanner-stats"),
    path("owasp-chart/", views.owasp_chart_data, name="scanner-owasp-chart"),
    path("top-files/", views.top_vulnerable_files, name="scanner-top-files"),
    path("scans/", views.ScanListCreateView.as_view(), name="scan-list-create"),
    path("scans/compare/", views.compare_scans, name="scan-compare"),
    path("scans/<uuid:pk>/", views.ScanDetailView.as_view(), name="scan-detail"),
    path("scans/<uuid:scan_id>/owasp-chart/", views.scan_owasp_chart, name="scan-owasp-chart"),
    path("scans/<uuid:scan_id>/findings/", views.FindingListView.as_view(), name="finding-list"),
    path("scans/<uuid:scan_id>/source/", views.source_file, name="scan-source-file"),
    path("scans/<uuid:scan_id>/report/pdf/", views.download_report, name="scan-report-pdf"),
    path("scans/<uuid:scan_id>/report/html/", views.download_report_html, name="scan-report-html"),
    path("findings/<uuid:pk>/", views.FindingDetailView.as_view(), name="finding-detail"),
    path("findings/<uuid:finding_id>/fix/", views.generate_fix, name="finding-fix"),
    path("findings/<uuid:finding_id>/apply/", views.apply_fix, name="finding-apply-fix"),
    path("findings/<uuid:finding_id>/status/", views.update_finding_status, name="finding-update-status"),
]
