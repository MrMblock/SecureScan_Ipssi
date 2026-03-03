from django.contrib import admin

from .models import Finding, Scan


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ["id", "source_type", "status", "created_at", "total_findings"]
    list_filter = ["status", "source_type"]
    readonly_fields = ["id", "created_at", "completed_at"]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ["id", "scan", "tool", "severity", "owasp_category", "title"]
    list_filter = ["tool", "severity", "owasp_category"]
