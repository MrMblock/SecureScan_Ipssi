import uuid

from django.conf import settings
from django.db import models


class Scan(models.Model):
    SOURCE_TYPE_CHOICES = [
        ("git", "Git URL"),
        ("zip", "ZIP File"),
        ("files", "Individual Files"),
        ("dast", "Live Website (DAST)"),
        ("pwn", "PWN Mon Site"),
    ]

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("cloning", "Cloning"),
        ("crawling", "Crawling"),
        ("detecting", "Detecting Languages"),
        ("scanning", "Scanning"),
        ("aggregating", "Aggregating Results"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scans",
        null=True,
        blank=True,
    )
    source_type = models.CharField(max_length=10, choices=SOURCE_TYPE_CHOICES)
    source_url = models.URLField(blank=True)
    source_file = models.FileField(upload_to="uploads/", blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    celery_task_id = models.CharField(max_length=255, blank=True)
    error_message = models.TextField(blank=True)
    workspace_path = models.CharField(max_length=500, blank=True)
    detected_languages = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    total_findings = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    security_score = models.FloatField(null=True, blank=True)
    cvss_max_score = models.FloatField(null=True, blank=True)
    progress = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Scan {self.id} [{self.status}]"


class Finding(models.Model):
    FINDING_STATUS_CHOICES = [
        ("open", "Open"),
        ("false_positive", "False Positive"),
        ("accepted_risk", "Accepted Risk"),
        ("fixed", "Fixed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    status = models.CharField(max_length=20, choices=FINDING_STATUS_CHOICES, default="open")
    tool = models.CharField(max_length=20)
    rule_id = models.CharField(max_length=255, blank=True)
    file_path = models.CharField(max_length=1000, blank=True)
    line_start = models.IntegerField(null=True, blank=True)
    line_end = models.IntegerField(null=True, blank=True)
    code_snippet = models.TextField(blank=True)
    severity = models.CharField(max_length=10, default="info")
    owasp_category = models.CharField(max_length=5, default="UNK")
    owasp_confidence = models.CharField(max_length=10, default="low")  # high / medium / low
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    raw_output = models.JSONField(default=dict)

    # AI auto-fix fields
    fixed_code = models.TextField(blank=True)
    fix_explanation = models.TextField(blank=True)
    fix_generated_at = models.DateTimeField(null=True, blank=True)
    fix_pr_url = models.URLField(blank=True)

    class Meta:
        ordering = ["-severity", "file_path", "line_start"]

    def __str__(self):
        return f"Finding [{self.tool}] {self.title} ({self.severity})"


class ScanReport(models.Model):
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name="report")
    pdf_file = models.FileField(upload_to="reports/", blank=True)
    github_pr_url = models.URLField(blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Report for Scan {self.scan_id}"
