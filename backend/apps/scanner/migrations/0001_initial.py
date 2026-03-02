import django.conf
import django.db.models.deletion
import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(django.conf.settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Scan",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "source_type",
                    models.CharField(
                        choices=[
                            ("git", "Git URL"),
                            ("zip", "ZIP File"),
                            ("files", "Individual Files"),
                        ],
                        max_length=10,
                    ),
                ),
                ("source_url", models.URLField(blank=True)),
                (
                    "source_file",
                    models.FileField(blank=True, upload_to="uploads/"),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("cloning", "Cloning"),
                            ("detecting", "Detecting Languages"),
                            ("scanning", "Scanning"),
                            ("aggregating", "Aggregating Results"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("celery_task_id", models.CharField(blank=True, max_length=255)),
                ("error_message", models.TextField(blank=True)),
                ("workspace_path", models.CharField(blank=True, max_length=500)),
                ("detected_languages", models.JSONField(default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("total_findings", models.IntegerField(default=0)),
                ("critical_count", models.IntegerField(default=0)),
                ("high_count", models.IntegerField(default=0)),
                ("medium_count", models.IntegerField(default=0)),
                ("low_count", models.IntegerField(default=0)),
                ("security_score", models.FloatField(blank=True, null=True)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="scans",
                        to=django.conf.settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="Finding",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("tool", models.CharField(max_length=20)),
                ("rule_id", models.CharField(blank=True, max_length=255)),
                ("file_path", models.CharField(blank=True, max_length=1000)),
                ("line_start", models.IntegerField(blank=True, null=True)),
                ("line_end", models.IntegerField(blank=True, null=True)),
                ("code_snippet", models.TextField(blank=True)),
                ("severity", models.CharField(default="info", max_length=10)),
                ("owasp_category", models.CharField(default="UNK", max_length=5)),
                ("title", models.CharField(max_length=500)),
                ("description", models.TextField(blank=True)),
                ("raw_output", models.JSONField(default=dict)),
                (
                    "scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="findings",
                        to="scanner.scan",
                    ),
                ),
            ],
            options={
                "ordering": ["-severity", "file_path", "line_start"],
            },
        ),
        migrations.CreateModel(
            name="ScanReport",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("pdf_file", models.FileField(blank=True, upload_to="reports/")),
                ("github_pr_url", models.URLField(blank=True)),
                ("generated_at", models.DateTimeField(auto_now_add=True)),
                (
                    "scan",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="report",
                        to="scanner.scan",
                    ),
                ),
            ],
        ),
    ]
