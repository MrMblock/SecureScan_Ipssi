from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0005_scan_cvss_max_score"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scan",
            name="source_type",
            field=models.CharField(
                choices=[
                    ("git", "Git URL"),
                    ("zip", "ZIP File"),
                    ("files", "Individual Files"),
                    ("dast", "Live Website (DAST)"),
                ],
                max_length=10,
            ),
        ),
        migrations.AlterField(
            model_name="scan",
            name="status",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("cloning", "Cloning"),
                    ("crawling", "Crawling"),
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
    ]
