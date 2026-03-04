from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0003_finding_fix_pr_url"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="status",
            field=models.CharField(
                choices=[
                    ("open", "Open"),
                    ("false_positive", "False Positive"),
                    ("accepted_risk", "Accepted Risk"),
                    ("fixed", "Fixed"),
                ],
                default="open",
                max_length=20,
            ),
        ),
    ]
