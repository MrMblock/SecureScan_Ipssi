from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0003_finding_fix_pr_url"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="owasp_confidence",
            field=models.CharField(max_length=10, default="low"),
            preserve_default=False,
        ),
    ]
