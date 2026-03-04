from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0004_finding_status"),
        ("scanner", "0004_finding_owasp_confidence"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="cvss_max_score",
            field=models.FloatField(blank=True, null=True),
        ),
    ]
