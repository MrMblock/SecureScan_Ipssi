from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0002_finding_fix_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="fix_pr_url",
            field=models.URLField(blank=True, default=""),
            preserve_default=False,
        ),
    ]
