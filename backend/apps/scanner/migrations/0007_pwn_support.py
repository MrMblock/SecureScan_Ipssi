from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0006_dast_support"),
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
                    ("pwn", "PWN Mon Site"),
                ],
                max_length=10,
            ),
        ),
        migrations.AddField(
            model_name="scan",
            name="progress",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
