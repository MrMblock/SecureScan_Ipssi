from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="fixed_code",
            field=models.TextField(blank=True, default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="finding",
            name="fix_explanation",
            field=models.TextField(blank=True, default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="finding",
            name="fix_generated_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
