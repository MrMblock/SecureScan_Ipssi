from django.db import migrations

import apps.accounts.fields


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0003_encrypt_github_token"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="gemini_api_key",
            field=apps.accounts.fields.EncryptedCharField(blank=True, default="", max_length=512),
        ),
    ]
