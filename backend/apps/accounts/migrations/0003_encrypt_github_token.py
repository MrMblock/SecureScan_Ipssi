"""Data migration: encrypt existing plaintext GitHub tokens."""

from django.db import migrations


def encrypt_existing_tokens(apps, schema_editor):
    """Re-save all profiles with a non-empty token so get_prep_value encrypts them."""
    UserProfile = apps.get_model("accounts", "UserProfile")
    for profile in UserProfile.objects.exclude(github_access_token=""):
        # Simply re-saving triggers EncryptedCharField.get_prep_value
        profile.save(update_fields=["github_access_token"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0002_userprofile_avatar"),
    ]

    operations = [
        migrations.RunPython(encrypt_existing_tokens, noop),
    ]
