from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.accounts.fields import EncryptedCharField


class UserProfile(models.Model):
    AI_PROVIDER_CHOICES = [
        ("gemini", "Google Gemini"),
        ("openai", "OpenAI"),
        ("anthropic", "Anthropic Claude"),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    avatar = models.ImageField(upload_to="avatars/", blank=True, default="")
    github_access_token = EncryptedCharField(max_length=512, blank=True, default="")
    github_login = models.CharField(max_length=150, blank=True, default="")
    ai_provider = models.CharField(max_length=20, choices=AI_PROVIDER_CHOICES, default="gemini")
    gemini_api_key = EncryptedCharField(max_length=512, blank=True, default="")
    openai_api_key = EncryptedCharField(max_length=512, blank=True, default="")
    anthropic_api_key = EncryptedCharField(max_length=512, blank=True, default="")

    def __str__(self):
        return f"Profile({self.user.email})"


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)
