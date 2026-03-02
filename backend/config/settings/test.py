"""Test settings — SQLite in-memory, Celery eager, no external services."""

from .base import *  # noqa: F401, F403

DEBUG = True
ALLOWED_HOSTS = ["*"]

# ---------- Database: SQLite in-memory ----------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# ---------- Celery: synchronous (no Redis) ----------
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = "memory://"
CELERY_RESULT_BACKEND = "cache+memory://"

# ---------- Channels: in-memory ----------
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}

# ---------- DRF: disable throttling ----------
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apps.accounts.authentication.CookieJWTAuthentication",
    ],
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {},
}

# ---------- Faster password hashing for tests ----------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# ---------- Scanner ----------
SCANNER_WORKSPACE_ROOT = "/tmp/securescan_test_workspaces"

# ---------- Dummy external API keys ----------
GEMINI_API_KEY = "test-fake-gemini-key"
GEMINI_MODEL = "gemini-test"
OPENAI_MODEL = "gpt-4o-test"
ANTHROPIC_MODEL = "claude-test"
GITHUB_TOKEN = "test-fake-github-token"
GITHUB_CLIENT_ID = "test-client-id"
GITHUB_CLIENT_SECRET = "test-client-secret"
GOOGLE_CLIENT_ID = "test-google-client-id"
GOOGLE_CLIENT_SECRET = "test-google-client-secret"
GOOGLE_REDIRECT_URI = "http://localhost/login"

# ---------- Disable password validators for test speed ----------
AUTH_PASSWORD_VALIDATORS = []
