import base64
import hashlib
import logging

from cryptography.fernet import Fernet
from django.conf import settings
from django.db import models

logger = logging.getLogger(__name__)

_fernet_instance = None


def _get_fernet():
    global _fernet_instance
    if _fernet_instance is not None:
        return _fernet_instance

    key = getattr(settings, "FIELD_ENCRYPTION_KEY", None)
    if not key:
        # Derive key using PBKDF2 with a fixed salt — much stronger than raw truncation.
        # In production, FIELD_ENCRYPTION_KEY should be set explicitly.
        if not settings.DEBUG:
            logger.warning(
                "FIELD_ENCRYPTION_KEY is not set! Deriving from SECRET_KEY. "
                "Set FIELD_ENCRYPTION_KEY in production for proper security."
            )
        raw = hashlib.pbkdf2_hmac(
            "sha256",
            settings.SECRET_KEY.encode(),
            b"securescan-field-encryption-salt",
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(raw)
    else:
        key = key.encode() if isinstance(key, str) else key

    _fernet_instance = Fernet(key)
    return _fernet_instance


class EncryptedCharField(models.CharField):
    """CharField that encrypts/decrypts transparently with Fernet."""

    def get_prep_value(self, value):
        if value and not value.startswith("gAAAAA"):
            value = _get_fernet().encrypt(value.encode()).decode()
        return super().get_prep_value(value)

    def from_db_value(self, value, expression, connection):
        if value and value.startswith("gAAAAA"):
            try:
                value = _get_fernet().decrypt(value.encode()).decode()
            except Exception:
                pass
        return value
