from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


class CookieJWTAuthentication(JWTAuthentication):
    """Read JWT from the ``access_token`` httpOnly cookie.

    Falls back to the standard ``Authorization: Bearer <token>`` header so
    that API clients (tests, mobile, etc.) still work.
    """

    def authenticate(self, request):
        # Try cookie first
        raw_token = request.COOKIES.get("access_token")
        if raw_token:
            try:
                validated_token = self.get_validated_token(raw_token)
                return self.get_user(validated_token), validated_token
            except (InvalidToken, TokenError, Exception):
                # Cookie is invalid/expired — don't block the request,
                # let AllowAny views through and IsAuthenticated views
                # fall back to header auth or return None.
                pass

        # Fallback to Authorization header
        return super().authenticate(request)
