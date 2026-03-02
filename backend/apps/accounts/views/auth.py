import os
import uuid

from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
import requests

from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.conf import settings

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import UserProfile

User = get_user_model()

# Avatar upload security
ALLOWED_AVATAR_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5 MB


def _validate_and_save_avatar(profile, avatar_file):
    """Validate avatar file type/size and save with a safe UUID-based name."""
    if avatar_file.size > MAX_AVATAR_SIZE:
        raise ValidationError("Avatar file too large (max 5 MB).")
    ext = os.path.splitext(avatar_file.name)[1].lower()
    if ext not in ALLOWED_AVATAR_EXTENSIONS:
        raise ValidationError(
            f"Invalid file type '{ext}'. Allowed: {', '.join(ALLOWED_AVATAR_EXTENSIONS)}"
        )
    safe_name = f"{uuid.uuid4().hex}{ext}"
    profile.avatar.save(safe_name, avatar_file, save=True)


# ===============================
# Me (current user)
# ===============================

class MeView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get(self, request):
        user = request.user
        profile = user.profile
        avatar_url = profile.avatar.url if profile.avatar else None
        return Response({
            "email": user.email,
            "name": user.first_name,
            "avatar_url": avatar_url,
            "ai_provider": profile.ai_provider,
            "gemini_api_key": "*" * 8 if profile.gemini_api_key else "",
            "openai_api_key": "*" * 8 if profile.openai_api_key else "",
            "anthropic_api_key": "*" * 8 if profile.anthropic_api_key else "",
        })

    def patch(self, request):
        user = request.user
        profile = user.profile

        name = request.data.get("name")
        if name is not None:
            user.first_name = name
            user.save(update_fields=["first_name"])

        avatar = request.FILES.get("avatar")
        if avatar:
            _validate_and_save_avatar(profile, avatar)

        password = request.data.get("password")
        if password:
            try:
                validate_password(password, user)
            except ValidationError as e:
                return Response({"error": e.messages}, status=400)
            user.set_password(password)
            user.save(update_fields=["password"])

        ai_provider = request.data.get("ai_provider")
        if ai_provider is not None and ai_provider in ("gemini", "openai", "anthropic"):
            profile.ai_provider = ai_provider

        update_profile_fields = []
        for field in ("gemini_api_key", "openai_api_key", "anthropic_api_key"):
            value = request.data.get(field)
            if value is not None:
                setattr(profile, field, value)
                update_profile_fields.append(field)

        if ai_provider is not None:
            update_profile_fields.append("ai_provider")

        if update_profile_fields:
            profile.save(update_fields=update_profile_fields)

        avatar_url = profile.avatar.url if profile.avatar else None
        return Response({
            "email": user.email,
            "name": user.first_name,
            "avatar_url": avatar_url,
            "ai_provider": profile.ai_provider,
            "gemini_api_key": "*" * 8 if profile.gemini_api_key else "",
            "openai_api_key": "*" * 8 if profile.openai_api_key else "",
            "anthropic_api_key": "*" * 8 if profile.anthropic_api_key else "",
        })


# ===============================
# Utility Functions
# ===============================

def generate_token(user):
    refresh = RefreshToken.for_user(user)

    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh)
    }


def _set_auth_cookies(response, user):
    """Set httpOnly JWT cookies on the response."""
    tokens = generate_token(user)
    access_lifetime = settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME")
    refresh_lifetime = settings.SIMPLE_JWT.get("REFRESH_TOKEN_LIFETIME")

    response.set_cookie(
        "access_token",
        tokens["access"],
        max_age=int(access_lifetime.total_seconds()),
        httponly=True,
        secure=not settings.DEBUG,
        samesite="Lax",
        path="/",
    )
    response.set_cookie(
        "refresh_token",
        tokens["refresh"],
        max_age=int(refresh_lifetime.total_seconds()),
        httponly=True,
        secure=not settings.DEBUG,
        samesite="Lax",
        path="/api/accounts/token/refresh/",
    )
    # Non-httpOnly flag so the frontend can detect auth state
    response.set_cookie(
        "is_authenticated",
        "true",
        max_age=int(refresh_lifetime.total_seconds()),
        httponly=False,
        secure=not settings.DEBUG,
        samesite="Lax",
        path="/",
    )
    return response


def _clear_auth_cookies(response):
    """Delete all auth cookies."""
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/api/accounts/token/refresh/")
    response.delete_cookie("is_authenticated", path="/")
    return response


def get_or_create_user(email):
    user, _ = User.objects.get_or_create(
        email=email,
        defaults={
            "username": email
        }
    )

    return user


# ===============================
# Signup
# ===============================

class SignupView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    throttle_scope = "auth"

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        name = request.data.get("name", "")

        if not email or not password:
            return Response({"error": "Email and password are required."}, status=400)

        if User.objects.filter(email=email).exists():
            return Response(
                {"error": "User already exists"},
                status=400
            )

        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"error": e.messages}, status=400)

        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            first_name=name,
        )

        avatar = request.FILES.get("avatar")
        if avatar:
            try:
                _validate_and_save_avatar(user.profile, avatar)
            except ValidationError:
                pass  # Non-blocking — account is created, avatar skipped

        response = Response({"detail": "ok"})
        return _set_auth_cookies(response, user)


# ===============================
# Login
# ===============================

class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid credentials"},
                status=401
            )

        if not user.check_password(password):
            return Response(
                {"error": "Invalid credentials"},
                status=401
            )

        response = Response({"detail": "ok"})
        return _set_auth_cookies(response, user)


# ===============================
# Google OAuth
# ===============================

class GoogleAuthView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    def _get_redirect_uri(self, request):
        # If the client sends the redirect_uri it used, trust that
        client_uri = request.data.get("redirect_uri")
        if client_uri:
            return client_uri
        origin = request.META.get("HTTP_ORIGIN") or request.META.get("HTTP_REFERER", "")
        # Strip path from referer if present
        if "/" in origin.split("//", 1)[-1]:
            origin = origin.rsplit("/", 1)[0] if origin.count("/") > 2 else origin
        return f"{origin.rstrip('/')}/login" if origin else settings.GOOGLE_REDIRECT_URI

    def post(self, request):
        code = request.data.get("code")
        redirect_uri = self._get_redirect_uri(request)

        try:
            token_response = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code"
                }
            )
            token_response.raise_for_status()
            token_res = token_response.json()
        except (requests.exceptions.RequestException, ValueError):
            return Response({"error": "Failed to contact Google OAuth."}, status=502)

        access_token = token_res.get("access_token")
        if not access_token:
            return Response({"error": "Google OAuth failed"}, status=400)

        try:
            info_response = requests.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={
                    "Authorization": f"Bearer {access_token}"
                }
            )
            info_response.raise_for_status()
            user_info = info_response.json()
        except (requests.exceptions.RequestException, ValueError):
            return Response({"error": "Failed to fetch Google user info."}, status=502)

        email = user_info.get("email")

        user = get_or_create_user(email)

        response = Response({"detail": "ok"})
        return _set_auth_cookies(response, user)


# ===============================
# Github OAuth
# ===============================

class GithubAuthView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    def post(self, request):
        code = request.data.get("code")
        redirect_uri = request.data.get("redirect_uri", "")

        token_data = {
            "client_id": settings.GITHUB_CLIENT_ID,
            "client_secret": settings.GITHUB_CLIENT_SECRET,
            "code": code,
        }
        if redirect_uri:
            token_data["redirect_uri"] = redirect_uri

        try:
            token_response = requests.post(
                "https://github.com/login/oauth/access_token",
                headers={
                    "Accept": "application/json"
                },
                data=token_data,
            )
            token_response.raise_for_status()
            token_res = token_response.json()
        except (requests.exceptions.RequestException, ValueError) as exc:
            import logging; logging.getLogger(__name__).error("GitHub OAuth token exchange failed: %s", exc)  # noqa: E702
            return Response({"error": f"Failed to contact GitHub OAuth: {exc}"}, status=502)

        access_token = token_res.get("access_token")
        if not access_token:
            error_desc = token_res.get("error_description", token_res.get("error", "unknown"))
            return Response({"error": f"GitHub OAuth failed: {error_desc}"}, status=400)

        try:
            info_response = requests.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}"
                }
            )
            info_response.raise_for_status()
            user_info = info_response.json()
        except (requests.exceptions.RequestException, ValueError):
            return Response({"error": "Failed to fetch GitHub user info."}, status=502)

        email = user_info.get("email") or user_info.get("login")
        github_login = user_info.get("login", "")

        user = get_or_create_user(email)

        # Persist the OAuth token so we can create PRs later
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.github_access_token = access_token
        profile.github_login = github_login
        profile.save(update_fields=["github_access_token", "github_login"])

        response = Response({"detail": "ok"})
        return _set_auth_cookies(response, user)


# ===============================
# GitHub Repos
# ===============================

class GithubReposView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile = request.user.profile
        token = profile.github_access_token
        if not token:
            return Response({"error": "GitHub not connected"}, status=400)

        repos = []
        page = 1
        while True:
            res = requests.get(
                "https://api.github.com/user/repos",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
                params={
                    "per_page": 100,
                    "page": page,
                    "sort": "updated",
                    "affiliation": "owner,collaborator,organization_member",
                },
            )
            if res.status_code != 200:
                return Response({"error": "GitHub API error"}, status=502)
            data = res.json()
            if not data:
                break
            repos.extend([
                {
                    "full_name": r["full_name"],
                    "clone_url": r["clone_url"],
                    "private": r["private"],
                    "language": r.get("language"),
                    "updated_at": r["updated_at"],
                }
                for r in data
            ])
            page += 1

        return Response(repos)


# ===============================
# Token (for CLI / API clients)
# ===============================

class TokenObtainView(APIView):
    """POST /api/accounts/token/ — Returns JWT in response body (for CLI/API clients)."""
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        user = authenticate(request, email=email, password=password)
        if user is None:
            return Response({"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        tokens = generate_token(user)
        return Response({
            "access": tokens["access"],
            "refresh": tokens["refresh"],
            "email": user.email,
            "name": user.first_name,
        })


# ===============================
# Token Refresh (JSON body)
# ===============================

class TokenRefreshBodyView(APIView):
    """POST /api/accounts/token/refresh/body/ — Refresh using JSON body (for CLI)."""
    permission_classes = [AllowAny]

    def post(self, request):
        raw_refresh = request.data.get("refresh")
        if not raw_refresh:
            return Response({"detail": "No refresh token."}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            refresh = RefreshToken(raw_refresh)
            return Response({"access": str(refresh.access_token)})
        except Exception:
            return Response({"detail": "Invalid refresh token."}, status=status.HTTP_401_UNAUTHORIZED)


# ===============================
# Logout
# ===============================

class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        response = Response({"detail": "ok"})
        return _clear_auth_cookies(response)


# ===============================
# Cookie Token Refresh
# ===============================

class CookieTokenRefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        raw_refresh = request.COOKIES.get("refresh_token")
        if not raw_refresh:
            return Response({"detail": "No refresh token."}, status=401)

        try:
            refresh = RefreshToken(raw_refresh)
            access_lifetime = settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME")
            response = Response({"detail": "ok"})
            response.set_cookie(
                "access_token",
                str(refresh.access_token),
                max_age=int(access_lifetime.total_seconds()),
                httponly=True,
                secure=not settings.DEBUG,
                samesite="Lax",
                path="/",
            )
            return response
        except Exception:
            response = Response({"detail": "Invalid refresh token."}, status=401)
            return _clear_auth_cookies(response)