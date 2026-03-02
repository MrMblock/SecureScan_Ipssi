from django.urls import path

from .views.auth import (
    SignupView,
    LoginView,
    LogoutView,
    GoogleAuthView,
    GithubAuthView,
    GithubReposView,
    MeView,
    CookieTokenRefreshView,
    TokenObtainView,
    TokenRefreshBodyView,
)

urlpatterns = [
    path("signup/", SignupView.as_view()),
    path("login/", LoginView.as_view()),
    path("logout/", LogoutView.as_view()),
    path("token/", TokenObtainView.as_view(), name="token_obtain"),
    path("token/refresh/", CookieTokenRefreshView.as_view()),
    path("token/refresh/body/", TokenRefreshBodyView.as_view(), name="token_refresh_body"),
    path("me/", MeView.as_view()),
    path("github/repos/", GithubReposView.as_view()),
    path("oauth/google/", GoogleAuthView.as_view()),
    path("oauth/github/", GithubAuthView.as_view()),
]
