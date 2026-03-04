"""Unit tests for the URL validator (SSRF protection)."""

from unittest.mock import patch, MagicMock

import pytest
from rest_framework import serializers

from apps.scanner.services.url_validator import _is_private_ip, validate_git_url


class TestIsPrivateIp:
    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_rfc1918_10(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_rfc1918_172(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_rfc1918_192(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_ipv6_loopback(self):
        assert _is_private_ip("::1") is True

    def test_public_ip(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_unparseable(self):
        assert _is_private_ip("not-an-ip") is True


class TestValidateGitUrl:
    def test_http_rejected(self):
        with pytest.raises(serializers.ValidationError, match="https://"):
            validate_git_url("http://github.com/user/repo.git")

    def test_no_host_rejected(self):
        with pytest.raises(serializers.ValidationError, match="no host"):
            validate_git_url("https://")

    def test_private_ip_127(self):
        with pytest.raises(serializers.ValidationError, match="private"):
            validate_git_url("https://127.0.0.1/repo.git")

    def test_private_ip_10(self):
        with pytest.raises(serializers.ValidationError, match="private"):
            validate_git_url("https://10.0.0.1/repo.git")

    def test_private_ip_192(self):
        with pytest.raises(serializers.ValidationError, match="private"):
            validate_git_url("https://192.168.1.1/repo.git")

    @patch("apps.scanner.services.url_validator.socket.getaddrinfo")
    @patch("apps.scanner.services.url_validator.httpx.head")
    def test_valid_url_accepted(self, mock_head, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("140.82.121.4", 443)),
        ]
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False
        mock_head.return_value = mock_response

        result = validate_git_url("https://github.com/user/repo.git")
        assert result == "https://github.com/user/repo.git"

    @patch("apps.scanner.services.url_validator.socket.getaddrinfo")
    @patch("apps.scanner.services.url_validator.httpx.head")
    def test_404_rejected(self, mock_head, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("140.82.121.4", 443)),
        ]
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.is_redirect = False
        mock_head.return_value = mock_response

        with pytest.raises(serializers.ValidationError, match="not found"):
            validate_git_url("https://github.com/user/nonexistent.git")
