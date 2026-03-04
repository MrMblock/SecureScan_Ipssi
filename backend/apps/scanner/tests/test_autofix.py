"""Tests for the multi-provider AI autofix service."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from apps.scanner.services.autofix import (
    PROVIDER_CALLERS,
    SUPPORTED_PROVIDERS,
    _build_prompt,
    _parse_ai_response,
    generate_fix,
    get_api_key_for_provider,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    tool="semgrep",
    rule_id="python.lang.security.audit.dangerous-exec-use",
    file_path="app.py",
    line_start=10,
    line_end=10,
    code_snippet="exec(user_input)",
    severity="high",
    owasp_category="A05",
    title="Dangerous exec() usage",
    description="User input passed to exec().",
    fix_generated_at=None,
    fixed_code="",
    fix_explanation="",
    status="open",
):
    scan = SimpleNamespace(workspace_path="/tmp/fake")
    finding = MagicMock()
    finding.id = "fake-finding-id"
    finding.scan = scan
    finding.tool = tool
    finding.rule_id = rule_id
    finding.file_path = file_path
    finding.line_start = line_start
    finding.line_end = line_end
    finding.code_snippet = code_snippet
    finding.severity = severity
    finding.owasp_category = owasp_category
    finding.title = title
    finding.description = description
    finding.fix_generated_at = fix_generated_at
    finding.fixed_code = fixed_code
    finding.fix_explanation = fix_explanation
    finding.status = status
    return finding


FAKE_AI_RESPONSE = json.dumps({
    "fixed_code": "safe_eval(user_input)",
    "explanation": "Replaced exec() with a safe alternative.",
    "is_false_positive": False,
})

FAKE_FP_RESPONSE = json.dumps({
    "fixed_code": "exec(user_input)",
    "explanation": "This is actually safe in this context.",
    "is_false_positive": True,
})


# ---------------------------------------------------------------------------
# _parse_ai_response
# ---------------------------------------------------------------------------

class TestParseAiResponse:
    def test_plain_json(self):
        result = _parse_ai_response(FAKE_AI_RESPONSE)
        assert result["fixed_code"] == "safe_eval(user_input)"
        assert result["explanation"] == "Replaced exec() with a safe alternative."
        assert result["is_false_positive"] is False

    def test_with_markdown_fences(self):
        wrapped = f"```json\n{FAKE_AI_RESPONSE}\n```"
        result = _parse_ai_response(wrapped)
        assert result["fixed_code"] == "safe_eval(user_input)"

    def test_false_positive_flag(self):
        result = _parse_ai_response(FAKE_FP_RESPONSE)
        assert result["is_false_positive"] is True

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _parse_ai_response("not json at all")

    def test_fixed_code_dict_serialized(self):
        resp = json.dumps({
            "fixed_code": {"key": "value"},
            "explanation": "test",
            "is_false_positive": False,
        })
        result = _parse_ai_response(resp)
        assert '"key"' in result["fixed_code"]


# ---------------------------------------------------------------------------
# get_api_key_for_provider
# ---------------------------------------------------------------------------

class TestGetApiKeyForProvider:
    def test_gemini(self):
        keys = {"gemini_api_key": "gk", "openai_api_key": "ok", "anthropic_api_key": "ak"}
        assert get_api_key_for_provider("gemini", keys) == "gk"

    def test_openai(self):
        keys = {"gemini_api_key": "gk", "openai_api_key": "ok", "anthropic_api_key": "ak"}
        assert get_api_key_for_provider("openai", keys) == "ok"

    def test_anthropic(self):
        keys = {"gemini_api_key": "gk", "openai_api_key": "ok", "anthropic_api_key": "ak"}
        assert get_api_key_for_provider("anthropic", keys) == "ak"

    def test_unknown_provider(self):
        keys = {"gemini_api_key": "gk"}
        assert get_api_key_for_provider("unknown", keys) == ""

    def test_missing_key(self):
        assert get_api_key_for_provider("gemini", {}) == ""


# ---------------------------------------------------------------------------
# _build_prompt
# ---------------------------------------------------------------------------

class TestBuildPrompt:
    def test_contains_finding_info(self):
        finding = _make_finding()
        prompt = _build_prompt(finding, lang="en")
        assert "exec(user_input)" in prompt
        assert "Dangerous exec() usage" in prompt
        assert "A05" in prompt

    def test_french_instruction(self):
        finding = _make_finding()
        prompt = _build_prompt(finding, lang="fr")
        assert "French" in prompt

    def test_english_default(self):
        finding = _make_finding()
        prompt = _build_prompt(finding)
        assert "English" in prompt


# ---------------------------------------------------------------------------
# generate_fix — cached result
# ---------------------------------------------------------------------------

class TestGenerateFixCached:
    def test_returns_cached_when_available(self):
        finding = _make_finding(
            fix_generated_at=timezone.now(),
            fixed_code="cached_fix()",
            fix_explanation="Cached explanation.",
        )
        result = generate_fix(finding, provider="gemini", api_key="fake")
        assert result["cached"] is True
        assert result["fixed_code"] == "cached_fix()"
        assert result["fix_explanation"] == "Cached explanation."


# ---------------------------------------------------------------------------
# generate_fix — pattern fix (no API needed)
# ---------------------------------------------------------------------------

class TestGenerateFixPatternFix:
    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix")
    def test_pattern_fix_used_when_available(self, mock_pattern):
        mock_pattern.return_value = {
            "fixed_code": "pattern_fix()",
            "fix_explanation": "Pattern fix.",
            "original_code": "exec(user_input)",
            "file_path": "app.py",
            "line_start": 10,
            "cached": False,
        }
        finding = _make_finding()
        result = generate_fix(finding, provider="gemini", api_key="fake")
        assert result["fixed_code"] == "pattern_fix()"
        finding.save.assert_called_once()


# ---------------------------------------------------------------------------
# generate_fix — provider validation
# ---------------------------------------------------------------------------

class TestGenerateFixProviderValidation:
    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_unsupported_provider_raises(self, _mock):
        finding = _make_finding()
        with pytest.raises(ValueError, match="Unsupported AI provider"):
            generate_fix(finding, provider="unknown_ai", api_key="key")

    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_missing_api_key_raises(self, _mock):
        finding = _make_finding()
        with pytest.raises(ValueError, match="No Gemini API key"):
            generate_fix(finding, provider="gemini", api_key="")

    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_missing_openai_key_message(self, _mock):
        finding = _make_finding()
        with pytest.raises(ValueError, match="No OpenAI API key"):
            generate_fix(finding, provider="openai", api_key="")

    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_missing_anthropic_key_message(self, _mock):
        finding = _make_finding()
        with pytest.raises(ValueError, match="No Anthropic API key"):
            generate_fix(finding, provider="anthropic", api_key="")


# ---------------------------------------------------------------------------
# generate_fix — Gemini provider
# ---------------------------------------------------------------------------

class TestGenerateFixGemini:
    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_gemini_success(self, _mock_pattern):
        mock_caller = MagicMock(return_value=FAKE_AI_RESPONSE)
        with patch.dict(PROVIDER_CALLERS, {"gemini": mock_caller}):
            finding = _make_finding()
            result = generate_fix(finding, provider="gemini", api_key="test-key")
            mock_caller.assert_called_once()
            assert result["fixed_code"] == "safe_eval(user_input)"
            assert result["cached"] is False
            finding.save.assert_called_once()

    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_gemini_false_positive(self, _mock_pattern):
        mock_caller = MagicMock(return_value=FAKE_FP_RESPONSE)
        with patch.dict(PROVIDER_CALLERS, {"gemini": mock_caller}):
            finding = _make_finding()
            result = generate_fix(finding, provider="gemini", api_key="test-key")
            assert result["is_false_positive"] is True
            assert finding.status == "false_positive"


# ---------------------------------------------------------------------------
# generate_fix — OpenAI provider
# ---------------------------------------------------------------------------

class TestGenerateFixOpenAI:
    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_openai_success(self, _mock_pattern):
        mock_caller = MagicMock(return_value=FAKE_AI_RESPONSE)
        with patch.dict(PROVIDER_CALLERS, {"openai": mock_caller}):
            finding = _make_finding()
            result = generate_fix(finding, provider="openai", api_key="sk-test")
            mock_caller.assert_called_once()
            assert result["fixed_code"] == "safe_eval(user_input)"


# ---------------------------------------------------------------------------
# generate_fix — Anthropic provider
# ---------------------------------------------------------------------------

class TestGenerateFixAnthropic:
    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_anthropic_success(self, _mock_pattern):
        mock_caller = MagicMock(return_value=FAKE_AI_RESPONSE)
        with patch.dict(PROVIDER_CALLERS, {"anthropic": mock_caller}):
            finding = _make_finding()
            result = generate_fix(finding, provider="anthropic", api_key="sk-ant-test")
            mock_caller.assert_called_once()
            assert result["fixed_code"] == "safe_eval(user_input)"


# ---------------------------------------------------------------------------
# generate_fix — error handling
# ---------------------------------------------------------------------------

class TestGenerateFixErrors:
    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_invalid_json_response(self, _mock_pattern):
        mock_caller = MagicMock(return_value="not json")
        with patch.dict(PROVIDER_CALLERS, {"gemini": mock_caller}):
            finding = _make_finding()
            with pytest.raises(ValueError, match="Failed to parse AI response"):
                generate_fix(finding, provider="gemini", api_key="key")

    @patch("apps.scanner.services.pattern_fixer.try_pattern_fix", return_value=None)
    def test_api_error(self, _mock_pattern):
        mock_caller = MagicMock(side_effect=Exception("API down"))
        with patch.dict(PROVIDER_CALLERS, {"gemini": mock_caller}):
            finding = _make_finding()
            with pytest.raises(ValueError, match="AI service error"):
                generate_fix(finding, provider="gemini", api_key="key")


# ---------------------------------------------------------------------------
# SUPPORTED_PROVIDERS constant
# ---------------------------------------------------------------------------

class TestSupportedProviders:
    def test_all_three_present(self):
        assert "gemini" in SUPPORTED_PROVIDERS
        assert "openai" in SUPPORTED_PROVIDERS
        assert "anthropic" in SUPPORTED_PROVIDERS

    def test_each_has_caller(self):
        from apps.scanner.services.autofix import PROVIDER_CALLERS
        for p in SUPPORTED_PROVIDERS:
            assert p in PROVIDER_CALLERS
