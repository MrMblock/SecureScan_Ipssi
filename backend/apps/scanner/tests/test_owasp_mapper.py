"""Unit tests for the OWASP Top 10 mapper."""

import pytest

from apps.scanner.services.owasp_mapper import get_owasp_label, map_finding_to_owasp


# ── Semgrep mapping ──────────────────────────────────────────────────────────


class TestSemgrepMapping:
    def test_sql_injection_in_rule_id(self):
        assert map_finding_to_owasp("semgrep", "python.lang.sql-injection.raw") == "A05"

    def test_ssrf_in_rule_id(self):
        assert map_finding_to_owasp("semgrep", "python.lang.ssrf.request") == "A01"

    def test_crypto_in_rule_id(self):
        assert map_finding_to_owasp("semgrep", "python.crypto.weak-hash") == "A04"

    def test_xss_in_rule_id(self):
        assert map_finding_to_owasp("semgrep", "javascript.browser.xss.innerhtml") == "A05"

    def test_open_redirect_in_rule_id(self):
        assert map_finding_to_owasp("semgrep", "dom-open-redirect-location") == "A01"

    def test_deserialization_in_rule_id(self):
        assert map_finding_to_owasp("semgrep", "python.deserialization.yaml") == "A08"

    def test_fallback_on_title(self):
        result = map_finding_to_owasp("semgrep", "some.unknown.rule", title="SQL injection detected")
        assert result == "A05"

    def test_fallback_on_description(self):
        result = map_finding_to_owasp(
            "semgrep", "some.unknown.rule", description="This allows command-injection"
        )
        assert result == "A05"

    def test_default_fallback(self):
        result = map_finding_to_owasp("semgrep", "some.unknown.rule", title="nothing", description="nothing")
        assert result == "A02"


# ── Bandit mapping ───────────────────────────────────────────────────────────


class TestBanditMapping:
    def test_b301_pickle(self):
        assert map_finding_to_owasp("bandit", "B301") == "A05"

    def test_b303_md5(self):
        assert map_finding_to_owasp("bandit", "B303") == "A04"

    def test_b104_bind_all(self):
        assert map_finding_to_owasp("bandit", "B104") == "A02"

    def test_b310_urllib(self):
        assert map_finding_to_owasp("bandit", "B310") == "A01"

    def test_unknown_code(self):
        assert map_finding_to_owasp("bandit", "B999") == "A02"


# ── ESLint mapping ───────────────────────────────────────────────────────────


class TestEslintMapping:
    def test_detect_eval(self):
        assert map_finding_to_owasp("eslint", "security/detect-eval-with-expression") == "A05"

    def test_detect_non_literal_fs(self):
        assert map_finding_to_owasp("eslint", "security/detect-non-literal-fs-filename") == "A01"

    def test_detect_timing_attack(self):
        assert map_finding_to_owasp("eslint", "security/detect-possible-timing-attacks") == "A04"

    def test_unknown_rule(self):
        assert map_finding_to_owasp("eslint", "some/unknown-rule") == "A02"


# ── npm audit mapping ───────────────────────────────────────────────────────


class TestNpmAuditMapping:
    def test_prototype_pollution(self):
        assert map_finding_to_owasp("npm_audit", "", title="Prototype Pollution in lodash") == "A08"

    def test_injection_keyword(self):
        assert map_finding_to_owasp("npm_audit", "", description="command injection via user input") == "A05"

    def test_supply_chain_default(self):
        assert map_finding_to_owasp("npm_audit", "", title="nothing relevant") == "A03"

    def test_malware(self):
        assert map_finding_to_owasp("npm_audit", "", title="malware detected in package") == "A03"


# ── TruffleHog ───────────────────────────────────────────────────────────────


class TestTrufflehogMapping:
    def test_always_a04(self):
        assert map_finding_to_owasp("trufflehog", "aws-access-key") == "A04"

    def test_any_rule_id(self):
        assert map_finding_to_owasp("trufflehog", "generic-secret") == "A04"


# ── Unknown tool ─────────────────────────────────────────────────────────────


def test_unknown_tool_returns_unk():
    assert map_finding_to_owasp("unknown_tool", "whatever") == "UNK"


# ── get_owasp_label ──────────────────────────────────────────────────────────


class TestGetOwaspLabel:
    def test_known_code(self):
        assert get_owasp_label("A01") == "Broken Access Control"

    def test_a05_injection(self):
        assert get_owasp_label("A05") == "Injection"

    def test_unknown_code(self):
        assert get_owasp_label("A99") == "Unknown"
