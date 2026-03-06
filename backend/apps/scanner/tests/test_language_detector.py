"""Unit tests for the language detector service."""


from apps.scanner.services.language_detector import detect_languages, get_analyzers_for_languages


class TestDetectLanguages:
    def test_python_files(self, tmp_path):
        (tmp_path / "main.py").write_text("print(1)")
        result = detect_languages(tmp_path)
        assert "python" in result
        assert "any" in result

    def test_javascript_files(self, tmp_path):
        (tmp_path / "app.js").write_text("console.log(1);")
        result = detect_languages(tmp_path)
        assert "javascript" in result
        assert "any" in result

    def test_requirements_txt_trusts_python(self, tmp_path):
        """Manifest file alone is trusted for Python (no .py needed)."""
        (tmp_path / "requirements.txt").write_text("flask\n")
        result = detect_languages(tmp_path)
        assert "python" in result

    def test_package_json_alone_not_trusted(self, tmp_path):
        """package.json alone does NOT trigger javascript detection."""
        (tmp_path / "package.json").write_text('{"name": "test"}')
        result = detect_languages(tmp_path)
        assert "javascript" not in result

    def test_package_json_with_ts_file(self, tmp_path):
        """package.json + .ts file → javascript detected."""
        (tmp_path / "package.json").write_text('{"name": "test"}')
        (tmp_path / "index.ts").write_text("const x = 1;")
        result = detect_languages(tmp_path)
        assert "javascript" in result

    def test_empty_workspace(self, tmp_path):
        result = detect_languages(tmp_path)
        assert result == ["any"]

    def test_html_discarded(self, tmp_path):
        (tmp_path / "index.html").write_text("<html></html>")
        result = detect_languages(tmp_path)
        assert "html" not in result
        assert "any" in result

    def test_node_modules_ignored(self, tmp_path):
        nm = tmp_path / "node_modules" / "lodash"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("module.exports = {};")
        result = detect_languages(tmp_path)
        assert "javascript" not in result

    def test_git_dir_ignored(self, tmp_path):
        git = tmp_path / ".git" / "hooks"
        git.mkdir(parents=True)
        (git / "pre-commit.py").write_text("#!/usr/bin/env python")
        result = detect_languages(tmp_path)
        assert "python" not in result

    def test_multiple_languages(self, tmp_path):
        (tmp_path / "app.py").write_text("pass")
        (tmp_path / "main.go").write_text("package main")
        result = detect_languages(tmp_path)
        assert "python" in result
        assert "go" in result
        assert "any" in result


class TestGetAnalyzersForLanguages:
    def test_python(self):
        analyzers = get_analyzers_for_languages(["python", "any"])
        assert "bandit" in analyzers
        assert "semgrep" in analyzers
        assert "trufflehog" in analyzers

    def test_javascript(self):
        analyzers = get_analyzers_for_languages(["javascript", "any"])
        assert "eslint" in analyzers
        assert "npm_audit" in analyzers
        assert "semgrep" in analyzers
        assert "trufflehog" in analyzers

    def test_any_only(self):
        analyzers = get_analyzers_for_languages(["any"])
        assert "semgrep" in analyzers
        assert "trufflehog" in analyzers
        assert "bandit" not in analyzers
        assert "eslint" not in analyzers

    def test_python_and_javascript(self):
        analyzers = get_analyzers_for_languages(["python", "javascript", "any"])
        assert "bandit" in analyzers
        assert "eslint" in analyzers
        assert "npm_audit" in analyzers
        assert "semgrep" in analyzers
        assert "trufflehog" in analyzers
