from pathlib import Path

# ---------------------------------------------------------------------------
# Extension → language mapping
# ---------------------------------------------------------------------------

_EXT_TO_LANG: dict[str, str] = {}

_LANG_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py", ".pyw", ".pyi"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    "php": {".php", ".phtml", ".php3", ".php4", ".php5"},
    "java": {".java"},
    "kotlin": {".kt", ".kts"},
    "go": {".go"},
    "ruby": {".rb", ".erb"},
    "csharp": {".cs"},
    "c_cpp": {".c", ".h", ".cpp", ".cxx", ".cc", ".hpp"},
    "rust": {".rs"},
    "swift": {".swift"},
    "html": {".html", ".htm"},
}

# Build reverse map: extension → language
for _lang, _exts in _LANG_EXTENSIONS.items():
    for _ext in _exts:
        _EXT_TO_LANG[_ext] = _lang

# ---------------------------------------------------------------------------
# Manifest → language mapping
# ---------------------------------------------------------------------------

_MANIFEST_TO_LANG: dict[str, str] = {
    # Python
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "setup.cfg": "python",
    "Pipfile": "python",
    # JavaScript / TypeScript
    "package.json": "javascript",
    # PHP
    "composer.json": "php",
    # Java / Kotlin
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "kotlin",
    # Go
    "go.mod": "go",
    # Ruby
    "Gemfile": "ruby",
    # C#
    ".csproj": "csharp",
    # Rust
    "Cargo.toml": "rust",
}

# Directories to skip during scanning
_SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", "vendor", "dist", "build"}


def detect_languages(workspace: Path) -> list[str]:
    """Detect programming languages present in a workspace directory.

    Uses a two-pass strategy:
    - Pass 1: collect languages from *file extensions* (high confidence).
    - Pass 2: add languages from *manifest files*, but apply a stricter rule
      for JavaScript: package.json is present in virtually every project
      (Python, Go, Ruby…) as a tooling config, so we only trust it when
      actual .js/.ts source files were also found.

    Always includes "any" (for TruffleHog secrets detection).
    """
    extension_languages: set[str] = set()
    manifest_languages: set[str] = set()

    for path in workspace.rglob("*"):
        # Skip heavy / irrelevant directories
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue

        name = path.name
        suffix = path.suffix.lower()

        # Manifest check
        if name in _MANIFEST_TO_LANG:
            manifest_languages.add(_MANIFEST_TO_LANG[name])

        # Extension check (higher confidence)
        if suffix in _EXT_TO_LANG:
            extension_languages.add(_EXT_TO_LANG[suffix])

    # Merge: extension-based is always trusted
    languages = set(extension_languages)

    # Manifest-based: trusted for all languages EXCEPT javascript,
    # because package.json appears in non-JS projects as tooling config.
    # For javascript we require at least one actual source file to confirm.
    for lang in manifest_languages:
        if lang == "javascript":
            if "javascript" in extension_languages:
                languages.add(lang)
            # else: skip — package.json alone doesn't prove a JS project
        else:
            languages.add(lang)

    # TruffleHog always runs — secrets can be in any repo
    languages.add("any")
    # Discard "html" — not a language for analyzer selection.
    # Semgrep already extracts inline scripts from HTML automatically.
    languages.discard("html")

    return sorted(languages)


def get_analyzers_for_languages(languages: list[str]) -> list[str]:
    """Return the set of security analyzers to run for the given languages.

    Semgrep always runs — it supports many languages natively and can detect
    issues in HTML, YAML, JSON, etc. even when no Python/JS is detected.
    TruffleHog always runs for secrets detection.
    Bandit + pip-audit are Python-specific.
    ESLint, npm audit are JavaScript-specific.
    Composer audit is PHP-specific.

    Returns a sorted list of analyzer identifiers.
    """
    analyzers = {"trufflehog", "semgrep"}

    if "python" in languages:
        analyzers.add("bandit")
        analyzers.add("pip_audit")

    if "javascript" in languages:
        analyzers.add("eslint")
        analyzers.add("npm_audit")

    if "php" in languages:
        analyzers.add("composer_audit")

    return sorted(analyzers)
