"""Map analyzer findings to OWASP Top 10 2025 categories.

Each tool has its own mapping tables. Rule IDs or keywords are matched
against known patterns to assign A01–A10 categories.
"""

import logging

logger = logging.getLogger(__name__)

OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

# ---------------------------------------------------------------------------
# Semgrep rule patterns → OWASP 2025
# ---------------------------------------------------------------------------
_SEMGREP_PATTERNS = {
    # A01 — Broken Access Control (+ SSRF)
    "open-redirect": "A01",
    "path-traversal": "A01",
    "access-control": "A01",
    "authorization": "A01",
    "csrf": "A01",
    "csurf": "A01",
    "cors": "A01",
    "directory-traversal": "A01",
    "ssrf": "A01",
    "request-forgery": "A01",

    # A02 — Security Misconfiguration
    "misconfiguration": "A02",
    "debug": "A02",
    "config": "A02",
    "helmet": "A02",
    "header": "A02",
    "security-audit": "A02",

    # A04 — Cryptographic Failures
    "crypto": "A04",
    "weak-hash": "A04",
    "md5": "A04",
    "sha1": "A04",
    "hardcoded-secret": "A04",
    "hardcoded-password": "A04",
    "private-key": "A04",
    "bcrypt-hash": "A04",
    "detected-private-key": "A04",
    "detected-bcrypt-hash": "A04",
    "insecure-hash": "A04",
    "tls": "A04",
    "ssl": "A04",

    # A05 — Injection (+ XSS)
    "sql-injection": "A05",
    "sqli": "A05",
    "injection": "A05",
    "eval": "A05",
    "code-injection": "A05",
    "command-injection": "A05",
    "xss": "A05",
    "code-string-concat": "A05",
    "nosql": "A05",
    "exec": "A05",
    "template-injection": "A05",
    "string-concat": "A05",

    # A06 — Insecure Design
    "insecure-design": "A06",
    "rate-limit": "A06",
    "rate_limit": "A06",
    "ratelimit": "A06",
    "throttl": "A06",
    "no-throttl": "A06",
    "race-condition": "A06",
    "race_condition": "A06",
    "business-logic": "A06",
    "mass-assignment": "A06",
    "unrestricted": "A06",
    "no-rate": "A06",
    "without-rate": "A06",
    "without-limit": "A06",
    "missing-rate": "A06",
    "talisman": "A06",        # flask-without-talisman = missing security headers / rate
    "unvalidated-redirect": "A06",
    "open-redirect-dos": "A06",

    # A07 — Authentication Failures
    "authentication": "A07",
    "session": "A07",
    "jwt": "A07",
    "password": "A07",
    "brute-force": "A07",
    "hardcoded-token": "A07",

    # A08 — Software or Data Integrity Failures
    "deserialization": "A08",
    "prototype-pollution": "A08",
    "integrity": "A08",
    "unsafe-unzip": "A08",
    "unverified": "A08",

    # A09 — Security Logging & Alerting Failures
    "logging": "A09",
    "log-injection": "A09",
    "log_injection": "A09",
    "audit-log": "A09",
    "no-log": "A09",
    "missing-log": "A09",
    "sensitive-log": "A09",
    "password-log": "A09",
    "secret-log": "A09",
    "print-instead": "A09",   # e.g. print-instead-of-logging
    "use-logging": "A09",
    "avoid-print": "A09",
    "no-exception-handler": "A09",
    "discard-exception": "A09",

    # A10 — Mishandling of Exceptional Conditions
    "exception": "A10",
    "error-handling": "A10",
    "fail-open": "A10",
    "swallow": "A10",
    "catch-all": "A10",
    "silent-fail": "A10",
}

# ---------------------------------------------------------------------------
# Bandit test IDs → OWASP 2025
# ---------------------------------------------------------------------------
_BANDIT_MAP = {
    # Injection → A05
    "B101": "A05",  # assert used
    "B102": "A05",  # exec used
    "B301": "A05",  # pickle
    "B302": "A05",  # marshal
    "B307": "A05",  # eval
    "B601": "A05",  # shell injection paramiko
    "B602": "A05",  # subprocess popen shell=True
    "B603": "A05",  # subprocess without shell
    "B604": "A05",  # any_other_function_with_shell_equals_true
    "B605": "A05",  # start_process_with_a_shell
    "B606": "A05",  # start_process_with_no_shell
    "B607": "A05",  # start_process_with_partial_path
    "B608": "A05",  # hardcoded_sql_expressions
    "B609": "A05",  # linux_commands_wildcard_injection
    "B610": "A05",  # django extra used
    "B611": "A05",  # django rawsql used
    "B701": "A05",  # jinja2 autoescape false
    "B702": "A05",  # use of mako templates
    "B703": "A05",  # django mark_safe

    # Crypto → A04
    "B303": "A04",  # md5/sha1
    "B304": "A04",  # DES cipher
    "B305": "A04",  # cipher mode
    "B324": "A04",  # hashlib

    # Misc config → A02
    "B104": "A02",  # bind all interfaces
    "B108": "A02",  # hardcoded tmp directory
    "B110": "A02",  # try_except_pass

    # Hardcoded passwords → A07 (Authentication Failures)
    # Note: hardcoded *encryption keys* map to A04, but hardcoded *passwords*
    # and *tokens* are an authentication failure first.
    "B105": "A07",  # hardcoded password string
    "B106": "A07",  # hardcoded password func arg
    "B107": "A07",  # hardcoded password default

    # Auth → A07
    "B501": "A07",  # request with no cert validation
    "B502": "A07",  # ssl with bad version
    "B503": "A07",  # ssl with bad defaults
    "B504": "A07",  # ssl with no version
    "B505": "A04",  # weak_cryptographic_key

    # SSRF → A01 (merged into Broken Access Control in 2025)
    "B310": "A01",  # urllib_urlopen
}

# ---------------------------------------------------------------------------
# ESLint security rules → OWASP 2025
# ---------------------------------------------------------------------------
_ESLINT_MAP = {
    "security/detect-eval-with-expression": "A05",
    "security/detect-non-literal-regexp": "A05",
    "security/detect-non-literal-fs-filename": "A01",
    "security/detect-non-literal-require": "A05",
    "security/detect-object-injection": "A05",
    "security/detect-possible-timing-attacks": "A04",
    "security/detect-pseudoRandomBytes": "A04",
    "security/detect-unsafe-regex": "A05",
    "security/detect-buffer-noassert": "A02",
    "security/detect-child-process": "A05",
    "security/detect-disable-mustache-escape": "A05",
    "security/detect-no-csrf-before-method-override": "A01",
    "security/detect-new-buffer": "A02",
}

# ---------------------------------------------------------------------------
# npm audit — severity-based + keyword heuristics
# ---------------------------------------------------------------------------
_NPM_KEYWORDS = {
    "prototype pollution": "A08",
    "injection": "A05",
    "command injection": "A05",
    "code execution": "A05",
    "arbitrary code": "A05",
    "xss": "A05",
    "cross-site": "A05",
    "path traversal": "A01",
    "directory traversal": "A01",
    "open redirect": "A01",
    "ssrf": "A01",
    "request forgery": "A01",
    "csrf": "A01",
    "denial of service": "A10",
    "redos": "A10",
    "regular expression": "A10",
    "memory exposure": "A04",
    "information disclosure": "A04",
    "weak crypto": "A04",
    "weak hash": "A04",
    "authentication": "A07",
    "session": "A07",
    "malware": "A03",
    "supply chain": "A03",
    "typosquat": "A03",
    "compromised": "A03",
    "backdoor": "A03",
    "integrity": "A08",
    "deserialization": "A08",
    "race condition": "A06",
    "rate limit": "A06",
    "brute force": "A07",
    "log": "A09",
}


# ---------------------------------------------------------------------------
# pip-audit CVE keywords → OWASP 2025
# ---------------------------------------------------------------------------
_PIP_AUDIT_KEYWORDS = {
    "injection": "A05",
    "sql": "A05",
    "xss": "A05",
    "code execution": "A05",
    "command": "A05",
    "path traversal": "A01",
    "directory traversal": "A01",
    "ssrf": "A01",
    "open redirect": "A01",
    "access control": "A01",
    "authentication": "A07",
    "session": "A07",
    "brute force": "A07",
    "cryptograph": "A04",
    "weak hash": "A04",
    "information disclosure": "A04",
    "memory": "A04",
    "deserialization": "A08",
    "prototype": "A08",
    "supply chain": "A03",
    "malware": "A03",
    "backdoor": "A03",
    "denial of service": "A10",
    "redos": "A10",
    "exception": "A10",
    "log": "A09",
    "rate limit": "A06",
}

# ---------------------------------------------------------------------------
# Composer audit (PHP) CVE keywords → OWASP 2025  (same structure)
# ---------------------------------------------------------------------------
_COMPOSER_KEYWORDS = dict(_PIP_AUDIT_KEYWORDS)  # identical heuristics


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_finding_to_owasp(tool: str, rule_id: str, title: str = "", description: str = "") -> str:
    """Map a single finding to an OWASP Top 10 category. Returns 'A01'–'A10' or 'UNK'."""
    category, _confidence = classify_finding(tool, rule_id, title, description)
    return category


def classify_finding(
    tool: str,
    rule_id: str,
    title: str = "",
    description: str = "",
) -> tuple[str, str]:
    """Return (owasp_category, confidence) for a finding.

    Confidence levels:
    - "high"   — exact lookup in a static rule/ID table
    - "medium" — keyword / text-based match
    - "low"    — tool default or UNK fallback
    """

    if tool == "semgrep":
        rule_lower = rule_id.lower()
        for pattern, category in _SEMGREP_PATTERNS.items():
            if pattern in rule_lower:
                return category, "high"
        # Fallback: check title/description
        text = (title + " " + description).lower()
        for pattern, category in _SEMGREP_PATTERNS.items():
            if pattern in text:
                return category, "medium"
        return "A02", "low"

    if tool == "bandit":
        mapped = _BANDIT_MAP.get(rule_id)
        if mapped:
            return mapped, "high"
        text = (title + " " + description).lower()
        for pattern, category in _SEMGREP_PATTERNS.items():
            if pattern in text:
                return category, "medium"
        return "A02", "low"

    if tool == "eslint":
        mapped = _ESLINT_MAP.get(rule_id)
        if mapped:
            return mapped, "high"
        return "A02", "low"

    if tool == "npm_audit":
        text = (title + " " + description).lower()
        for keyword, category in _NPM_KEYWORDS.items():
            if keyword in text:
                return category, "medium"
        return "A03", "low"

    if tool == "pip_audit":
        text = (title + " " + description).lower()
        for keyword, category in _PIP_AUDIT_KEYWORDS.items():
            if keyword in text:
                return category, "medium"
        return "A03", "low"

    if tool == "composer_audit":
        text = (title + " " + description).lower()
        for keyword, category in _COMPOSER_KEYWORDS.items():
            if keyword in text:
                return category, "medium"
        return "A03", "low"

    if tool == "trufflehog":
        return "A04", "high"

    if tool == "gitleaks":
        return "A04", "high"

    if tool in ("retire.js", "retirejs"):
        return "A03", "high"

    # DAST modules
    if tool == "dast_headers":
        return "A02", "high"

    if tool == "dast_ssl":
        return "A04", "high"

    if tool == "dast_dirs":
        return "A01", "high"

    if tool == "dast_cors":
        return "A02", "high"

    if tool == "dast_xss":
        return "A05", "high"

    if tool == "dast_sqli":
        return "A05", "high"

    if tool == "dast_redirect":
        return "A01", "high"

    # PWN Mon Site tools
    if tool == "pwn_nmap":
        rule_lower = rule_id.lower()
        if "dangerous-port" in rule_lower:
            return "A02", "high"
        if "nse-" in rule_lower:
            text = (title + " " + description).lower()
            if any(kw in text for kw in ("sqli", "sql", "injection", "xss")):
                return "A05", "high"
            if any(kw in text for kw in ("ssl", "tls", "crypto")):
                return "A04", "high"
            return "A01", "medium"
        return "A02", "medium"

    if tool == "pwn_sslyze":
        return "A04", "high"

    if tool == "pwn_fingerprint":
        return "A06", "medium"

    if tool == "pwn_nuclei":
        template_lower = rule_id.lower()
        text = (title + " " + description).lower()
        # Injection-related
        _inject_kw = ("sqli", "sql-injection", "xss", "ssti", "rce",
                      "command-injection", "lfi", "rfi")
        if any(kw in template_lower for kw in _inject_kw):
            return "A05", "high"
        if any(kw in template_lower for kw in ("ssrf", "open-redirect", "traversal")):
            return "A01", "high"
        if any(kw in template_lower for kw in ("misconfig", "exposed", "default-login", "admin-panel")):
            return "A02", "high"
        if any(kw in template_lower for kw in ("ssl", "tls", "weak-cipher", "heartbleed")):
            return "A04", "high"
        if any(kw in template_lower for kw in ("cve-",)):
            # CVEs default to A02 (misconfiguration / outdated software)
            if any(kw in text for kw in ("injection", "xss", "rce", "command")):
                return "A05", "high"
            if any(kw in text for kw in ("auth", "login", "password", "session")):
                return "A07", "high"
            return "A02", "high"
        if any(kw in template_lower for kw in ("auth", "login", "password", "default-credential")):
            return "A07", "high"
        if any(kw in template_lower for kw in ("outdated", "version", "eol")):
            return "A03", "medium"
        if any(kw in template_lower for kw in ("error", "stacktrace", "debug")):
            return "A10", "medium"
        if any(kw in template_lower for kw in ("log", "verbose")):
            return "A09", "medium"
        # Text-based fallback
        if any(kw in text for kw in ("injection", "xss", "sql")):
            return "A05", "medium"
        if any(kw in text for kw in ("ssl", "tls", "certificate")):
            return "A04", "medium"
        return "A02", "low"

    # Universal fallback: scan text against _SEMGREP_PATTERNS before returning UNK
    text = (rule_id + " " + title + " " + description).lower()
    for pattern, category in _SEMGREP_PATTERNS.items():
        if pattern in text:
            return category, "medium"

    logger.warning("OWASP mapping returned UNK for tool=%s rule_id=%s title=%s", tool, rule_id, title[:80])
    return "UNK", "low"


def get_owasp_label(code: str) -> str:
    """Get the full OWASP label for a category code."""
    return OWASP_CATEGORIES.get(code, "Unknown")


# ---------------------------------------------------------------------------
# OWASP Recommendations per category
# ---------------------------------------------------------------------------
OWASP_RECOMMENDATIONS = {
    "A01": {
        "en": (
            "Implement proper access controls: enforce least privilege, "
            "deny by default, validate all access on the server side. "
            "Use CORS policies and disable directory listings."
        ),
        "fr": (
            "Implementer des controles d'acces : appliquer le principe "
            "du moindre privilege, refuser par defaut, valider tous les "
            "acces cote serveur. Utiliser des politiques CORS et "
            "desactiver les listings de repertoires."
        ),
    },
    "A02": {
        "en": (
            "Harden configuration: remove default credentials, disable "
            "unnecessary features, apply security headers, and review "
            "cloud permissions regularly."
        ),
        "fr": (
            "Renforcer la configuration : supprimer les identifiants "
            "par defaut, desactiver les fonctionnalites inutiles, "
            "appliquer les en-tetes de securite, et revoir "
            "regulierement les permissions cloud."
        ),
    },
    "A03": {
        "en": (
            "Audit dependencies regularly with automated tools. Pin "
            "versions, verify package integrity, and monitor for known "
            "vulnerabilities in third-party libraries."
        ),
        "fr": (
            "Auditer regulierement les dependances avec des outils "
            "automatises. Epingler les versions, verifier l'integrite "
            "des paquets et surveiller les vulnerabilites connues."
        ),
    },
    "A04": {
        "en": (
            "Use strong encryption algorithms (AES-256, RSA-2048+). "
            "Never hardcode secrets. Rotate keys regularly and use "
            "proper key management solutions."
        ),
        "fr": (
            "Utiliser des algorithmes de chiffrement forts (AES-256, "
            "RSA-2048+). Ne jamais coder en dur les secrets. Faire "
            "tourner les cles regulierement et utiliser des solutions "
            "de gestion de cles."
        ),
    },
    "A05": {
        "en": (
            "Use parameterized queries for SQL, escape outputs for "
            "XSS, and validate/sanitize all user input. Prefer ORM "
            "methods over raw queries."
        ),
        "fr": (
            "Utiliser des requetes parametrees pour SQL, echapper les "
            "sorties pour XSS, et valider/assainir toutes les entrees "
            "utilisateur. Preferer les methodes ORM aux requetes brutes."
        ),
    },
    "A06": {
        "en": (
            "Add rate limiting, input validation, and threat modeling "
            "from the design phase. Implement CAPTCHA for sensitive "
            "operations and enforce business logic checks server-side."
        ),
        "fr": (
            "Ajouter du rate limiting, de la validation d'entree et "
            "de la modelisation de menaces des la conception. "
            "Implementer des CAPTCHA pour les operations sensibles et "
            "appliquer les regles metier cote serveur."
        ),
    },
    "A07": {
        "en": (
            "Implement multi-factor authentication, use strong "
            "password policies, and protect against credential "
            "stuffing with account lockout and rate limiting."
        ),
        "fr": (
            "Implementer l'authentification multi-facteurs, utiliser "
            "des politiques de mots de passe forts et proteger contre "
            "le bourrage d'identifiants avec le verrouillage de compte."
        ),
    },
    "A08": {
        "en": (
            "Verify software integrity with digital signatures and "
            "checksums. Use CI/CD pipeline security controls and avoid "
            "deserializing untrusted data."
        ),
        "fr": (
            "Verifier l'integrite des logiciels avec des signatures "
            "numeriques et des checksums. Utiliser des controles de "
            "securite CI/CD et eviter de deserialiser des donnees "
            "non fiables."
        ),
    },
    "A09": {
        "en": (
            "Log all authentication, access control, and input "
            "validation failures. Implement monitoring and alerting. "
            "Use structured logging and protect log integrity."
        ),
        "fr": (
            "Journaliser tous les echecs d'authentification, de "
            "controle d'acces et de validation. Implementer la "
            "surveillance et les alertes. Utiliser des logs structures "
            "et proteger leur integrite."
        ),
    },
    "A10": {
        "en": (
            "Handle all exceptions gracefully. Never expose stack "
            "traces to users. Implement proper error handling with "
            "fail-safe defaults."
        ),
        "fr": (
            "Gerer toutes les exceptions proprement. Ne jamais exposer "
            "les traces d'erreur aux utilisateurs. Implementer une "
            "gestion d'erreurs avec des valeurs par defaut securisees."
        ),
    },
}


def get_owasp_recommendation(code: str, lang: str = "en") -> str:
    """Return a human-readable recommendation for an OWASP category code."""
    rec = OWASP_RECOMMENDATIONS.get(code)
    if not rec:
        return ""
    return rec.get(lang, rec.get("en", ""))
