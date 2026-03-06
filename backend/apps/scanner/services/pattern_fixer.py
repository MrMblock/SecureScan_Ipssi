"""Deterministic pattern-based auto-fix for common vulnerabilities.

Provides regex-based fixes for well-known security patterns (SQLi, XSS, etc.)
without requiring an AI API call. Falls back to Gemini for complex cases.
"""

import re

PATTERNS = [
    # 1. SQL Injection → parameterized queries
    {
        "id": "sqli_fstring",
        "triggers": {"rule_ids": ["sql-injection", "hardcoded-sql", "S608", "tainted-sql", "B608"]},
        "match": lambda code: bool(
            re.search(
                r"""(f['"]|['"].*%s.*%|['"].*\+\s*\w+.*['"]"""
                r"""|\.format\s*\(|\.[ ]*\$)\s*"""
                r""".*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)""",
                code, re.IGNORECASE | re.DOTALL,
            )
            or re.search(
                r"""(SELECT|INSERT|UPDATE|DELETE)"""
                r""".*?(f['"]|['"].*\{|\+\s*\w+"""
                r"""|\.format\s*\(|\.[ ]*\$)""",
                code, re.IGNORECASE | re.DOTALL,
            )
        ),
        "fix": lambda code: _fix_sqli(code),
        "explanation": {
            "en": (
                "Replaced string interpolation in SQL query with "
                "parameterized query using placeholders. This prevents "
                "SQL injection by separating code from data."
            ),
            "fr": (
                "Remplacement de l'interpolation de chaîne dans la "
                "requête SQL par une requête paramétrée. Cela empêche "
                "l'injection SQL en séparant le code des données."
            ),
        },
    },
    # 2. XSS innerHTML → textContent
    {
        "id": "xss_innerhtml",
        "triggers": {"rule_ids": ["innerHTML", "xss", "no-inner-html"]},
        "match": lambda code: ".innerHTML" in code and "=" in code,
        "fix": lambda code: code.replace(".innerHTML", ".textContent"),
        "explanation": {
            "en": (
                "Replaced innerHTML with textContent to prevent "
                "XSS. textContent safely sets text without "
                "parsing HTML."
            ),
            "fr": (
                "Remplacement de innerHTML par textContent pour "
                "prévenir les XSS. textContent insère du texte "
                "sans interpréter le HTML."
            ),
        },
    },
    # 3. document.write → DOM API
    {
        "id": "document_write",
        "triggers": {"rule_ids": ["document-write", "no-document-write"]},
        "match": lambda code: "document.write(" in code,
        "fix": lambda code: re.sub(
            r"document\.write\((.+?)\)",
            r"document.body.insertAdjacentHTML('beforeend', \1)",
            code,
        ),
        "explanation": {
            "en": (
                "Replaced document.write() with "
                "insertAdjacentHTML() which is safer and doesn't "
                "overwrite the entire document."
            ),
            "fr": (
                "Remplacement de document.write() par "
                "insertAdjacentHTML() qui est plus sûr et n'écrase "
                "pas le document entier."
            ),
        },
    },
    # 4. eval() → JSON.parse
    {
        "id": "eval_to_json",
        "triggers": {"rule_ids": ["eval", "no-eval", "S307"]},
        "match": lambda code: bool(re.search(r"\beval\s*\(", code)),
        "fix": lambda code: re.sub(r"\beval\s*\((.+?)\)", r"JSON.parse(\1)", code),
        "explanation": {
            "en": (
                "Replaced eval() with JSON.parse() to prevent "
                "arbitrary code execution. JSON.parse only parses "
                "data, not code."
            ),
            "fr": (
                "Remplacement de eval() par JSON.parse() pour "
                "empêcher l'exécution de code arbitraire. "
                "JSON.parse ne traite que les données."
            ),
        },
    },
    # 5. exec() → subprocess (Python)
    {
        "id": "exec_to_subprocess",
        "triggers": {"rule_ids": ["B102"]},
        "match": lambda code: bool(re.search(r"\bexec\s*\(", code)),
        "fix": lambda code: re.sub(
            r"\bexec\s*\((.+?)\)",
            r"subprocess.run(\1, shell=False, check=True)",
            code,
        ),
        "explanation": {
            "en": (
                "Replaced exec() with subprocess.run() using "
                "shell=False. This prevents shell injection by not "
                "interpreting shell metacharacters."
            ),
            "fr": (
                "Remplacement de exec() par subprocess.run() avec "
                "shell=False. Cela empêche l'injection shell en "
                "n'interprétant pas les métacaractères."
            ),
        },
    },
    # 6. os.system → subprocess.run
    {
        "id": "os_system_to_subprocess",
        "triggers": {"rule_ids": ["B605", "B607"]},
        "match": lambda code: "os.system(" in code,
        "fix": lambda code: _fix_os_system(code),
        "explanation": {
            "en": (
                "Replaced os.system() with subprocess.run() using "
                "shlex.split(). This avoids shell injection by "
                "properly splitting command arguments."
            ),
            "fr": (
                "Remplacement de os.system() par subprocess.run() "
                "avec shlex.split(). Cela évite l'injection shell "
                "en séparant correctement les arguments."
            ),
        },
    },
    # 7. Hardcoded secret → env var
    {
        "id": "hardcoded_secret",
        "triggers": {"rule_ids": ["hardcoded", "hardcoded-credentials", "hardcoded-password", "hardcoded-secret"]},
        "match": lambda code: bool(re.search(
            r"""(?:password|secret|api_key|token|apikey|auth)\w*\s*=\s*['"][^'"]{4,}['"]""",
            code, re.IGNORECASE,
        )),
        "fix": lambda code: _fix_hardcoded_secret(code),
        "explanation": {
            "en": (
                "Replaced hardcoded secret with environment "
                "variable lookup. Secrets should never be "
                "committed to source code."
            ),
            "fr": (
                "Remplacement du secret codé en dur par une "
                "variable d'environnement. Les secrets ne doivent "
                "jamais être dans le code source."
            ),
        },
    },
    # 8. MD5/SHA1 → SHA256
    {
        "id": "weak_hash",
        "triggers": {"rule_ids": ["md5", "sha1", "B303", "B304"]},
        "match": lambda code: bool(re.search(r"\b(md5|sha1)\b", code, re.IGNORECASE)),
        "fix": lambda code: re.sub(
            r"\bmd5\b", "sha256",
            re.sub(r"\bsha1\b", "sha256", code, flags=re.IGNORECASE),
            flags=re.IGNORECASE,
        ),
        "explanation": {
            "en": (
                "Replaced weak hash algorithm (MD5/SHA1) with "
                "SHA-256. MD5 and SHA1 are cryptographically "
                "broken and vulnerable to collision attacks."
            ),
            "fr": (
                "Remplacement de l'algorithme de hachage faible "
                "(MD5/SHA1) par SHA-256. MD5 et SHA1 sont "
                "cryptographiquement cassés."
            ),
        },
    },
    # 9. DEBUG=True → False
    {
        "id": "debug_true",
        "triggers": {"rule_ids": ["debug"]},
        "match": lambda code: bool(re.search(r"\bDEBUG\s*=\s*True\b", code)),
        "fix": lambda code: re.sub(r"\bDEBUG\s*=\s*True\b", "DEBUG = False", code),
        "explanation": {
            "en": (
                "Set DEBUG to False. Debug mode in production "
                "exposes sensitive information like stack traces "
                "and configuration details."
            ),
            "fr": (
                "Passage de DEBUG à False. Le mode debug en "
                "production expose des informations sensibles "
                "comme les traces d'erreurs."
            ),
        },
    },
    # 10. CORS * → explicit origins
    {
        "id": "cors_wildcard",
        "triggers": {"rule_ids": ["cors"]},
        "match": lambda code: bool(re.search(r"""['\"]\*['\"]""", code)) and "cors" in code.lower(),
        "fix": lambda code: re.sub(r"""['\"](\*)['\"]""", '"https://your-domain.com"', code),
        "explanation": {
            "en": (
                "Replaced CORS wildcard (*) with an explicit "
                "origin. Wildcard CORS allows any website to make "
                "requests to your API."
            ),
            "fr": (
                "Remplacement du wildcard CORS (*) par une "
                "origine explicite. Le wildcard permet à "
                "n'importe quel site d'accéder à votre API."
            ),
        },
    },
    # 11. Cookie without security flags
    {
        "id": "insecure_cookie",
        "triggers": {"rule_ids": ["cookie", "insecure-cookie", "missing-secure-flag"]},
        "match": lambda code: bool(
            re.search(r"set_cookie\s*\(", code)
            and not re.search(
                r"httponly\s*=\s*True", code, re.IGNORECASE,
            )
        ),
        "fix": lambda code: _fix_cookie(code),
        "explanation": {
            "en": (
                "Added httponly, secure, and samesite flags to "
                "cookie. These flags prevent XSS cookie theft "
                "and CSRF attacks."
            ),
            "fr": (
                "Ajout des flags httponly, secure et samesite au "
                "cookie. Ces flags empêchent le vol de cookies "
                "par XSS et les attaques CSRF."
            ),
        },
    },
    # 12. pickle.loads → json.loads
    {
        "id": "pickle_loads",
        "triggers": {"rule_ids": ["B301"]},
        "match": lambda code: "pickle.loads(" in code or "pickle.load(" in code,
        "fix": lambda code: code.replace("pickle.loads(", "json.loads(").replace("pickle.load(", "json.load("),
        "explanation": {
            "en": (
                "Replaced pickle with json for deserialization. "
                "Pickle can execute arbitrary code during "
                "deserialization, making it unsafe for "
                "untrusted data."
            ),
            "fr": (
                "Remplacement de pickle par json pour la "
                "désérialisation. Pickle peut exécuter du code "
                "arbitraire, ce qui est dangereux pour des "
                "données non fiables."
            ),
        },
    },
    # 13. yaml.load → yaml.safe_load
    {
        "id": "yaml_unsafe_load",
        "triggers": {"rule_ids": ["B506"]},
        "match": lambda code: bool(re.search(r"yaml\.load\s*\(", code)),
        "fix": lambda code: re.sub(r"yaml\.load\s*\(", "yaml.safe_load(", code),
        "explanation": {
            "en": (
                "Replaced yaml.load() with yaml.safe_load(). "
                "yaml.load can execute arbitrary Python code "
                "embedded in YAML documents."
            ),
            "fr": (
                "Remplacement de yaml.load() par yaml.safe_load(). "
                "yaml.load peut exécuter du code Python arbitraire "
                "intégré dans les documents YAML."
            ),
        },
    },
    # 14. requests verify=False → verify=True
    {
        "id": "requests_no_verify",
        "triggers": {"rule_ids": ["B501"]},
        "match": lambda code: "verify=False" in code,
        "fix": lambda code: code.replace("verify=False", "verify=True"),
        "explanation": {
            "en": (
                "Changed verify=False to verify=True to enforce "
                "SSL certificate verification. Disabling "
                "verification allows man-in-the-middle attacks."
            ),
            "fr": (
                "Changement de verify=False à verify=True pour "
                "vérifier les certificats SSL. Désactiver la "
                "vérification permet les attaques "
                "man-in-the-middle."
            ),
        },
    },
    # 15. mktemp → mkstemp
    {
        "id": "mktemp_to_mkstemp",
        "triggers": {"rule_ids": ["B108"]},
        "match": lambda code: "mktemp(" in code,
        "fix": lambda code: code.replace("mktemp(", "mkstemp("),
        "explanation": {
            "en": (
                "Replaced mktemp() with mkstemp(). mktemp is "
                "vulnerable to race conditions where an attacker "
                "can create the file before your program."
            ),
            "fr": (
                "Remplacement de mktemp() par mkstemp(). mktemp "
                "est vulnérable aux conditions de concurrence "
                "(race conditions)."
            ),
        },
    },
    # 16. shell=True in subprocess → shell=False
    {
        "id": "shell_true",
        "triggers": {"rule_ids": ["B602", "B604", "subprocess-shell-true", "shell-injection"]},
        "match": lambda code: "shell=True" in code,
        "fix": lambda code: code.replace("shell=True", "shell=False"),
        "explanation": {
            "en": (
                "Changed shell=True to shell=False in subprocess "
                "call. shell=True allows shell injection via "
                "metacharacters in user input."
            ),
            "fr": (
                "Changement de shell=True a shell=False dans "
                "l'appel subprocess. shell=True permet l'injection "
                "shell via les metacaracteres."
            ),
        },
    },
    # 17. random.random() for security → secrets.token_hex()
    {
        "id": "random_to_secrets",
        "triggers": {"rule_ids": ["B311", "pseudo-random", "insecure-random"]},
        "match": lambda code: bool(re.search(r"\brandom\.(random|randint|choice|randrange)\s*\(", code)),
        "fix": lambda code: re.sub(
            r"\brandom\.(random|randint|choice|randrange)\s*\([^)]*\)",
            "secrets.token_hex(16)",
            code,
        ),
        "explanation": {
            "en": (
                "Replaced random module with secrets.token_hex() "
                "for cryptographically secure random generation. "
                "The random module is not suitable for security "
                "purposes."
            ),
            "fr": (
                "Remplacement du module random par "
                "secrets.token_hex() pour une generation aleatoire "
                "cryptographiquement sure. Le module random n'est "
                "pas adapte a la securite."
            ),
        },
    },
    # 18. assert in production code → if not: raise ValueError
    {
        "id": "assert_to_raise",
        "triggers": {"rule_ids": ["B101", "assert-used", "no-assert"]},
        "match": lambda code: bool(re.search(r"\bassert\s+", code)),
        "fix": lambda code: _fix_assert(code),
        "explanation": {
            "en": (
                "Replaced assert with explicit if/raise. Assert "
                "statements are stripped when Python runs with -O "
                "flag, silently removing security checks."
            ),
            "fr": (
                "Remplacement de assert par if/raise explicite. "
                "Les assertions sont supprimees avec le flag -O "
                "de Python, retirant silencieusement les "
                "verifications de securite."
            ),
        },
    },
    # 19. chmod 777 / overly permissive file permissions → 0o755
    {
        "id": "chmod_777",
        "triggers": {"rule_ids": ["B103", "chmod", "file-permissions"]},
        "match": lambda code: bool(re.search(r"0o?777", code)),
        "fix": lambda code: re.sub(r"0o?777", "0o755", code),
        "explanation": {
            "en": (
                "Changed file permissions from 777 "
                "(world-writable) to 755. World-writable files "
                "can be modified by any user on the system."
            ),
            "fr": (
                "Changement des permissions de 777 (ecriture pour "
                "tous) a 755. Les fichiers accessibles en ecriture "
                "a tous peuvent etre modifies par n'importe quel "
                "utilisateur."
            ),
        },
    },
    # 20. Telnet/FTP → recommendation SSH/SFTP
    {
        "id": "telnet_ftp_to_ssh",
        "triggers": {"rule_ids": ["B401", "B402", "telnet", "ftp", "cleartext-protocol"]},
        "match": lambda code: bool(re.search(r"\b(telnetlib|ftplib)\b", code)),
        "fix": lambda code: re.sub(r"\btelnetlib\b", "paramiko  # Use SSH instead of Telnet", code).replace(
            "ftplib", "paramiko  # Use SFTP instead of FTP"
        ),
        "explanation": {
            "en": (
                "Replaced Telnet/FTP with SSH/SFTP (paramiko). "
                "Telnet and FTP transmit data in cleartext, "
                "exposing credentials and data to network "
                "sniffing."
            ),
            "fr": (
                "Remplacement de Telnet/FTP par SSH/SFTP "
                "(paramiko). Telnet et FTP transmettent les "
                "donnees en clair, exposant les identifiants "
                "au sniffing reseau."
            ),
        },
    },
]


def _fix_sqli(code: str) -> str:
    """Replace f-string/concat SQL with parameterized query."""
    # PHP concat: "SELECT ... WHERE id = " . $id → prepared statement
    m = re.search(r"""(['"])(.*?)\1\s*\.\s*(\$\w+)""", code)
    if m:
        _, body, var = m.group(1), m.group(2), m.group(3)
        placeholder = "?"
        prepared = (
            f'"{body}{placeholder}"  /* use prepared: '
            f"$stmt = $pdo->prepare(...); "
            f"$stmt->execute([{var}]); */"
        )
        return code[:m.start()] + prepared + code[m.end():]
    # Python f-string: f"SELECT ... WHERE x = {var}" → "SELECT ... WHERE x = %s", (var,)
    m = re.search(r"""f(['"])(.*?)\1""", code)
    if m:
        _, body = m.group(1), m.group(2)
        params = re.findall(r"\{(\w+)\}", body)
        new_body = re.sub(r"\{(\w+)\}", "%s", body)
        params_str = ", ".join(params)
        replacement = f'"{new_body}", ({params_str},)'
        return code[:m.start()] + replacement + code[m.end():]
    # Python/JS string concat: "SELECT ... " + var → "SELECT ... %s", (var,)
    m = re.search(r"""(['"])(.*?)\1\s*\+\s*(\w+)""", code)
    if m:
        _, body, var = m.group(1), m.group(2), m.group(3)
        return code[:m.start()] + f'"{body}%s", ({var},)' + code[m.end():]
    return code


def _fix_os_system(code: str) -> str:
    """Replace os.system(cmd) with subprocess.run(shlex.split(cmd))."""
    return re.sub(
        r"os\.system\((.+?)\)",
        r"subprocess.run(shlex.split(\1), check=True)",
        code,
    )


def _fix_hardcoded_secret(code: str) -> str:
    """Replace hardcoded secret value with env var lookup."""
    def replacer(m: re.Match) -> str:
        name = m.group(1).upper()
        return f'{m.group(1)} = os.environ.get("{name}")'

    return re.sub(
        r"""((?:password|secret|api_key|token|apikey|auth)\w*)\s*=\s*['"][^'"]+['"]""",
        replacer,
        code,
        flags=re.IGNORECASE,
    )


def _fix_assert(code: str) -> str:
    """Replace assert statements with if/raise."""
    def replacer(m: re.Match) -> str:
        condition = m.group(1).strip()
        msg = m.group(2)
        if msg:
            return f"if not ({condition}):\n    raise ValueError({msg.strip()})"
        return f'if not ({condition}):\n    raise ValueError("{condition}")'

    return re.sub(r"\bassert\s+(.+?)(?:,\s*(.+))?$", replacer, code, flags=re.MULTILINE)


def _fix_cookie(code: str) -> str:
    """Add security flags to set_cookie call."""
    if "httponly" not in code.lower():
        code = re.sub(
            r"(set_cookie\s*\([^)]+)\)",
            r"\1, httponly=True, secure=True, samesite='Lax')",
            code,
        )
    return code


def try_pattern_fix(finding, lang: str = "en") -> dict | None:
    """Try to fix a finding using deterministic patterns.

    Returns a dict with fixed_code/fix_explanation if a pattern matches, or None.
    """
    code = finding.code_snippet or ""
    rule_id = (finding.rule_id or "").strip()
    tool = (finding.tool or "").strip().lower()
    title = (finding.title or "").lower()

    if not code:
        return None

    for pattern in PATTERNS:
        triggers = pattern["triggers"]
        trigger_ids = triggers.get("rule_ids", [])

        # Check if rule_id or title matches any trigger
        matched = False
        for tid in trigger_ids:
            tid_lower = tid.lower()
            if tid_lower == rule_id.lower() or tid_lower in rule_id.lower():
                matched = True
                break
            if tid_lower in title or tid_lower.replace("-", " ") in title:
                matched = True
                break
            if tid_lower in tool:
                matched = True
                break

        if not matched:
            continue

        # Check if the code matches the pattern
        if not pattern["match"](code):
            continue

        fixed_code = pattern["fix"](code)
        if fixed_code == code:
            continue

        explanation = pattern["explanation"].get(lang, pattern["explanation"]["en"])

        return {
            "fixed_code": fixed_code,
            "fix_explanation": explanation,
            "original_code": code,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "pattern_id": pattern["id"],
            "cached": False,
        }

    return None
