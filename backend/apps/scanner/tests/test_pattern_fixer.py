"""Tests exhaustifs pour le pattern fixer déterministe.

Chaque pattern est testé avec plusieurs extraits de code vulnérable réalistes.
On vérifie à chaque fois :
  1. Le résultat n'est pas None (pattern reconnu)
  2. Le code corrigé ne contient plus la vulnérabilité
  3. Le code corrigé contient la bonne correction
  4. L'explication (FR et EN) est présente et pertinente
  5. Le pattern_id est correct
  6. Les métadonnées (file_path, line_start, original_code) sont préservées
"""

from types import SimpleNamespace

import pytest

from apps.scanner.services.pattern_fixer import try_pattern_fix

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_finding(**kwargs):
    """Crée un objet finding simulé."""
    defaults = {
        "code_snippet": "",
        "rule_id": "",
        "tool": "",
        "title": "",
        "file_path": "app/vulnerable.py",
        "line_start": 10,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _assert_fix_metadata(result, *, pattern_id, file_path="app/vulnerable.py", line_start=10):
    """Vérifie les métadonnées communes à toute correction."""
    assert result is not None, "Le pattern aurait dû matcher"
    assert result["pattern_id"] == pattern_id
    assert result["file_path"] == file_path
    assert result["line_start"] == line_start
    assert result["cached"] is False
    assert result["original_code"]  # on a bien gardé le code original
    assert result["fixed_code"] != result["original_code"], "Le fix doit modifier le code"
    assert len(result["fix_explanation"]) > 20, "L'explication doit être substantielle"


# ===================================================================
# Pattern 1 — SQL Injection → requêtes paramétrées
# ===================================================================

class TestSQLInjection:
    """Tests pour la correction d'injections SQL (f-strings, concaténation)."""

    def test_fstring_select_where(self):
        """SELECT avec f-string et variable dans WHERE."""
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        result = try_pattern_fix(_make_finding(rule_id="sql-injection", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="sqli_fstring")
        assert "%s" in result["fixed_code"]
        assert "user_id" in result["fixed_code"]
        assert 'f"' not in result["fixed_code"]

    def test_fstring_select_where_explanation_en(self):
        """L'explication EN mentionne 'parameterized' et 'injection'."""
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        result = try_pattern_fix(_make_finding(rule_id="sql-injection", code_snippet=code), lang="en")
        assert "parameterized" in result["fix_explanation"].lower()
        assert "injection" in result["fix_explanation"].lower()

    def test_fstring_select_where_explanation_fr(self):
        """L'explication FR mentionne 'paramétrée' et 'injection'."""
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        result = try_pattern_fix(_make_finding(rule_id="sql-injection", code_snippet=code), lang="fr")
        assert "paramétrée" in result["fix_explanation"].lower()
        assert "injection" in result["fix_explanation"].lower()

    def test_fstring_delete_query(self):
        """DELETE avec f-string."""
        code = 'db.execute(f"DELETE FROM orders WHERE order_id = {oid}")'
        result = try_pattern_fix(_make_finding(rule_id="sql-injection", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="sqli_fstring")
        assert "%s" in result["fixed_code"]
        assert "oid" in result["fixed_code"]
        assert 'f"' not in result["fixed_code"]

    def test_fstring_insert_query(self):
        """INSERT avec f-string et plusieurs variables."""
        code = 'cursor.execute(f"INSERT INTO logs (user, action) VALUES ({user}, {action})")'
        result = try_pattern_fix(_make_finding(rule_id="sql-injection", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="sqli_fstring")
        assert result["fixed_code"].count("%s") == 2
        assert "user" in result["fixed_code"]
        assert "action" in result["fixed_code"]

    def test_fstring_update_query(self):
        """UPDATE avec f-string."""
        code = 'cursor.execute(f"UPDATE users SET email = {new_email} WHERE id = {uid}")'
        result = try_pattern_fix(_make_finding(rule_id="sql-injection", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="sqli_fstring")
        assert result["fixed_code"].count("%s") == 2

    def test_concat_select(self):
        """SELECT avec concaténation de chaîne."""
        code = 'cursor.execute("SELECT * FROM products WHERE name = " + product_name)'
        result = try_pattern_fix(_make_finding(rule_id="sql-injection", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="sqli_fstring")
        assert "%s" in result["fixed_code"]
        assert "product_name" in result["fixed_code"]
        assert "+" not in result["fixed_code"]

    def test_trigger_via_hardcoded_sql_rule(self):
        """Le pattern se déclenche aussi avec le rule_id 'hardcoded-sql'."""
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        result = try_pattern_fix(_make_finding(rule_id="hardcoded-sql", code_snippet=code))
        assert result is not None
        assert result["pattern_id"] == "sqli_fstring"

    def test_trigger_via_s608_rule(self):
        """Le pattern se déclenche aussi avec le rule_id bandit 'S608'."""
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        result = try_pattern_fix(_make_finding(rule_id="S608", code_snippet=code))
        assert result is not None
        assert result["pattern_id"] == "sqli_fstring"


# ===================================================================
# Pattern 2 — XSS innerHTML → textContent
# ===================================================================

class TestXSSInnerHTML:
    """Tests pour la correction XSS via innerHTML."""

    def test_simple_innerhtml_assignment(self):
        """Assignation directe innerHTML = userInput."""
        code = 'element.innerHTML = userInput;'
        result = try_pattern_fix(_make_finding(rule_id="innerHTML", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="xss_innerhtml")
        assert "textContent" in result["fixed_code"]
        assert "innerHTML" not in result["fixed_code"]

    def test_innerhtml_with_template_literal(self):
        """innerHTML avec template literal JS."""
        code = 'document.getElementById("output").innerHTML = `<p>${data}</p>`;'
        result = try_pattern_fix(_make_finding(rule_id="xss", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="xss_innerhtml")
        assert ".textContent" in result["fixed_code"]

    def test_innerhtml_in_function_body(self):
        """innerHTML dans le corps d'une fonction."""
        code = 'function render(html) { container.innerHTML = html; }'
        result = try_pattern_fix(_make_finding(rule_id="no-inner-html", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="xss_innerhtml")
        assert "textContent" in result["fixed_code"]
        assert "innerHTML" not in result["fixed_code"]

    def test_explanation_mentions_xss_en(self):
        """L'explication EN mentionne XSS."""
        code = 'el.innerHTML = val;'
        result = try_pattern_fix(_make_finding(rule_id="innerHTML", code_snippet=code), lang="en")
        assert "xss" in result["fix_explanation"].lower()

    def test_explanation_mentions_xss_fr(self):
        """L'explication FR mentionne XSS."""
        code = 'el.innerHTML = val;'
        result = try_pattern_fix(_make_finding(rule_id="innerHTML", code_snippet=code), lang="fr")
        assert "xss" in result["fix_explanation"].lower()

    def test_trigger_via_title_match(self):
        """Le pattern matche via le title contenant 'innerHTML'."""
        code = 'el.innerHTML = x;'
        result = try_pattern_fix(_make_finding(
            rule_id="some-custom-rule",
            title="Avoid innerHTML assignment for XSS prevention",
            code_snippet=code,
        ))
        assert result is not None
        assert result["pattern_id"] == "xss_innerhtml"


# ===================================================================
# Pattern 3 — document.write → DOM API
# ===================================================================

class TestDocumentWrite:
    """Tests pour la correction de document.write."""

    def test_simple_document_write(self):
        """document.write(content) simple."""
        code = 'document.write(content)'
        result = try_pattern_fix(_make_finding(rule_id="document-write", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="document_write")
        assert "insertAdjacentHTML" in result["fixed_code"]
        assert "beforeend" in result["fixed_code"]
        assert "document.write" not in result["fixed_code"]

    def test_document_write_with_html_string(self):
        """document.write avec chaîne HTML."""
        code = 'document.write("<h1>Hello " + name + "</h1>")'
        result = try_pattern_fix(_make_finding(rule_id="document-write", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="document_write")
        assert "insertAdjacentHTML" in result["fixed_code"]

    def test_document_write_with_variable(self):
        """document.write avec variable seule."""
        code = 'document.write(userHtml)'
        result = try_pattern_fix(_make_finding(rule_id="no-document-write", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="document_write")
        assert "userHtml" in result["fixed_code"]

    def test_explanation_en(self):
        code = 'document.write(x)'
        result = try_pattern_fix(_make_finding(rule_id="document-write", code_snippet=code), lang="en")
        assert "document.write" in result["fix_explanation"].lower() or "overwrite" in result["fix_explanation"].lower()

    def test_explanation_fr(self):
        code = 'document.write(x)'
        result = try_pattern_fix(_make_finding(rule_id="document-write", code_snippet=code), lang="fr")
        assert "document.write" in result["fix_explanation"].lower() or "écrase" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 4 — eval() → JSON.parse
# ===================================================================

class TestEval:
    """Tests pour la correction eval() → JSON.parse()."""

    def test_eval_with_variable(self):
        """eval(data) → JSON.parse(data)."""
        code = 'const config = eval(jsonString);'
        result = try_pattern_fix(_make_finding(rule_id="no-eval", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="eval_to_json")
        assert "JSON.parse(jsonString)" in result["fixed_code"]
        assert "eval" not in result["fixed_code"]

    def test_eval_with_response_text(self):
        """eval(response.text) → JSON.parse(response.text)."""
        code = 'var data = eval(response.text);'
        result = try_pattern_fix(_make_finding(rule_id="eval", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="eval_to_json")
        assert "JSON.parse" in result["fixed_code"]

    def test_eval_inline(self):
        """eval dans une expression inline."""
        code = 'return eval(input);'
        result = try_pattern_fix(_make_finding(rule_id="S307", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="eval_to_json")
        assert "JSON.parse(input)" in result["fixed_code"]

    def test_explanation_mentions_code_execution_en(self):
        code = 'eval(x)'
        result = try_pattern_fix(_make_finding(rule_id="eval", code_snippet=code), lang="en")
        assert "code execution" in result["fix_explanation"].lower() or "arbitrary" in result["fix_explanation"].lower()

    def test_explanation_mentions_code_execution_fr(self):
        code = 'eval(x)'
        result = try_pattern_fix(_make_finding(rule_id="eval", code_snippet=code), lang="fr")
        explanation = result["fix_explanation"].lower()
        assert "code arbitraire" in explanation or "exécution" in explanation


# ===================================================================
# Pattern 5 — exec() → subprocess
# ===================================================================

class TestExec:
    """Tests pour exec() → subprocess.run()."""

    def test_exec_simple_command(self):
        """exec(cmd) basique."""
        code = 'exec(user_command)'
        result = try_pattern_fix(_make_finding(rule_id="B102", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="exec_to_subprocess")
        assert "subprocess.run(user_command, shell=False, check=True)" in result["fixed_code"]

    def test_exec_with_variable_in_context(self):
        """exec dans un contexte plus large."""
        code = 'result = exec(cmd_string)'
        result = try_pattern_fix(_make_finding(rule_id="B102", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="exec_to_subprocess")
        assert "subprocess.run" in result["fixed_code"]
        assert "shell=False" in result["fixed_code"]

    def test_exec_with_f_string_command(self):
        """exec avec f-string."""
        code = 'exec(f"ls {directory}")'
        result = try_pattern_fix(_make_finding(rule_id="B102", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="exec_to_subprocess")
        assert "subprocess.run" in result["fixed_code"]

    def test_explanation_mentions_shell_injection_en(self):
        code = 'exec(cmd)'
        result = try_pattern_fix(_make_finding(rule_id="B102", code_snippet=code), lang="en")
        assert "shell" in result["fix_explanation"].lower() or "injection" in result["fix_explanation"].lower()

    def test_explanation_mentions_shell_injection_fr(self):
        code = 'exec(cmd)'
        result = try_pattern_fix(_make_finding(rule_id="B102", code_snippet=code), lang="fr")
        assert "shell" in result["fix_explanation"].lower() or "injection" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 6 — os.system → subprocess.run
# ===================================================================

class TestOsSystem:
    """Tests pour os.system() → subprocess.run(shlex.split(...))."""

    def test_os_system_with_variable(self):
        """os.system(cmd) basique."""
        code = 'os.system(cmd)'
        result = try_pattern_fix(_make_finding(rule_id="B605", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="os_system_to_subprocess")
        assert "subprocess.run(shlex.split(cmd), check=True)" in result["fixed_code"]
        assert "os.system" not in result["fixed_code"]

    def test_os_system_with_string_literal(self):
        """os.system avec commande en dur."""
        code = 'os.system("rm -rf /tmp/data")'
        result = try_pattern_fix(_make_finding(rule_id="B605", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="os_system_to_subprocess")
        assert "shlex.split" in result["fixed_code"]
        assert "os.system" not in result["fixed_code"]

    def test_os_system_with_fstring(self):
        """os.system avec f-string."""
        code = 'os.system(f"ping {host}")'
        result = try_pattern_fix(_make_finding(rule_id="B607", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="os_system_to_subprocess")
        assert "subprocess.run" in result["fixed_code"]

    def test_trigger_via_b607(self):
        """Le rule_id B607 déclenche le même pattern."""
        code = 'os.system(command)'
        result = try_pattern_fix(_make_finding(rule_id="B607", code_snippet=code))
        assert result is not None
        assert result["pattern_id"] == "os_system_to_subprocess"

    def test_explanation_mentions_shlex_en(self):
        code = 'os.system(cmd)'
        result = try_pattern_fix(_make_finding(rule_id="B605", code_snippet=code), lang="en")
        assert "shell" in result["fix_explanation"].lower()

    def test_explanation_mentions_shlex_fr(self):
        code = 'os.system(cmd)'
        result = try_pattern_fix(_make_finding(rule_id="B605", code_snippet=code), lang="fr")
        assert "shell" in result["fix_explanation"].lower() or "injection" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 7 — Hardcoded secret → env var
# ===================================================================

class TestHardcodedSecret:
    """Tests pour les secrets codés en dur → variables d'environnement."""

    def test_hardcoded_password(self):
        """password = "..." → os.environ.get("PASSWORD")."""
        code = 'password = "super_secret_123"'
        result = try_pattern_fix(_make_finding(rule_id="hardcoded", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="hardcoded_secret")
        assert 'os.environ.get("PASSWORD")' in result["fixed_code"]
        assert "super_secret_123" not in result["fixed_code"]

    def test_hardcoded_api_key(self):
        """api_key = "sk-..." → os.environ.get("API_KEY")."""
        code = 'api_key = "sk-1234567890abcdef"'
        result = try_pattern_fix(_make_finding(rule_id="hardcoded-secret", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="hardcoded_secret")
        assert 'os.environ.get("API_KEY")' in result["fixed_code"]
        assert "sk-1234567890abcdef" not in result["fixed_code"]

    def test_hardcoded_token(self):
        """token = "..." → os.environ.get("TOKEN")."""
        code = 'token = "ghp_xxxxxxxxxxxxxxxxxxxx"'
        result = try_pattern_fix(_make_finding(rule_id="hardcoded", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="hardcoded_secret")
        assert 'os.environ.get("TOKEN")' in result["fixed_code"]

    def test_hardcoded_secret_key(self):
        """secret_key = "..." → os.environ.get("SECRET_KEY")."""
        code = "secret_key = 'django-insecure-k3y-v4lue-here!'"
        result = try_pattern_fix(_make_finding(rule_id="hardcoded-credentials", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="hardcoded_secret")
        assert 'os.environ.get("SECRET_KEY")' in result["fixed_code"]

    def test_hardcoded_auth_token(self):
        """auth_token = "..." → os.environ.get("AUTH_TOKEN")."""
        code = 'auth_token = "Bearer eyJhbGciOiJIUzI1NiJ9..."'
        result = try_pattern_fix(_make_finding(rule_id="hardcoded-password", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="hardcoded_secret")
        assert 'os.environ.get("AUTH_TOKEN")' in result["fixed_code"]

    def test_hardcoded_apikey_camelcase(self):
        """apiKey = "..." (camelCase) → os.environ.get("APIKEY")."""
        code = 'apiKey = "AKIAIOSFODNN7EXAMPLE"'
        result = try_pattern_fix(_make_finding(rule_id="hardcoded", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="hardcoded_secret")
        assert "os.environ.get" in result["fixed_code"]
        assert "AKIAIOSFODNN7EXAMPLE" not in result["fixed_code"]

    def test_short_value_not_matched(self):
        """Valeur trop courte (<4 chars) ne devrait pas matcher."""
        code = 'password = "ab"'
        result = try_pattern_fix(_make_finding(rule_id="hardcoded", code_snippet=code))
        assert result is None

    def test_explanation_mentions_env_en(self):
        code = 'password = "leaked_secret"'
        result = try_pattern_fix(_make_finding(rule_id="hardcoded", code_snippet=code), lang="en")
        assert "environment" in result["fix_explanation"].lower() or "source code" in result["fix_explanation"].lower()

    def test_explanation_mentions_env_fr(self):
        code = 'password = "leaked_secret"'
        result = try_pattern_fix(_make_finding(rule_id="hardcoded", code_snippet=code), lang="fr")
        explanation = result["fix_explanation"].lower()
        assert "environnement" in explanation or "code source" in explanation


# ===================================================================
# Pattern 8 — MD5/SHA1 → SHA256
# ===================================================================

class TestWeakHash:
    """Tests pour le remplacement MD5/SHA1 → SHA-256."""

    def test_hashlib_md5(self):
        """hashlib.md5(data) → hashlib.sha256(data)."""
        code = 'digest = hashlib.md5(data).hexdigest()'
        result = try_pattern_fix(_make_finding(rule_id="B303", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="weak_hash")
        assert "sha256" in result["fixed_code"]
        assert "md5" not in result["fixed_code"]

    def test_hashlib_sha1(self):
        """hashlib.sha1(data) → hashlib.sha256(data)."""
        code = 'h = hashlib.sha1(password.encode()).hexdigest()'
        result = try_pattern_fix(_make_finding(rule_id="B304", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="weak_hash")
        assert "sha256" in result["fixed_code"]
        assert "sha1" not in result["fixed_code"].lower()

    def test_md5_new(self):
        """hashlib.new("md5") → hashlib.new("sha256")."""
        code = 'h = hashlib.new("md5")'
        result = try_pattern_fix(_make_finding(rule_id="md5", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="weak_hash")
        assert "sha256" in result["fixed_code"]

    def test_md5_in_longer_code(self):
        """MD5 dans un contexte de code plus long."""
        code = 'checksum = hashlib.md5(open(filepath, "rb").read()).hexdigest()'
        result = try_pattern_fix(_make_finding(rule_id="B303", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="weak_hash")
        assert "sha256" in result["fixed_code"]
        assert "md5" not in result["fixed_code"]

    def test_trigger_via_title_md5(self):
        """Trigger via titre contenant 'md5'."""
        code = 'hashlib.md5(data)'
        result = try_pattern_fix(_make_finding(
            rule_id="some-rule",
            title="Use of weak MD5 hash function",
            code_snippet=code,
        ))
        assert result is not None
        assert result["pattern_id"] == "weak_hash"

    def test_explanation_mentions_collision_en(self):
        code = 'hashlib.md5(data)'
        result = try_pattern_fix(_make_finding(rule_id="B303", code_snippet=code), lang="en")
        assert "collision" in result["fix_explanation"].lower() or "broken" in result["fix_explanation"].lower()

    def test_explanation_mentions_collision_fr(self):
        code = 'hashlib.md5(data)'
        result = try_pattern_fix(_make_finding(rule_id="B303", code_snippet=code), lang="fr")
        assert "cassé" in result["fix_explanation"].lower() or "sha-256" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 9 — DEBUG=True → False
# ===================================================================

class TestDebugTrue:
    """Tests pour DEBUG = True → DEBUG = False."""

    def test_debug_true_simple(self):
        """DEBUG = True basique."""
        code = 'DEBUG = True'
        result = try_pattern_fix(_make_finding(rule_id="debug", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="debug_true")
        assert "DEBUG = False" in result["fixed_code"]
        assert "True" not in result["fixed_code"]

    def test_debug_true_in_settings(self):
        """DEBUG = True dans un fichier settings Django."""
        code = 'DEBUG = True  # SECURITY WARNING: don\'t run with debug turned on!'
        result = try_pattern_fix(_make_finding(
            rule_id="debug",
            code_snippet=code,
            file_path="config/settings/production.py",
        ))
        _assert_fix_metadata(result, pattern_id="debug_true", file_path="config/settings/production.py")
        assert "DEBUG = False" in result["fixed_code"]

    def test_debug_false_not_matched(self):
        """DEBUG = False ne doit PAS matcher (déjà sécurisé)."""
        code = 'DEBUG = False'
        result = try_pattern_fix(_make_finding(rule_id="debug", code_snippet=code))
        assert result is None

    def test_explanation_mentions_production_en(self):
        code = 'DEBUG = True'
        result = try_pattern_fix(_make_finding(rule_id="debug", code_snippet=code), lang="en")
        assert "production" in result["fix_explanation"].lower() or "sensitive" in result["fix_explanation"].lower()

    def test_explanation_mentions_production_fr(self):
        code = 'DEBUG = True'
        result = try_pattern_fix(_make_finding(rule_id="debug", code_snippet=code), lang="fr")
        assert "production" in result["fix_explanation"].lower() or "sensible" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 10 — CORS * → explicit origins
# ===================================================================

class TestCORSWildcard:
    """Tests pour CORS wildcard * → origine explicite."""

    def test_cors_allowed_origins_star(self):
        """CORS_ALLOWED_ORIGINS = "*"."""
        code = 'CORS_ALLOWED_ORIGINS = "*"'
        result = try_pattern_fix(_make_finding(rule_id="cors", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="cors_wildcard")
        assert "*" not in result["fixed_code"]
        assert "https://" in result["fixed_code"]

    def test_cors_origin_header_star(self):
        """Access-Control-Allow-Origin: *."""
        code = "CORS_ORIGIN_WHITELIST = ['*']"
        result = try_pattern_fix(_make_finding(rule_id="cors", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="cors_wildcard")
        assert "*" not in result["fixed_code"]

    def test_cors_with_single_quotes(self):
        """CORS avec guillemets simples."""
        code = "CORS_ALLOWED_ORIGINS = '*'"
        result = try_pattern_fix(_make_finding(rule_id="cors", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="cors_wildcard")
        assert "*" not in result["fixed_code"]

    def test_explanation_mentions_any_website_en(self):
        code = 'CORS_ALLOWED_ORIGINS = "*"'
        result = try_pattern_fix(_make_finding(rule_id="cors", code_snippet=code), lang="en")
        assert "any" in result["fix_explanation"].lower() or "wildcard" in result["fix_explanation"].lower()

    def test_explanation_mentions_any_website_fr(self):
        code = 'CORS_ALLOWED_ORIGINS = "*"'
        result = try_pattern_fix(_make_finding(rule_id="cors", code_snippet=code), lang="fr")
        assert "n'importe quel" in result["fix_explanation"].lower() or "wildcard" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 11 — Cookie sans flags de sécurité
# ===================================================================

class TestInsecureCookie:
    """Tests pour l'ajout de flags de sécurité aux cookies."""

    def test_set_cookie_without_flags(self):
        """set_cookie basique sans flags."""
        code = 'response.set_cookie("session", value)'
        result = try_pattern_fix(_make_finding(rule_id="cookie", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="insecure_cookie")
        assert "httponly=True" in result["fixed_code"]
        assert "secure=True" in result["fixed_code"]
        assert "samesite" in result["fixed_code"]

    def test_set_cookie_with_max_age(self):
        """set_cookie avec max_age mais sans flags de sécurité."""
        code = 'response.set_cookie("token", jwt_token, max_age=3600)'
        result = try_pattern_fix(_make_finding(rule_id="insecure-cookie", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="insecure_cookie")
        assert "httponly=True" in result["fixed_code"]
        assert "secure=True" in result["fixed_code"]
        assert "max_age=3600" in result["fixed_code"]  # le paramètre existant est conservé

    def test_set_cookie_with_path(self):
        """set_cookie avec path."""
        code = 'response.set_cookie("csrf", csrf_value, path="/")'
        result = try_pattern_fix(_make_finding(rule_id="missing-secure-flag", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="insecure_cookie")
        assert "httponly=True" in result["fixed_code"]

    def test_cookie_already_secure_not_matched(self):
        """Cookie déjà sécurisé ne devrait PAS matcher."""
        code = 'response.set_cookie("session", value, httponly=True, secure=True)'
        result = try_pattern_fix(_make_finding(rule_id="cookie", code_snippet=code))
        assert result is None

    def test_explanation_mentions_xss_csrf_en(self):
        code = 'response.set_cookie("session", value)'
        result = try_pattern_fix(_make_finding(rule_id="cookie", code_snippet=code), lang="en")
        assert "xss" in result["fix_explanation"].lower() or "csrf" in result["fix_explanation"].lower()

    def test_explanation_mentions_xss_csrf_fr(self):
        code = 'response.set_cookie("session", value)'
        result = try_pattern_fix(_make_finding(rule_id="cookie", code_snippet=code), lang="fr")
        assert "xss" in result["fix_explanation"].lower() or "csrf" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 12 — pickle.loads → json.loads
# ===================================================================

class TestPickleLoads:
    """Tests pour pickle → json."""

    def test_pickle_loads(self):
        """pickle.loads(payload) → json.loads(payload)."""
        code = 'data = pickle.loads(payload)'
        result = try_pattern_fix(_make_finding(rule_id="B301", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="pickle_loads")
        assert "json.loads(payload)" in result["fixed_code"]
        assert "pickle" not in result["fixed_code"]

    def test_pickle_load_from_file(self):
        """pickle.load(f) → json.load(f)."""
        code = 'data = pickle.load(open("data.pkl", "rb"))'
        result = try_pattern_fix(_make_finding(rule_id="B301", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="pickle_loads")
        assert "json.load(" in result["fixed_code"]
        assert "pickle" not in result["fixed_code"]

    def test_pickle_loads_with_encoding(self):
        """pickle.loads avec argument."""
        code = 'obj = pickle.loads(network_data)'
        result = try_pattern_fix(_make_finding(rule_id="B301", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="pickle_loads")
        assert "json.loads(network_data)" in result["fixed_code"]

    def test_explanation_mentions_arbitrary_code_en(self):
        code = 'pickle.loads(data)'
        result = try_pattern_fix(_make_finding(rule_id="B301", code_snippet=code), lang="en")
        assert "arbitrary code" in result["fix_explanation"].lower() or "execute" in result["fix_explanation"].lower()

    def test_explanation_mentions_arbitrary_code_fr(self):
        code = 'pickle.loads(data)'
        result = try_pattern_fix(_make_finding(rule_id="B301", code_snippet=code), lang="fr")
        assert "code arbitraire" in result["fix_explanation"].lower() or "exécuter" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 13 — yaml.load → yaml.safe_load
# ===================================================================

class TestYamlLoad:
    """Tests pour yaml.load → yaml.safe_load."""

    def test_yaml_load_simple(self):
        """yaml.load(content) → yaml.safe_load(content)."""
        code = 'config = yaml.load(file_content)'
        result = try_pattern_fix(_make_finding(rule_id="B506", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="yaml_unsafe_load")
        assert "yaml.safe_load(file_content)" in result["fixed_code"]
        assert "yaml.load(" not in result["fixed_code"]

    def test_yaml_load_with_open(self):
        """yaml.load(open(...)) → yaml.safe_load(open(...))."""
        code = 'data = yaml.load(open("config.yml"))'
        result = try_pattern_fix(_make_finding(rule_id="B506", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="yaml_unsafe_load")
        assert "yaml.safe_load(" in result["fixed_code"]

    def test_yaml_load_with_stream(self):
        """yaml.load(stream) en contexte with."""
        code = 'settings = yaml.load(stream)'
        result = try_pattern_fix(_make_finding(rule_id="B506", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="yaml_unsafe_load")
        assert "yaml.safe_load(stream)" in result["fixed_code"]

    def test_yaml_safe_load_not_matched(self):
        """yaml.safe_load ne doit PAS matcher (déjà sécurisé)."""
        code = 'config = yaml.safe_load(content)'
        result = try_pattern_fix(_make_finding(rule_id="B506", code_snippet=code))
        assert result is None

    def test_explanation_mentions_python_code_en(self):
        code = 'yaml.load(data)'
        result = try_pattern_fix(_make_finding(rule_id="B506", code_snippet=code), lang="en")
        assert "python" in result["fix_explanation"].lower() or "arbitrary" in result["fix_explanation"].lower()

    def test_explanation_mentions_python_code_fr(self):
        code = 'yaml.load(data)'
        result = try_pattern_fix(_make_finding(rule_id="B506", code_snippet=code), lang="fr")
        assert "python" in result["fix_explanation"].lower() or "arbitraire" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 14 — requests verify=False → verify=True
# ===================================================================

class TestRequestsNoVerify:
    """Tests pour verify=False → verify=True."""

    def test_requests_get_verify_false(self):
        """requests.get(url, verify=False) → verify=True."""
        code = 'response = requests.get(url, verify=False)'
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="requests_no_verify")
        assert "verify=True" in result["fixed_code"]
        assert "verify=False" not in result["fixed_code"]

    def test_requests_post_verify_false(self):
        """requests.post avec verify=False."""
        code = 'r = requests.post(api_url, json=payload, verify=False)'
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="requests_no_verify")
        assert "verify=True" in result["fixed_code"]
        assert "json=payload" in result["fixed_code"]  # les autres args sont conservés

    def test_requests_session_verify_false(self):
        """Session.get avec verify=False."""
        code = 'session.get("https://api.example.com", verify=False, timeout=30)'
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="requests_no_verify")
        assert "verify=True" in result["fixed_code"]
        assert "timeout=30" in result["fixed_code"]

    def test_verify_true_not_matched(self):
        """verify=True ne doit PAS matcher (déjà sécurisé)."""
        code = 'requests.get(url, verify=True)'
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=code))
        assert result is None

    def test_explanation_mentions_mitm_en(self):
        code = 'requests.get(url, verify=False)'
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=code), lang="en")
        assert "man-in-the-middle" in result["fix_explanation"].lower() or "ssl" in result["fix_explanation"].lower()

    def test_explanation_mentions_mitm_fr(self):
        code = 'requests.get(url, verify=False)'
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=code), lang="fr")
        assert "man-in-the-middle" in result["fix_explanation"].lower() or "ssl" in result["fix_explanation"].lower()


# ===================================================================
# Pattern 15 — mktemp → mkstemp
# ===================================================================

class TestMktemp:
    """Tests pour mktemp() → mkstemp()."""

    def test_mktemp_simple(self):
        """tempfile.mktemp() → tempfile.mkstemp()."""
        code = 'tmpfile = tempfile.mktemp()'
        result = try_pattern_fix(_make_finding(rule_id="B108", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="mktemp_to_mkstemp")
        assert "mkstemp()" in result["fixed_code"]
        assert "mktemp(" not in result["fixed_code"]

    def test_mktemp_with_suffix(self):
        """tempfile.mktemp(suffix=".txt") → tempfile.mkstemp(suffix=".txt")."""
        code = 'path = tempfile.mktemp(suffix=".csv")'
        result = try_pattern_fix(_make_finding(rule_id="B108", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="mktemp_to_mkstemp")
        assert 'mkstemp(suffix=".csv")' in result["fixed_code"]

    def test_mktemp_with_dir(self):
        """tempfile.mktemp(dir="/tmp") → tempfile.mkstemp(dir="/tmp")."""
        code = 'tmp = tempfile.mktemp(dir="/tmp")'
        result = try_pattern_fix(_make_finding(rule_id="B108", code_snippet=code))
        _assert_fix_metadata(result, pattern_id="mktemp_to_mkstemp")
        assert "mkstemp(" in result["fixed_code"]
        assert 'dir="/tmp"' in result["fixed_code"]

    def test_explanation_mentions_race_condition_en(self):
        code = 'tempfile.mktemp()'
        result = try_pattern_fix(_make_finding(rule_id="B108", code_snippet=code))
        assert "race condition" in result["fix_explanation"].lower() or "attacker" in result["fix_explanation"].lower()

    def test_explanation_mentions_race_condition_fr(self):
        code = 'tempfile.mktemp()'
        result = try_pattern_fix(_make_finding(rule_id="B108", code_snippet=code), lang="fr")
        assert "concurrence" in result["fix_explanation"].lower() or "race" in result["fix_explanation"].lower()


# ===================================================================
# Tests transversaux — triggering, métadonnées, langues, edge cases
# ===================================================================

class TestTriggerMatching:
    """Tests pour les différents mécanismes de déclenchement."""

    def test_trigger_via_rule_id_exact(self):
        """Le rule_id exact déclenche le pattern."""
        code = 'requests.get(url, verify=False)'
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=code))
        assert result is not None

    def test_trigger_via_title_keyword(self):
        """Un mot-clé dans le title déclenche le pattern."""
        code = 'el.innerHTML = data;'
        result = try_pattern_fix(_make_finding(
            rule_id="custom-rule-123",
            title="Detected innerHTML usage that may lead to XSS",
            code_snippet=code,
        ))
        assert result is not None
        assert result["pattern_id"] == "xss_innerhtml"

    def test_trigger_via_tool_name(self):
        """Le nom de l'outil dans tool déclenche le pattern si c'est un trigger_id."""
        code = 'eval(data)'
        result = try_pattern_fix(_make_finding(
            rule_id="unrelated-rule",
            tool="eval-detector",
            code_snippet=code,
        ))
        assert result is not None
        assert result["pattern_id"] == "eval_to_json"

    def test_rule_id_case_insensitive(self):
        """Le matching du rule_id est insensible à la casse."""
        code = 'requests.get(url, verify=False)'
        result = try_pattern_fix(_make_finding(rule_id="b501", code_snippet=code))
        assert result is not None

    def test_no_trigger_no_match(self):
        """Aucun trigger → None même si le code est vulnérable."""
        code = 'requests.get(url, verify=False)'
        result = try_pattern_fix(_make_finding(rule_id="unrelated-rule", code_snippet=code))
        assert result is None


class TestMetadataPreservation:
    """Tests pour la préservation des métadonnées du finding."""

    def test_file_path_preserved(self):
        """Le file_path original est conservé."""
        result = try_pattern_fix(_make_finding(
            rule_id="B501",
            code_snippet='requests.get(url, verify=False)',
            file_path="src/api/client.py",
        ))
        assert result["file_path"] == "src/api/client.py"

    def test_line_start_preserved(self):
        """Le line_start original est conservé."""
        result = try_pattern_fix(_make_finding(
            rule_id="B501",
            code_snippet='requests.get(url, verify=False)',
            line_start=42,
        ))
        assert result["line_start"] == 42

    def test_original_code_preserved(self):
        """Le code original est dans original_code."""
        original = 'requests.get(url, verify=False)'
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=original))
        assert result["original_code"] == original

    def test_cached_always_false(self):
        """cached est toujours False (c'est un fix frais)."""
        result = try_pattern_fix(_make_finding(
            rule_id="B501",
            code_snippet='requests.get(url, verify=False)',
        ))
        assert result["cached"] is False


class TestLanguageExplanations:
    """Tests pour les explications multilingues sur tous les patterns."""

    PATTERN_SAMPLES = [
        ("sqli_fstring", "sql-injection", 'cursor.execute(f"SELECT * FROM t WHERE id = {x}")'),
        ("xss_innerhtml", "innerHTML", 'el.innerHTML = val;'),
        ("document_write", "document-write", 'document.write(x)'),
        ("eval_to_json", "eval", 'eval(x)'),
        ("exec_to_subprocess", "B102", 'exec(cmd)'),
        ("os_system_to_subprocess", "B605", 'os.system(cmd)'),
        ("hardcoded_secret", "hardcoded", 'password = "secret1234"'),
        ("weak_hash", "B303", 'hashlib.md5(data)'),
        ("debug_true", "debug", 'DEBUG = True'),
        ("cors_wildcard", "cors", 'CORS_ALLOWED_ORIGINS = "*"'),
        ("insecure_cookie", "cookie", 'response.set_cookie("s", v)'),
        ("pickle_loads", "B301", 'pickle.loads(data)'),
        ("yaml_unsafe_load", "B506", 'yaml.load(data)'),
        ("requests_no_verify", "B501", 'requests.get(url, verify=False)'),
        ("mktemp_to_mkstemp", "B108", 'tempfile.mktemp()'),
    ]

    @pytest.mark.parametrize("pattern_id,rule_id,code", PATTERN_SAMPLES)
    def test_english_explanation_not_empty(self, pattern_id, rule_id, code):
        """Chaque pattern fournit une explication EN non vide."""
        result = try_pattern_fix(_make_finding(rule_id=rule_id, code_snippet=code), lang="en")
        assert result is not None, f"Pattern {pattern_id} devrait matcher"
        assert len(result["fix_explanation"]) > 20, f"Explication EN trop courte pour {pattern_id}"

    @pytest.mark.parametrize("pattern_id,rule_id,code", PATTERN_SAMPLES)
    def test_french_explanation_not_empty(self, pattern_id, rule_id, code):
        """Chaque pattern fournit une explication FR non vide."""
        result = try_pattern_fix(_make_finding(rule_id=rule_id, code_snippet=code), lang="fr")
        assert result is not None, f"Pattern {pattern_id} devrait matcher"
        assert len(result["fix_explanation"]) > 20, f"Explication FR trop courte pour {pattern_id}"

    @pytest.mark.parametrize("pattern_id,rule_id,code", PATTERN_SAMPLES)
    def test_unknown_lang_falls_back(self, pattern_id, rule_id, code):
        """Langue inconnue → fallback sur l'anglais."""
        result = try_pattern_fix(_make_finding(rule_id=rule_id, code_snippet=code), lang="zh")
        assert result is not None
        # Doit donner l'explication EN (fallback)
        result_en = try_pattern_fix(_make_finding(rule_id=rule_id, code_snippet=code), lang="en")
        assert result["fix_explanation"] == result_en["fix_explanation"]

    @pytest.mark.parametrize("pattern_id,rule_id,code", PATTERN_SAMPLES)
    def test_pattern_id_correct(self, pattern_id, rule_id, code):
        """Le pattern_id retourné correspond bien au pattern attendu."""
        result = try_pattern_fix(_make_finding(rule_id=rule_id, code_snippet=code))
        assert result["pattern_id"] == pattern_id

    @pytest.mark.parametrize("pattern_id,rule_id,code", PATTERN_SAMPLES)
    def test_fixed_code_differs_from_original(self, pattern_id, rule_id, code):
        """Le code corrigé est toujours différent du code original."""
        result = try_pattern_fix(_make_finding(rule_id=rule_id, code_snippet=code))
        assert result["fixed_code"] != code, f"Le fix de {pattern_id} n'a rien changé"


class TestEdgeCases:
    """Tests pour les cas limites."""

    def test_empty_code_returns_none(self):
        """Code vide → None."""
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=""))
        assert result is None

    def test_none_code_returns_none(self):
        """Code None → None."""
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet=None))
        assert result is None

    def test_whitespace_only_code(self):
        """Code contenant uniquement des espaces."""
        result = try_pattern_fix(_make_finding(rule_id="B501", code_snippet="   \n\t  "))
        assert result is None

    def test_safe_code_not_matched(self):
        """Code sécurisé ne devrait pas être modifié."""
        safe_codes = [
            ("B501", 'requests.get(url, verify=True)'),
            ("B506", 'yaml.safe_load(data)'),
            ("debug", 'DEBUG = False'),
            ("cookie", 'response.set_cookie("s", v, httponly=True, secure=True)'),
        ]
        for rule_id, code in safe_codes:
            result = try_pattern_fix(_make_finding(rule_id=rule_id, code_snippet=code))
            assert result is None, f"Le code sécurisé ne devrait pas matcher: {code}"

    def test_unknown_rule_never_matches(self):
        """Un rule_id inconnu ne déclenche aucun pattern."""
        vulnerable_codes = [
            'requests.get(url, verify=False)',
            'eval(data)',
            'os.system(cmd)',
            'pickle.loads(data)',
        ]
        for code in vulnerable_codes:
            result = try_pattern_fix(_make_finding(rule_id="totally-unknown-rule-xyz", code_snippet=code))
            assert result is None, f"Ne devrait pas matcher sans trigger: {code}"
