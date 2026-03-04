"""AI auto-fix service with multi-provider support (Gemini, OpenAI, Anthropic).

Generates code fix suggestions for detected vulnerabilities.
"""

import json
import logging
import os

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = ("gemini", "openai", "anthropic")

FIX_PROMPT_LINES = """\
You are a senior security engineer. A static analysis tool found a vulnerability.

**Tool:** {tool}
**Rule:** {rule_id}
**Severity:** {severity}
**OWASP Category:** {owasp_category}
**Title:** {title}
**Description:** {description}
**File:** {file_path} (lines {line_start}–{line_end})

**Vulnerable code snippet:**
```
{code_snippet}
```

{file_context}

CRITICAL RULES for "fixed_code":
- Your fix will DIRECTLY REPLACE lines {line_start}–{line_end} in the file.
- "fixed_code" MUST contain ONLY the replacement for those exact lines. Do NOT include surrounding \
code, function declarations, or any lines outside the vulnerable range.
- If the vulnerability is on a single line, return only the fixed version of that single line.
- Keep the same indentation and style. Only change what is necessary to fix the vulnerability.

Provide a JSON response with exactly these keys:
- "fixed_code": the replacement code for lines {line_start}–{line_end} ONLY.
- "explanation": a concise explanation (2-4 sentences) of what was wrong and how the fix addresses it.
- "is_false_positive": boolean — set to true ONLY if the code is actually safe and the tool incorrectly flagged it.
{language_instruction}
Respond ONLY with valid JSON, no markdown fences.
"""

FIX_PROMPT_FULL_FILE = """\
You are a senior security engineer. A static analysis tool found a vulnerability.

**Tool:** {tool}
**Rule:** {rule_id}
**Severity:** {severity}
**OWASP Category:** {owasp_category}
**Title:** {title}
**Description:** {description}
**File:** {file_path}

**Current full file content:**
```
{full_file_content}
```

CRITICAL RULES for "fixed_code":
- Return the ENTIRE file content with the vulnerability fixed.
- Do NOT return only the changed lines — return the COMPLETE file so it can be written as-is.
- Keep everything else in the file exactly the same. Only change what is necessary to fix the vulnerability.
- Preserve all formatting, indentation, and comments.
- For dependency vulnerabilities (package.json, requirements.txt, composer.json, etc.):
  UPDATE the version of the vulnerable package to the latest secure version directly in the dependencies.
  Do NOT just add "overrides" or "resolutions" — change the actual version number.
  If the vulnerable package is a transitive dependency, update the parent package that pulls it in.

Respond using this EXACT format with delimiters (NOT JSON):

===EXPLANATION_START===
A concise explanation (2-4 sentences) of what was wrong and how the fix addresses it.{language_instruction}
===EXPLANATION_END===
===FALSE_POSITIVE===
false
===FIXED_CODE_START===
The COMPLETE fixed file content here.
===FIXED_CODE_END===
"""


def _read_file_context(workspace_path: str, file_path: str, line_start: int | None) -> str:
    """Read surrounding context from the source file if available."""
    if not workspace_path or not file_path:
        return ""
    full_path = os.path.join(workspace_path, file_path)
    if not os.path.isfile(full_path):
        return ""
    try:
        with open(full_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if line_start and line_start > 1:
            start = max(0, line_start - 15)
            end = min(len(lines), line_start + 25)
            context_lines = lines[start:end]
            return "**Surrounding file context (lines {}-{}):**\n```\n{}```".format(
                start + 1, end, "".join(context_lines)
            )
        return "**File beginning:**\n```\n{}```".format("".join(lines[:60]))
    except OSError:
        return ""


def _read_full_file(workspace_path: str, file_path: str) -> str:
    """Read the entire source file content."""
    if not workspace_path or not file_path:
        return ""
    full_path = os.path.join(workspace_path, file_path)
    if not os.path.isfile(full_path):
        return ""
    try:
        with open(full_path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _build_prompt(finding, lang: str = "en") -> str:
    """Build the fix prompt from a finding.

    Uses line-based prompt when line info is available, full-file prompt otherwise
    (e.g. dependency vulnerabilities detected by pip-audit/npm-audit).
    """
    workspace_path = getattr(finding.scan, "workspace_path", "")

    from .owasp_mapper import get_owasp_label  # noqa: PLC0415

    lang_names = {"en": "English", "fr": "French", "es": "Spanish", "de": "German", "it": "Italian"}
    lang_name = lang_names.get(lang or "en", lang or "English")
    language_instruction = f'\nIMPORTANT: Write the "explanation" value in {lang_name}. Keep "fixed_code" as code only.'
    owasp_label = f"{finding.owasp_category} — {get_owasp_label(finding.owasp_category)}"

    has_line_info = finding.line_start and finding.line_start > 0

    if has_line_info:
        file_context = _read_file_context(workspace_path, finding.file_path, finding.line_start)
        return FIX_PROMPT_LINES.format(
            tool=finding.tool,
            rule_id=finding.rule_id,
            severity=finding.severity,
            owasp_category=owasp_label,
            title=finding.title,
            description=finding.description,
            file_path=finding.file_path,
            line_start=finding.line_start,
            line_end=finding.line_end or finding.line_start,
            code_snippet=finding.code_snippet or "(no snippet available)",
            file_context=file_context,
            language_instruction=language_instruction,
        )
    else:
        full_content = _read_full_file(workspace_path, finding.file_path)
        if not full_content:
            full_content = finding.code_snippet or "(file not available)"
        return FIX_PROMPT_FULL_FILE.format(
            tool=finding.tool,
            rule_id=finding.rule_id,
            severity=finding.severity,
            owasp_category=owasp_label,
            title=finding.title,
            description=finding.description,
            file_path=finding.file_path,
            full_file_content=full_content,
            language_instruction=language_instruction,
        )


def _parse_delimiter_response(text: str) -> dict | None:
    """Try to parse a delimiter-based response (used for full-file fixes)."""
    if "===FIXED_CODE_START===" not in text:
        return None

    import re as _re  # noqa: PLC0415

    explanation = ""
    m = _re.search(r"===EXPLANATION_START===\s*\n(.*?)\n\s*===EXPLANATION_END===", text, _re.DOTALL)
    if m:
        explanation = m.group(1).strip()

    is_fp = False
    m = _re.search(r"===FALSE_POSITIVE===\s*\n\s*(true|false)", text, _re.IGNORECASE)
    if m:
        is_fp = m.group(1).strip().lower() == "true"

    m = _re.search(r"===FIXED_CODE_START===\s*\n(.*?)\n\s*===FIXED_CODE_END===", text, _re.DOTALL)
    if not m:
        return None
    fixed_code = m.group(1)
    # Strip markdown fences the AI sometimes wraps around the code
    if fixed_code.startswith("```"):
        fixed_code = fixed_code.split("\n", 1)[1] if "\n" in fixed_code else fixed_code[3:]
    if fixed_code.rstrip().endswith("```"):
        fixed_code = fixed_code.rstrip()[:-3].rstrip()

    return {
        "fixed_code": fixed_code,
        "explanation": explanation,
        "is_false_positive": is_fp,
    }


def _parse_ai_response(text: str) -> dict:
    """Parse AI response, supporting both delimiter format and JSON format."""
    text = text.strip()

    # Try delimiter format first (used for full-file fixes)
    delim_result = _parse_delimiter_response(text)
    if delim_result:
        return delim_result

    # Strip markdown fences
    if text.startswith("```"):
        first_line, _, rest = text.partition("\n")
        text = rest if rest else text[3:]
        if text.endswith("```"):
            text = text[:-3].strip()

    # Try to extract JSON object if there's surrounding text
    if not text.startswith("{"):
        start = text.find("{")
        if start != -1:
            text = text[start:]
    if not text.endswith("}"):
        end = text.rfind("}")
        if end != -1:
            text = text[: end + 1]

    # Use strict=False to tolerate control characters (tabs, newlines)
    # inside JSON strings — common in AI responses containing code.
    result = json.loads(text, strict=False)

    fixed_code = result.get("fixed_code", "")
    if isinstance(fixed_code, dict):
        fixed_code = json.dumps(fixed_code, indent=2)

    return {
        "fixed_code": fixed_code,
        "explanation": result.get("explanation", ""),
        "is_false_positive": result.get("is_false_positive", False),
    }


# ---------------------------------------------------------------------------
# Provider adapters
# ---------------------------------------------------------------------------

def _call_gemini(prompt: str, api_key: str) -> str:
    """Call Google Gemini and return raw text response."""
    import google.generativeai as genai  # noqa: PLC0415

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(settings.GEMINI_MODEL)
    response = model.generate_content(prompt)
    return response.text


def _call_openai(prompt: str, api_key: str) -> str:
    """Call OpenAI API and return raw text response."""
    from openai import OpenAI  # noqa: PLC0415

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=getattr(settings, "OPENAI_MODEL", "gpt-4o"),
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )
    return response.choices[0].message.content


def _call_anthropic(prompt: str, api_key: str) -> str:
    """Call Anthropic Claude API and return raw text response."""
    import anthropic  # noqa: PLC0415

    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=getattr(settings, "ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


PROVIDER_CALLERS = {
    "gemini": _call_gemini,
    "openai": _call_openai,
    "anthropic": _call_anthropic,
}


def get_api_key_for_provider(provider: str, keys: dict) -> str:
    """Extract the correct API key from a keys dict based on provider name."""
    key_map = {
        "gemini": "gemini_api_key",
        "openai": "openai_api_key",
        "anthropic": "anthropic_api_key",
    }
    return keys.get(key_map.get(provider, ""), "")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_fix(finding, lang: str = "en", provider: str = "gemini", api_key: str = "", force: bool = False) -> dict:
    """Generate an AI fix for a finding using the specified provider.

    Returns dict with keys: fixed_code, fix_explanation, original_code, file_path, line_start, cached.
    """
    # Return cached fix if available (unless force regeneration)
    if finding.fix_generated_at and not force:
        return {
            "fixed_code": finding.fixed_code,
            "fix_explanation": finding.fix_explanation,
            "original_code": finding.code_snippet,
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "cached": True,
        }

    # Try deterministic pattern fix first (no API needed)
    from .pattern_fixer import try_pattern_fix  # noqa: PLC0415

    pattern_result = try_pattern_fix(finding, lang=lang)
    if pattern_result:
        finding.fixed_code = pattern_result["fixed_code"]
        finding.fix_explanation = pattern_result["fix_explanation"]
        finding.fix_generated_at = timezone.now()
        finding.save(update_fields=["fixed_code", "fix_explanation", "fix_generated_at"])
        return pattern_result

    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported AI provider: {provider}. Choose from: {', '.join(SUPPORTED_PROVIDERS)}")

    if not api_key:
        provider_labels = {"gemini": "Gemini", "openai": "OpenAI", "anthropic": "Anthropic"}
        label = provider_labels.get(provider, provider)
        raise ValueError(f"No {label} API key configured. Add yours in Settings.")

    prompt = _build_prompt(finding, lang=lang)
    caller = PROVIDER_CALLERS[provider]

    try:
        raw_text = caller(prompt, api_key)
        result = _parse_ai_response(raw_text)
    except (json.JSONDecodeError, KeyError, AttributeError) as exc:
        logger.warning("Failed to parse %s response for finding %s: %s", provider, finding.id, exc)
        raise ValueError("Failed to parse AI response. Please try again.") from exc
    except Exception as exc:
        logger.error("%s API error for finding %s: %s", provider, finding.id, exc)
        raise ValueError(f"AI service error: {exc}") from exc

    # Cache on the finding
    finding.fixed_code = result["fixed_code"]
    finding.fix_explanation = result["explanation"]
    finding.fix_generated_at = timezone.now()
    update_fields = ["fixed_code", "fix_explanation", "fix_generated_at"]

    if result["is_false_positive"]:
        finding.status = "false_positive"
        update_fields.append("status")

    finding.save(update_fields=update_fields)

    return {
        "fixed_code": result["fixed_code"],
        "fix_explanation": result["explanation"],
        "original_code": finding.code_snippet,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "cached": False,
        "is_false_positive": result["is_false_positive"],
    }
