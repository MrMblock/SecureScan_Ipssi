"""Automatic false positive detection for common scanner patterns.

Runs during scan aggregation to mark known false positives before they reach the UI.
"""

import re


def is_false_positive(finding_data: dict) -> bool:
    """Check if a finding matches a known false positive pattern.

    Args:
        finding_data: dict with keys like rule_id, tool, code_snippet, title, description, file_path

    Returns:
        True if the finding is a known false positive.
    """
    rule_id = finding_data.get("rule_id", "")
    code = finding_data.get("code_snippet", "")
    title = (finding_data.get("title", "") or "").lower()
    desc = (finding_data.get("description", "") or "").lower()

    # ── Pattern 1: setTimeout / setInterval with function literal ──
    # Semgrep flags these as "eval injection" or "dom eval injection"
    # but passing a function (arrow or reference) is perfectly safe.
    # Only passing a string is dangerous: setTimeout("alert(1)", 100)
    if _is_timer_false_positive(rule_id, code, title, desc):
        return True

    # ── Pattern 2: console.log / console.warn flagged as info leak ──
    if _is_console_false_positive(rule_id, code, title):
        return True

    # ── Pattern 3: innerHTML with sanitized/static content ──
    if _is_innerhtml_static(rule_id, code, title):
        return True

    return False


def _is_timer_false_positive(rule_id: str, code: str, title: str, desc: str) -> bool:
    """setTimeout/setInterval with function argument (not string) is safe."""
    # Check if this is about setTimeout/setInterval
    is_timer_rule = any(kw in title + desc + rule_id.lower() for kw in [
        "settimeout", "setinterval", "eval", "dom-eval", "dom_eval",
    ])
    if not is_timer_rule:
        return False

    # Check if the code uses setTimeout/setInterval
    if not re.search(r'set(Timeout|Interval)\s*\(', code):
        return False

    # If the first argument is a function (arrow, named, or anonymous), it's safe
    # Dangerous: setTimeout("code", ms) — string argument
    # Safe: setTimeout(() => ..., ms) or setTimeout(function() {...}, ms) or setTimeout(fn, ms)
    timer_call = re.search(
        r'set(?:Timeout|Interval)\s*\(\s*(.{1,80})',
        code,
        re.DOTALL,
    )
    if timer_call:
        first_arg = timer_call.group(1).strip()
        # If first arg starts with a string literal, it's NOT a false positive
        if first_arg.startswith(("'", '"', '`')):
            return False
        # Otherwise (arrow function, function ref, function expression) → false positive
        return True

    return False


def _is_console_false_positive(rule_id: str, code: str, title: str) -> bool:
    """console.log in frontend code is rarely a real vulnerability."""
    if "console" not in title and "console" not in rule_id.lower():
        return False
    if re.search(r'console\.(log|warn|info|debug)\s*\(', code):
        return True
    return False


def _is_innerhtml_static(rule_id: str, code: str, title: str) -> bool:
    """innerHTML with only static strings (no variables) is safe."""
    if "innerhtml" not in title.lower() and "innerhtml" not in rule_id.lower():
        return False
    # Only mark as FP if innerHTML is assigned a pure string literal
    if re.search(r'\.innerHTML\s*=\s*["\'][^"\']*["\']', code):
        return True
    return False
