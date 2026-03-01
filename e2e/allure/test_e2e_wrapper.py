"""test_e2e_wrapper.py — Allure report wrapper for OpenClaw E2E tests.

Reads test-results.json from batch_analyzer.py and generates pytest test cases
with Allure metadata for each pattern. Produces a visual Allure report with
Epic/Feature/Story hierarchy.

Usage:
    cd e2e/allure && python3 -m pytest test_e2e_wrapper.py \
        --test-results=../../e2e/results/test-results.json \
        --logs-dir=../../e2e/results \
        --alluredir=../../allure-results \
        -v
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

import allure
import pytest

# Project root (relative to e2e/allure/)
PROJECT_ROOT = Path(__file__).parent.parent.parent

# Pattern files directory
PATTERNS_DIR = PROJECT_ROOT / "test" / "e2e" / "patterns" / "categories"

# Security keywords for evidence highlighting
SECURITY_KEYWORDS = [
    "rm -rf",
    "rm -f",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/",
    "curl",
    "wget",
    "nc ",
    "netcat",
    "while true",
    "infinite loop",
    "max retries",
    "recursion depth",
    "$(whoami)",
    "`whoami`",
    "chmod 777",
    "chmod 000",
    "mkfs.",
    "dd if=",
    "config_change",
    "gpt-4-unsafe",
    "../../",
    ".env",
    "credentials",
    "api_key",
]

# Severity mapping by category
SEVERITY_MAP = {
    "dangerous_command": allure.severity_level.CRITICAL,
    "data_exfiltration": allure.severity_level.CRITICAL,
    "agent_runaway": allure.severity_level.NORMAL,
    "workspace_escape": allure.severity_level.NORMAL,
    "suspicious_config": allure.severity_level.NORMAL,
    "shell_injection": allure.severity_level.NORMAL,
    "unauthorized_model": allure.severity_level.MINOR,
    "benign": allure.severity_level.TRIVIAL,
    "edge_cases": allure.severity_level.NORMAL,
    "composite": allure.severity_level.CRITICAL,
    "plaintext_threats": allure.severity_level.NORMAL,
}

# Cache for loaded patterns
_patterns_cache: Optional[dict] = None


def load_all_patterns() -> dict:
    """Load all pattern JSON files and return a map of pattern_id -> pattern_info."""
    global _patterns_cache
    if _patterns_cache is not None:
        return _patterns_cache

    pattern_map: dict = {}
    if not PATTERNS_DIR.is_dir():
        return pattern_map

    for json_file in sorted(PATTERNS_DIR.glob("*.json")):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        category = data.get("category", "unknown")
        for pattern in data.get("patterns", []):
            pid = pattern.get("id", "")
            if pid:
                pattern["_category"] = category
                pattern_map[pid] = pattern

    _patterns_cache = pattern_map
    return pattern_map


def load_test_results(path: str) -> list:
    """Load test-results.json and return list of result dicts."""
    results_path = Path(path)
    if not results_path.is_file():
        pytest.skip(f"test-results.json not found: {path}")
        return []

    with open(results_path, "r") as f:
        return json.load(f)


def highlight_keywords_in_text(text: str, keywords: list, fmt: str = "html") -> str:
    """Highlight security keywords in evidence text.

    Applies keyword highlighting to the plain text content first, then wraps
    in HTML tags. This prevents keyword replacements from corrupting HTML
    markup. Matched text preserves its original casing.

    Args:
        text: The evidence text to highlight
        keywords: List of keywords to highlight
        fmt: Output format ("html" or "text")

    Returns:
        Formatted text with highlighted keywords
    """
    if fmt == "html":
        # Step 1: HTML-escape the text content
        escaped_text = _html_escape(text)
        # Step 2: Apply keyword highlighting to escaped text only (not HTML tags)
        for kw in keywords:
            escaped_kw = _html_escape(kw)
            if escaped_kw.lower() in escaped_text.lower():
                escaped_text = _case_insensitive_replace(
                    escaped_text, escaped_kw,
                    lambda m: f"<mark style='background: #ffeb3b; font-weight: bold;'>{m}</mark>"
                )
        # Step 3: Wrap in HTML tags after highlighting
        return f"<pre style='font-family: monospace; white-space: pre-wrap;'>{escaped_text}</pre>"
    else:
        result = text
        for kw in keywords:
            if kw.lower() in result.lower():
                result = _case_insensitive_replace(result, kw, lambda m: f"**{m}**")
        return result


def format_rule_match_status(result: dict) -> str:
    """Format rule match status as emoji string."""
    category = result.get("category", "")
    expected = result.get("expected_rule", "")
    rule_match = result.get("rule_match") is True

    if category == "benign" and not expected:
        return "✅ Expected Not Detected"
    if not expected:
        return "⚠️ Not Defined"
    if rule_match:
        return "✅ Match"
    return "❌ Mismatch"


def map_severity(result: dict) -> Any:
    """Map test result category to Allure severity level."""
    category = result.get("category", "")
    return SEVERITY_MAP.get(category, allure.severity_level.NORMAL)


def _html_escape(text: str) -> str:
    """Escape HTML special characters."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def _case_insensitive_replace(text: str, old: str, new) -> str:
    """Replace all case-insensitive occurrences of old in text.

    Args:
        text: The text to search in
        old: The pattern to match (case-insensitive)
        new: Either a replacement string, or a callable that receives the
             matched text and returns the replacement (preserves original case)
    """
    if callable(new):
        return re.sub(
            re.escape(old),
            lambda m: new(m.group(0)),
            text,
            flags=re.IGNORECASE,
        )
    return re.sub(re.escape(old), new, text, flags=re.IGNORECASE)


# ---- pytest hooks and test function ----

def pytest_generate_tests(metafunc):
    """Dynamically parametrize tests from test-results.json."""
    if "result" in metafunc.fixturenames:
        test_results_path = metafunc.config.getoption("--test-results")
        results = load_test_results(test_results_path)
        if results:
            metafunc.parametrize(
                "result", results,
                ids=[f"{i:02d}_{r['pattern_id']}" for i, r in enumerate(results, 1)],
            )


def _format_latency(result: dict) -> str:
    """Format latency for display."""
    latency = result.get("latency_ms", -1)
    if latency < 0:
        return "N/A"
    return f"{latency}ms"


def _build_description(result: dict, pattern_info: dict) -> str:
    """Build rich Markdown description for Allure report detail view."""
    pattern_id = result["pattern_id"]
    category = result["category"]
    status = result.get("status", "unknown")
    expected_rule = result.get("expected_rule", "")
    matched_rule = result.get("matched_rule", "")
    matched_rules = result.get("matched_rules", [])
    evidence = result.get("evidence", "No evidence recorded")

    # Pattern info fields
    desc_text = pattern_info.get("description", "N/A")
    severity = pattern_info.get("severity", "N/A")
    attack_type = pattern_info.get("attack_type", category)
    payload_raw = pattern_info.get("payload", "")

    # Try to extract args from JSON payload
    payload_display = payload_raw
    try:
        p = json.loads(payload_raw)
        if isinstance(p, dict) and "args" in p:
            payload_display = p["args"]
    except (json.JSONDecodeError, TypeError):
        pass

    # Rule mapping display
    if matched_rules:
        matched_display = ", ".join(f"`{r}`" for r in matched_rules)
    else:
        matched_display = f"`{matched_rule or 'N/A'}`"

    match_status = format_rule_match_status(result)
    detected = result.get("detected", False)
    detection_count = "1 / 1" if detected else "0 / 1"

    description = f"""
## Attack Pattern Information

| Item | Value |
|------|-------|
| **Pattern ID** | `{pattern_id}` |
| **Description** | {desc_text} |
| **Category** | {attack_type.upper()} |
| **Severity** | `{severity.upper() if severity else 'N/A'}` |

## Attack Details

- **Payload**: `{payload_display or 'N/A'}`
- **Expected Detection**: {'Yes' if expected_rule else 'No'}

## Test Execution Results

- **Status**: `{status.upper()}`
- **Detection Count**: {detection_count}
- **Latency**: {_format_latency(result)}

## Rule Mapping

| Item | Value |
|------|-------|
| **Expected Rule** | `{expected_rule or 'N/A'}` |
| **Matched Rule** | {matched_display} |
| **Rule Match** | {match_status} |

## Detection Evidence

```
{evidence}
```
"""
    return description.strip()


def test_e2e_detection(result):
    """E2E pattern detection test — one test case per pattern."""
    pattern_id = result["pattern_id"]
    category = result["category"]

    # Set Allure metadata
    allure.dynamic.epic("E2E Security Tests")
    allure.dynamic.feature(category.upper())
    allure.dynamic.story(pattern_id)
    allure.dynamic.severity(map_severity(result))

    # Load pattern info and build rich description
    patterns = load_all_patterns()
    pattern_info = patterns.get(pattern_id, {})
    description = _build_description(result, pattern_info)
    allure.dynamic.description(description)

    # Step 1: Test execution result (JSON attachment)
    with allure.step("Test Execution Result"):
        allure.attach(
            json.dumps(result, indent=2),
            name=f"{pattern_id}-result.json",
            attachment_type=allure.attachment_type.JSON,
        )

    # Step 2: Detection evidence with keyword highlighting
    evidence = result.get("evidence", "")
    if evidence:
        highlighted = highlight_keywords_in_text(evidence, SECURITY_KEYWORDS, "html")
        html_doc = (
            "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
            "<style>body{font-family:monospace;padding:15px;background:#1a1a1a;"
            "color:#e0e0e0;line-height:1.5}pre{white-space:pre-wrap;word-wrap:break-word}"
            "mark{background:#FFFF00;color:#000;padding:1px 3px;border-radius:2px}</style>"
            f"</head><body><h3 style='color:#4CAF50'>Detection Evidence</h3>{highlighted}</body></html>"
        )
        with allure.step("Detection Evidence (Highlighted)"):
            allure.attach(
                html_doc,
                name="Detection Evidence (HTML)",
                attachment_type=allure.attachment_type.HTML,
            )

    # Step 3: Rule mapping verification
    with allure.step("Rule Mapping Verification"):
        expected_rule = result.get("expected_rule", "")
        matched_rule = result.get("matched_rule", "")
        match_status = format_rule_match_status(result)
        mapping_text = (
            f"Expected Rule: {expected_rule or 'N/A'}\n"
            f"Matched Rule: {matched_rule or 'N/A'}\n"
            f"Rule Match: {match_status}"
        )
        allure.attach(
            mapping_text,
            name="Rule Mapping",
            attachment_type=allure.attachment_type.TEXT,
        )

    # Step 4: Verification result
    with allure.step("Verification Result"):
        if result["status"] == "passed":
            allure.attach(
                f"Test passed: {pattern_id}",
                name="Test Result",
                attachment_type=allure.attachment_type.TEXT,
            )
        else:
            allure.attach(
                f"Test failed: {pattern_id}\nDetected: {result.get('detected')}\n"
                f"Expected: {expected_rule}\nMatched: {matched_rule}",
                name="Test Result",
                attachment_type=allure.attachment_type.TEXT,
            )

    # pytest assertion
    assert result["status"] == "passed", (
        f"Pattern {pattern_id} ({category}): "
        f"status={result['status']}, "
        f"detected={result.get('detected')}, "
        f"expected_rule={result.get('expected_rule', '')}, "
        f"matched_rule={result.get('matched_rule', '')}"
    )
