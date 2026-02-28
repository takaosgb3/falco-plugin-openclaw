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
from pathlib import Path
from typing import Any

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
_patterns_cache: dict | None = None


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

    Args:
        text: The evidence text to highlight
        keywords: List of keywords to highlight
        fmt: Output format ("html" or "text")

    Returns:
        Formatted text with highlighted keywords
    """
    if fmt == "html":
        result = f"<pre style='font-family: monospace; white-space: pre-wrap;'>{_html_escape(text)}</pre>"
        for kw in keywords:
            escaped_kw = _html_escape(kw)
            if escaped_kw.lower() in result.lower():
                result = _case_insensitive_replace(
                    result, escaped_kw,
                    f"<mark style='background: #ffeb3b; font-weight: bold;'>{escaped_kw}</mark>"
                )
        return result
    else:
        result = text
        for kw in keywords:
            if kw.lower() in result.lower():
                result = _case_insensitive_replace(result, kw, f"**{kw}**")
        return result


def format_rule_match_status(result: dict) -> str:
    """Format expected vs matched rule comparison for Allure attachment."""
    expected = result.get("expected_rule", "")
    matched = result.get("matched_rule", "")
    rule_match = result.get("rule_match", False)
    matched_rules = result.get("matched_rules", [])

    lines = []
    lines.append(f"Expected Rule: {expected or '(none)'}")

    if matched_rules:
        lines.append(f"Matched Rules: {', '.join(matched_rules)}")
    else:
        lines.append(f"Matched Rule:  {matched or '(none)'}")

    status_icon = "MATCH" if rule_match else "MISMATCH"
    lines.append(f"Status: {status_icon}")

    return "\n".join(lines)


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
            .replace('"', "&quot;"))


def _case_insensitive_replace(text: str, old: str, new: str) -> str:
    """Replace all case-insensitive occurrences of old with new in text."""
    import re
    return re.sub(re.escape(old), new, text, flags=re.IGNORECASE)


# ---- pytest hooks and test function ----

def pytest_generate_tests(metafunc):
    """Dynamically parametrize tests from test-results.json."""
    if "result" in metafunc.fixturenames:
        test_results_path = metafunc.config.getoption("--test-results")
        results = load_test_results(test_results_path)
        if results:
            metafunc.parametrize("result", results, ids=lambda r: r["pattern_id"])


def test_e2e_detection(result):
    """E2E pattern detection test — one test case per pattern."""
    pattern_id = result["pattern_id"]
    category = result["category"]

    # Set Allure metadata
    allure.dynamic.epic("E2E Security Tests")
    allure.dynamic.feature(category.upper())
    allure.dynamic.story(pattern_id)
    allure.dynamic.severity(map_severity(result))

    # Add description from pattern data
    patterns = load_all_patterns()
    pattern_info = patterns.get(pattern_id, {})
    description = pattern_info.get("description", "")
    if description:
        allure.dynamic.description(description)

    # Attach evidence with keyword highlighting
    evidence = result.get("evidence", "")
    if evidence:
        highlighted = highlight_keywords_in_text(evidence, SECURITY_KEYWORDS, "html")
        allure.attach(
            highlighted,
            name="Falco Alert Evidence",
            attachment_type=allure.attachment_type.HTML,
        )

    # Attach rule mapping status
    expected_rule = result.get("expected_rule", "")
    if expected_rule:
        rule_status = format_rule_match_status(result)
        allure.attach(
            rule_status,
            name="Rule Mapping",
            attachment_type=allure.attachment_type.TEXT,
        )

    # Attach latency info
    latency = result.get("latency_ms", -1)
    if latency >= 0:
        allure.attach(
            f"Detection latency: {latency}ms",
            name="Latency",
            attachment_type=allure.attachment_type.TEXT,
        )

    # Attach raw result JSON for debugging
    allure.attach(
        json.dumps(result, indent=2),
        name="Raw Result",
        attachment_type=allure.attachment_type.JSON,
    )

    # Assert test status
    assert result["status"] == "passed", (
        f"Pattern {pattern_id} ({category}): "
        f"status={result['status']}, "
        f"detected={result.get('detected')}, "
        f"expected_rule={expected_rule}, "
        f"matched_rule={result.get('matched_rule', '')}"
    )
