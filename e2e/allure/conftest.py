"""pytest configuration for OpenClaw E2E Allure report generation.

Defines custom CLI options and prewarms caches for fair test measurement.
"""

import pytest


def pytest_addoption(parser):
    """Add custom command-line options for E2E test report generation."""
    parser.addoption(
        "--test-results",
        action="store",
        required=True,
        help="Path to test-results.json from batch_analyzer.py",
    )
    parser.addoption(
        "--logs-dir",
        action="store",
        default=None,
        help="Path to Falco logs directory (for evidence attachments)",
    )


def pytest_configure(config):
    """Store option values and prewarm caches."""
    config.test_results = config.getoption("--test-results")
    config.logs_dir = config.getoption("--logs-dir")
    _prewarm_caches()


def _prewarm_caches():
    """Prewarm pattern loading cache for fair test timing."""
    try:
        from test_e2e_wrapper import load_all_patterns
        load_all_patterns()
    except (ImportError, Exception):
        pass
