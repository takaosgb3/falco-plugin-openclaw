#!/usr/bin/env python3
"""
Generate Rule Mapping Trend HTML Page for E2E Reports

This script generates an HTML page with an interactive Rule Mapping Trend chart
using Chart.js, plus a JSON history file for persistence across runs.

The chart tracks:
- Rule Match (green): expected_rule matched actual Falco rule
- Rule Mismatch (red): expected_rule did NOT match actual Falco rule
- Expected Not Detected (blue): benign patterns correctly not detected
- Not Defined (gray): patterns with no expected_rule defined

Adapted from falco-plugin-nginx for openclaw's test-results.json format.

Usage:
    python generate_rule_mapping_trend_html.py \
        --test-results results/test-results.json \
        --run-number 100 \
        --report-url "https://example.com/e2e-report/100/" \
        --history-input rule-mapping-trend-history.json \
        --history-output rule-mapping-trend-history.json \
        --html-output rule-mapping-trend.html \
        --max-history 20
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CATEGORY_MATCH = "Rule Match"
CATEGORY_MISMATCH = "Rule Mismatch"
CATEGORY_EXPECTED_NOT_DETECTED = "Expected Not Detected"
CATEGORY_NOT_DEFINED = "Not Defined"


def calculate_rule_mapping_status(test_result: Dict) -> str:
    """Calculate Rule Mapping status for a single test result.

    Openclaw-specific logic based on category, expected_rule, and rule_match fields.

    Returns:
        One of the four category constants.
    """
    category = test_result.get("category", "")
    expected_rule = test_result.get("expected_rule", "")
    rule_match = test_result.get("rule_match") is True

    # Benign patterns with no expected rule → true negatives
    if category == "benign" and not expected_rule:
        return CATEGORY_EXPECTED_NOT_DETECTED

    # No expected rule (edge cases, some plaintext) → not defined
    if not expected_rule:
        return CATEGORY_NOT_DEFINED

    # Has expected rule and matches
    if rule_match:
        return CATEGORY_MATCH

    # Has expected rule but doesn't match
    return CATEGORY_MISMATCH


def calculate_statistics(test_results: List[Dict]) -> Dict[str, int]:
    """Calculate Rule Mapping statistics from test results."""
    stats = {
        CATEGORY_MATCH: 0,
        CATEGORY_MISMATCH: 0,
        CATEGORY_EXPECTED_NOT_DETECTED: 0,
        CATEGORY_NOT_DEFINED: 0,
    }
    for result in test_results:
        status = calculate_rule_mapping_status(result)
        stats[status] += 1
    return stats


def create_trend_entry(
    run_number: int,
    report_url: str,
    stats: Dict[str, int],
    timestamp: Optional[str] = None,
) -> Dict:
    """Create a single trend entry for history."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "buildOrder": run_number,
        "reportName": f"#{run_number}",
        "reportUrl": report_url,
        "timestamp": timestamp,
        "data": stats,
    }


def merge_trend_history(
    new_entry: Dict, existing_history: List[Dict], max_history: int = 20
) -> List[Dict]:
    """Merge new trend entry into existing history, dedup by buildOrder."""
    updated = [new_entry] + existing_history
    seen = set()
    deduplicated = []
    for entry in updated:
        build_order = entry.get("buildOrder")
        if build_order not in seen:
            seen.add(build_order)
            deduplicated.append(entry)
    deduplicated.sort(key=lambda x: x.get("buildOrder", 0))
    return deduplicated[-max_history:]


def generate_html(history: List[Dict], current_run: int) -> str:
    """Generate HTML page with Chart.js trend chart."""
    labels = [
        entry.get("reportName", f"#{entry.get('buildOrder', '?')}")
        for entry in history
    ]
    urls = [entry.get("reportUrl", "#") for entry in history]

    match_data = [
        entry.get("data", {}).get(CATEGORY_MATCH, 0) for entry in history
    ]
    mismatch_data = [
        entry.get("data", {}).get(CATEGORY_MISMATCH, 0) for entry in history
    ]
    expected_not_detected_data = [
        entry.get("data", {}).get(CATEGORY_EXPECTED_NOT_DETECTED, 0)
        for entry in history
    ]
    not_defined_data = [
        entry.get("data", {}).get(CATEGORY_NOT_DEFINED, 0) for entry in history
    ]

    current_entry = next(
        (e for e in history if e.get("buildOrder") == current_run), None
    )
    if current_entry:
        current_stats = current_entry.get("data", {})
        total = sum(current_stats.values())
        match_count = current_stats.get(CATEGORY_MATCH, 0)
        mismatch_count = current_stats.get(CATEGORY_MISMATCH, 0)
        expected_not = current_stats.get(CATEGORY_EXPECTED_NOT_DETECTED, 0)
        match_rate = (match_count / total * 100) if total > 0 else 0
    else:
        total = match_count = mismatch_count = expected_not = 0
        match_rate = 0

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rule Mapping Trend - E2E Tests #{current_run}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh; padding: 20px; color: #e0e0e0;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ text-align: center; margin-bottom: 30px; }}
        h1 {{ font-size: 2rem; color: #4CAF50; margin-bottom: 10px; }}
        .subtitle {{ color: #888; font-size: 1rem; }}
        .back-link {{ display: inline-block; margin-top: 10px; color: #64b5f6; text-decoration: none; }}
        .back-link:hover {{ text-decoration: underline; }}
        .stats-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px; margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px;
            text-align: center; border: 1px solid rgba(255,255,255,0.1);
        }}
        .stat-card.match {{ border-color: rgba(76,175,80,0.5); }}
        .stat-card.mismatch {{ border-color: rgba(244,67,54,0.5); }}
        .stat-value {{ font-size: 2.5rem; font-weight: bold; margin-bottom: 5px; }}
        .stat-value.green {{ color: #4CAF50; }}
        .stat-value.red {{ color: #f44336; }}
        .stat-value.blue {{ color: #2196F3; }}
        .stat-value.gray {{ color: #9e9e9e; }}
        .stat-label {{ color: #888; font-size: 0.9rem; }}
        .chart-container {{
            background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px;
            margin-bottom: 30px; border: 1px solid rgba(255,255,255,0.1);
        }}
        .chart-title {{ font-size: 1.2rem; color: #fff; margin-bottom: 15px; text-align: center; }}
        .chart-wrapper {{ position: relative; height: 400px; }}
        .legend-info {{
            text-align: center; margin-top: 15px; padding-top: 15px;
            border-top: 1px solid rgba(255,255,255,0.1); font-size: 0.85rem; color: #888;
        }}
        .legend-item {{ display: inline-block; margin: 0 15px; }}
        .legend-color {{
            display: inline-block; width: 12px; height: 12px; border-radius: 2px;
            margin-right: 5px; vertical-align: middle;
        }}
        footer {{ text-align: center; color: #666; font-size: 0.8rem; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Rule Mapping Trend</h1>
            <p class="subtitle">E2E Tests #{current_run} - Pattern Rule Verification</p>
            <a href="../{current_run}/" class="back-link">&larr; Back to Allure Report</a>
        </header>
        <div class="stats-grid">
            <div class="stat-card match">
                <div class="stat-value green">{match_count}</div>
                <div class="stat-label">Rule Match</div>
            </div>
            <div class="stat-card mismatch">
                <div class="stat-value red">{mismatch_count}</div>
                <div class="stat-label">Rule Mismatch</div>
            </div>
            <div class="stat-card">
                <div class="stat-value blue">{expected_not}</div>
                <div class="stat-label">Expected Not Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value gray">{match_rate:.1f}%</div>
                <div class="stat-label">Match Rate</div>
            </div>
        </div>
        <div class="chart-container">
            <h2 class="chart-title">Rule Mapping Trend (Last {len(history)} Runs)</h2>
            <div class="chart-wrapper"><canvas id="trendChart"></canvas></div>
            <div class="legend-info">
                <span class="legend-item"><span class="legend-color" style="background:#4CAF50;"></span>Rule Match</span>
                <span class="legend-item"><span class="legend-color" style="background:#f44336;"></span>Rule Mismatch</span>
                <span class="legend-item"><span class="legend-color" style="background:#2196F3;"></span>Expected Not Detected</span>
                <span class="legend-item"><span class="legend-color" style="background:#9e9e9e;"></span>Not Defined</span>
            </div>
        </div>
        <div class="chart-container">
            <h2 class="chart-title">Rule Mismatch Trend (Detailed View)</h2>
            <div class="chart-wrapper" style="height:300px;"><canvas id="mismatchChart"></canvas></div>
            <div class="legend-info">
                <span class="legend-item"><span class="legend-color" style="background:#f44336;"></span>Rule Mismatch</span>
                <span class="legend-item"><span class="legend-color" style="background:#2196F3;"></span>Expected Not Detected</span>
                <p style="margin-top:10px;color:#666;">Focused scale for better visibility of mismatches.</p>
            </div>
        </div>
        <footer>
            Generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |
            <a href="https://github.com/takaosgb3/falco-plugin-openclaw" style="color:#64b5f6;">falco-plugin-openclaw</a>
        </footer>
    </div>
    <script>
        const labels = {json.dumps(labels)};
        const urls = {json.dumps(urls)};
        const matchData = {json.dumps(match_data)};
        const mismatchData = {json.dumps(mismatch_data)};
        const expectedNotData = {json.dumps(expected_not_detected_data)};
        const notDefinedData = {json.dumps(not_defined_data)};

        function makeDataset(label, data, color) {{
            return {{
                label, data,
                borderColor: color,
                backgroundColor: color.replace(')', ', 0.1)').replace('rgb', 'rgba'),
                fill: true, tension: 0.3, pointRadius: 4, pointHoverRadius: 6
            }};
        }}
        const commonOpts = {{
            responsive: true, maintainAspectRatio: false,
            interaction: {{ mode: 'index', intersect: false }},
            plugins: {{ legend: {{ display: false }} }},
            scales: {{
                x: {{ grid: {{ color: 'rgba(255,255,255,0.1)' }}, ticks: {{ color: '#888' }} }},
                y: {{ beginAtZero: true, grid: {{ color: 'rgba(255,255,255,0.1)' }}, ticks: {{ color: '#888' }} }}
            }},
            onClick: function(evt, elements) {{
                if (elements.length > 0) {{ const idx = elements[0].index; if (urls[idx]) window.open(urls[idx], '_blank'); }}
            }}
        }};

        new Chart(document.getElementById('trendChart').getContext('2d'), {{
            type: 'line',
            data: {{
                labels,
                datasets: [
                    makeDataset('Rule Match', matchData, 'rgb(76, 175, 80)'),
                    makeDataset('Rule Mismatch', mismatchData, 'rgb(244, 67, 54)'),
                    makeDataset('Expected Not Detected', expectedNotData, 'rgb(33, 150, 243)'),
                    makeDataset('Not Defined', notDefinedData, 'rgb(158, 158, 158)')
                ]
            }},
            options: {{
                ...commonOpts,
                plugins: {{
                    ...commonOpts.plugins,
                    tooltip: {{
                        backgroundColor: 'rgba(0,0,0,0.8)', titleColor: '#fff', bodyColor: '#e0e0e0',
                        padding: 12, displayColors: true,
                        callbacks: {{
                            title: ctx => 'Run ' + labels[ctx[0].dataIndex],
                            afterBody: ctx => {{
                                const i = ctx[0].dataIndex;
                                const t = matchData[i]+mismatchData[i]+expectedNotData[i]+notDefinedData[i];
                                return '\\nMatch Rate: '+(t>0?(matchData[i]/t*100).toFixed(1):0)+'%\\nTotal: '+t;
                            }}
                        }}
                    }}
                }}
            }}
        }});

        new Chart(document.getElementById('mismatchChart').getContext('2d'), {{
            type: 'line',
            data: {{
                labels,
                datasets: [
                    {{ ...makeDataset('Rule Mismatch', mismatchData, 'rgb(244, 67, 54)'), borderWidth: 3, pointRadius: 5 }},
                    {{ ...makeDataset('Expected Not Detected', expectedNotData, 'rgb(33, 150, 243)'), borderWidth: 2, pointRadius: 5 }}
                ]
            }},
            options: {{
                ...commonOpts,
                plugins: {{ legend: {{ display: true, position: 'top', labels: {{ color: '#888', usePointStyle: true }} }} }},
                scales: {{
                    ...commonOpts.scales,
                    y: {{ ...commonOpts.scales.y, suggestedMax: Math.max(...mismatchData, ...expectedNotData)*1.2 || 10, ticks: {{ color: '#888', stepSize: 5 }} }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
    return html


def main():
    parser = argparse.ArgumentParser(
        description="Generate Rule Mapping Trend HTML Page"
    )
    parser.add_argument("--test-results", required=True, help="Path to test-results.json")
    parser.add_argument("--run-number", type=int, required=True, help="Run number")
    parser.add_argument("--report-url", default="", help="URL to the Allure report")
    parser.add_argument("--history-input", help="Path to existing history JSON")
    parser.add_argument("--history-output", required=True, help="Output path for history JSON")
    parser.add_argument("--html-output", required=True, help="Output path for HTML page")
    parser.add_argument("--max-history", type=int, default=20, help="Max history entries")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    test_results_path = Path(args.test_results)
    if not test_results_path.exists():
        logger.error(f"Test results file not found: {args.test_results}")
        sys.exit(1)

    try:
        with open(test_results_path, "r") as f:
            test_results = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Could not read test results: {e}")
        sys.exit(1)

    if not isinstance(test_results, list):
        logger.error(f"Expected JSON array, got {type(test_results).__name__}")
        sys.exit(1)

    logger.info(f"Loaded {len(test_results)} test results")

    stats = calculate_statistics(test_results)
    logger.info(f"Rule Mapping Statistics: {stats}")

    new_entry = create_trend_entry(
        run_number=args.run_number, report_url=args.report_url, stats=stats
    )

    existing_history = []
    if args.history_input:
        history_path = Path(args.history_input)
        if history_path.exists():
            try:
                with open(history_path, "r") as f:
                    existing_history = json.load(f)
                logger.info(f"Loaded {len(existing_history)} existing history entries")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load history: {e}, starting fresh")

    updated_history = merge_trend_history(
        new_entry=new_entry,
        existing_history=existing_history,
        max_history=args.max_history,
    )

    history_output_path = Path(args.history_output)
    history_output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(history_output_path, "w") as f:
        json.dump(updated_history, f, indent=2)
    logger.info(f"Written {len(updated_history)} history entries to {args.history_output}")

    html_content = generate_html(updated_history, args.run_number)
    html_output_path = Path(args.html_output)
    html_output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(html_output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info(f"Generated HTML: {args.html_output}")

    total = sum(stats.values())
    match_rate = (stats[CATEGORY_MATCH] / total * 100) if total > 0 else 0
    print(f"\n{'='*50}")
    print("Rule Mapping Trend HTML Generated")
    print(f"{'='*50}")
    print(f"Run Number: {args.run_number}")
    print(f"Total Patterns: {total}")
    print(f"  - {CATEGORY_MATCH}: {stats[CATEGORY_MATCH]}")
    print(f"  - {CATEGORY_MISMATCH}: {stats[CATEGORY_MISMATCH]}")
    print(f"  - {CATEGORY_EXPECTED_NOT_DETECTED}: {stats[CATEGORY_EXPECTED_NOT_DETECTED]}")
    print(f"  - {CATEGORY_NOT_DEFINED}: {stats[CATEGORY_NOT_DEFINED]}")
    print(f"Match Rate: {match_rate:.1f}%")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
