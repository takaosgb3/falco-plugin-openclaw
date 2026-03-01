#!/usr/bin/env python3
"""batch_analyzer.py — Falco E2E test result analyzer for OpenClaw.

Analyzes Falco output from inject_patterns.sh, correlates alerts with
test patterns via session_id, and generates test-results.json + summary.json.

Usage:
    python3 batch_analyzer.py \
        --patterns test/e2e/patterns/categories \
        --falco-log e2e/results/falco-output.log \
        --test-ids e2e/results/test-ids.json \
        --output e2e/results/test-results.json \
        --summary-output e2e/results/summary.json \
        [--verbose]

Exit codes:
    0  Analysis complete (detection rate >= threshold)
    1  Analysis complete but detection rate < threshold

Environment variables:
    MIN_DETECTION_RATE    Minimum detection rate threshold (default: 0.95)
    GITHUB_ACTIONS        "true" to simplify log format
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path


# Threat categories that should be detected (positive patterns)
POSITIVE_CATEGORIES = {
    "dangerous_command",
    "data_exfiltration",
    "agent_runaway",
    "workspace_escape",
    "suspicious_config",
    "unauthorized_model",
    "shell_injection",
}

# Default minimum detection rate
DEFAULT_MIN_DETECTION_RATE = 0.95


class BatchAnalyzer:
    """Analyzes Falco E2E test results by correlating alerts with test patterns."""

    def __init__(self, patterns_dir: str, verbose: bool = False):
        self.verbose = verbose
        self.pattern_map: dict = {}
        self._load_patterns(patterns_dir)

    def _load_patterns(self, patterns_dir: str) -> None:
        """Load all pattern JSON files and build pattern_map[id]."""
        patterns_path = Path(patterns_dir)
        if not patterns_path.is_dir():
            print(f"Error: Patterns directory not found: {patterns_dir}", file=sys.stderr)
            sys.exit(1)

        for json_file in sorted(patterns_path.glob("*.json")):
            try:
                with open(json_file, "r") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"Warning: Failed to load {json_file}: {e}", file=sys.stderr)
                continue

            category = data.get("category", "unknown")
            for pattern in data.get("patterns", []):
                pid = pattern.get("id", "")
                if pid:
                    pattern["_category"] = category
                    pattern["_source_file"] = json_file.name
                    self.pattern_map[pid] = pattern

        if self.verbose:
            print(f"[DEBUG] Loaded {len(self.pattern_map)} patterns from {patterns_dir}",
                  file=sys.stderr)

    def parse_falco_log(self, log_path: str) -> dict:
        """Parse falco-output.log (JSON lines) and return detections by session_id.

        Returns:
            dict: {session_id: [{"rule": str, "output": str, "time": str, ...}, ...]}
        """
        detections: dict = {}
        log_file = Path(log_path)

        if not log_file.is_file():
            print(f"Warning: Falco log not found: {log_path}", file=sys.stderr)
            return detections

        with open(log_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    if self.verbose:
                        print(f"[DEBUG] Skipping non-JSON line {line_num}: {line[:80]}",
                              file=sys.stderr)
                    continue

                # Extract session_id from output_fields
                output_fields = alert.get("output_fields", {})
                session_id = output_fields.get("openclaw.session_id", "")

                if not session_id:
                    if self.verbose:
                        print(f"[DEBUG] Alert without session_id at line {line_num}",
                              file=sys.stderr)
                    continue

                detection = {
                    "rule": alert.get("rule", ""),
                    "output": alert.get("output", ""),
                    "priority": alert.get("priority", ""),
                    "time": alert.get("time", ""),
                    "source": alert.get("source", ""),
                    "output_fields": output_fields,
                }

                if session_id not in detections:
                    detections[session_id] = []
                detections[session_id].append(detection)

        if self.verbose:
            total_alerts = sum(len(v) for v in detections.values())
            print(f"[DEBUG] Parsed {total_alerts} alerts for "
                  f"{len(detections)} unique session_ids", file=sys.stderr)

        return detections

    def match_patterns(self, detections: dict, test_ids: list) -> list:
        """Correlate detections with test patterns via session_id.

        Args:
            detections: {session_id: [detection, ...]} from parse_falco_log
            test_ids: list of {test_id, pattern_id, category, sent_at} from test-ids.json

        Returns:
            list of result dicts for each pattern
        """
        results = []

        for test_entry in test_ids:
            pattern_id = test_entry.get("pattern_id", "")
            test_id = test_entry.get("test_id", pattern_id)
            category = test_entry.get("category", "")
            sent_at = test_entry.get("sent_at", 0)

            pattern_info = self.pattern_map.get(pattern_id, {})
            expected_rule = pattern_info.get("expected_rule", "")
            expected_rules = pattern_info.get("expected_rules", [])

            # Get detections for this pattern
            pattern_detections = detections.get(pattern_id, [])
            detected = len(pattern_detections) > 0

            # Collect all matched rules
            matched_rules = [d["rule"] for d in pattern_detections]
            matched_rule = matched_rules[0] if matched_rules else ""

            # Calculate rule match
            rule_match = self._check_rule_match(
                expected_rule, expected_rules, matched_rules
            )

            # Calculate latency
            latency_ms = self._calculate_latency(pattern_detections, sent_at)

            # Get evidence (first detection's output)
            evidence = pattern_detections[0]["output"] if pattern_detections else ""

            # Determine status
            status = self._determine_status(
                category, expected_rule, expected_rules,
                detected, rule_match, pattern_info
            )

            result = {
                "pattern_id": pattern_id,
                "category": category,
                "detected": detected,
                "expected_rule": expected_rule,
                "matched_rule": matched_rule,
                "rule_match": rule_match,
                "latency_ms": latency_ms,
                "evidence": evidence,
                "status": status,
            }

            # Add matched_rules array for composite patterns
            if expected_rules:
                result["matched_rules"] = matched_rules

            results.append(result)

        return results

    def _check_rule_match(self, expected_rule: str, expected_rules: list,
                          matched_rules: list) -> bool:
        """Check if expected rules match actual detections.

        Note: Falco 0.43.0 fires only ONE rule per event (highest priority).
        For composite patterns with expected_rules[], we check that the primary
        expected_rule matches, since multiple rules won't fire simultaneously.
        """
        if expected_rules and expected_rule:
            # Composite pattern: check primary expected_rule matches
            # (Falco fires only the highest-priority matching rule per event)
            return any(
                self.compare_rules(expected_rule, matched)
                for matched in matched_rules
            )
        elif expected_rules:
            # Composite without primary: check any expected rule matches
            for expected in expected_rules:
                if any(self.compare_rules(expected, matched)
                       for matched in matched_rules):
                    return True
            return False
        elif expected_rule:
            # Single rule: at least one detection must match
            return any(
                self.compare_rules(expected_rule, matched)
                for matched in matched_rules
            )
        else:
            # No expected rule (benign/non-detection): no detection is correct
            return not matched_rules

    def _calculate_latency(self, detections: list, sent_at_ms: int) -> int:
        """Calculate detection latency in milliseconds."""
        if not detections or sent_at_ms == 0:
            return -1

        first_detection = detections[0]
        time_str = first_detection.get("time", "")
        if not time_str:
            return -1

        try:
            # Parse ISO 8601 timestamp from Falco
            # Format: "2026-02-28T10:00:00.123456789Z"
            # Python's fromisoformat doesn't handle nanoseconds, so truncate
            clean_time = re.sub(r"(\.\d{6})\d*", r"\1", time_str)
            clean_time = clean_time.replace("Z", "+00:00")
            detected_dt = datetime.fromisoformat(clean_time)
            detected_ms = int(detected_dt.timestamp() * 1000)
            return max(0, detected_ms - sent_at_ms)
        except (ValueError, OSError):
            if self.verbose:
                print(f"[DEBUG] Failed to parse time: {time_str}", file=sys.stderr)
            return -1

    def _determine_status(self, category: str, expected_rule: str,
                          expected_rules: list, detected: bool,
                          rule_match: bool, pattern_info: dict) -> str:
        """Determine test status (passed/failed)."""
        if category == "benign":
            # Benign patterns: check if detection matches expected behavior
            expected_threat = pattern_info.get("expected_threat", "")
            if expected_rule:
                # Falco-level detection expected (even if parser doesn't detect)
                return "passed" if (detected and rule_match) else "failed"
            elif expected_threat:
                # Parser-level detection expected
                return "passed" if detected else "failed"
            else:
                # True negatives: no detection expected
                return "passed" if not detected else "failed"
        elif category in ("edge_cases", "composite", "plaintext_threats"):
            # Special categories: check expected_threat (Falco-level) first,
            # then expected_parser_threat (parser-level) separately.
            # These fields have different semantics — expected_threat is the
            # Falco rule-level expectation, expected_parser_threat is the
            # parser's DetectThreat() output (may differ due to 10KB truncation).
            expected_threat = pattern_info.get("expected_threat", "")
            if not expected_threat:
                expected_threat = pattern_info.get("expected_parser_threat", "")
            if expected_rules:
                # Composite: all expected rules must match
                return "passed" if rule_match else "failed"
            elif expected_rule:
                # Has expected rule: must detect and match
                return "passed" if (detected and rule_match) else "failed"
            elif expected_threat == "":
                # No detection expected
                return "passed" if not detected else "failed"
            else:
                return "passed" if detected else "failed"
        elif category in POSITIVE_CATEGORIES:
            # Positive patterns: must detect and rule must match
            return "passed" if (detected and rule_match) else "failed"
        else:
            # Unknown category: just check detection
            return "passed" if detected else "failed"

    @staticmethod
    def compare_rules(expected: str, actual: str) -> bool:
        """Compare rule names with multiple matching strategies.

        Strategies (in order):
        1. Exact match
        2. Normalized match (lowercase, stripped prefix)
        3. Partial match (expected contained in actual or vice versa)
        """
        if not expected or not actual:
            return False

        # 1. Exact match
        if expected == actual:
            return True

        # 2. Normalized match
        norm_expected = BatchAnalyzer.normalize_rule_name(expected)
        norm_actual = BatchAnalyzer.normalize_rule_name(actual)
        if norm_expected == norm_actual:
            return True

        # 3. Partial match
        if norm_expected in norm_actual or norm_actual in norm_expected:
            return True

        return False

    @staticmethod
    def normalize_rule_name(name: str) -> str:
        """Normalize rule name by removing [OPENCLAW XXX] prefix and lowercasing.

        Example: "[OPENCLAW DangerousCmd] Dangerous Command Execution"
                 -> "dangerous command execution"
        """
        # Remove [OPENCLAW ...] prefix
        normalized = re.sub(r"^\[OPENCLAW\s+\w+\]\s*", "", name)
        return normalized.strip().lower()

    def generate_summary(self, results: list) -> dict:
        """Generate summary statistics from test results."""
        positive_results = []
        negative_results = []
        edge_case_results = []
        composite_results = []
        plaintext_results = []
        latencies = []

        for r in results:
            cat = r["category"]
            if cat in POSITIVE_CATEGORIES:
                positive_results.append(r)
            elif cat == "benign":
                negative_results.append(r)
            elif cat == "edge_cases":
                edge_case_results.append(r)
            elif cat == "composite":
                composite_results.append(r)
            elif cat == "plaintext_threats":
                plaintext_results.append(r)

            if r.get("latency_ms", -1) >= 0:
                latencies.append(r["latency_ms"])

        # Positive patterns
        pos_detected = sum(1 for r in positive_results if r["detected"] and r["rule_match"])
        pos_total = len(positive_results)
        detection_rate = pos_detected / pos_total if pos_total > 0 else 0.0

        # Negative patterns (false positives)
        neg_total = len(negative_results)
        false_positives = 0
        for r in negative_results:
            pattern_info = self.pattern_map.get(r["pattern_id"], {})
            expected_threat = pattern_info.get("expected_threat", "")
            expected_rule = pattern_info.get("expected_rule", "")
            if not expected_threat and not expected_rule and r["detected"]:
                false_positives += 1

        fp_rate = false_positives / neg_total if neg_total > 0 else 0.0

        # Latency stats
        latency_stats = {}
        if latencies:
            latency_stats = {
                "avg_ms": int(sum(latencies) / len(latencies)),
                "min_ms": min(latencies),
                "max_ms": max(latencies),
            }
        else:
            latency_stats = {"avg_ms": 0, "min_ms": 0, "max_ms": 0}

        summary = {
            "positive_patterns": {
                "total": pos_total,
                "detected": pos_detected,
                "detection_rate": round(detection_rate, 4),
            },
            "negative_patterns": {
                "total": neg_total,
                "false_positives": false_positives,
                "fp_rate": round(fp_rate, 4),
            },
            "edge_case_patterns": {
                "total": len(edge_case_results),
                "passed": sum(1 for r in edge_case_results if r["status"] == "passed"),
            },
            "composite_patterns": {
                "total": len(composite_results),
                "passed": sum(1 for r in composite_results if r["status"] == "passed"),
            },
            "plaintext_patterns": {
                "total": len(plaintext_results),
                "passed": sum(1 for r in plaintext_results if r["status"] == "passed"),
            },
            "latency": latency_stats,
        }

        return summary


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Falco E2E test results for OpenClaw"
    )
    parser.add_argument(
        "--patterns", required=True,
        help="Pattern JSON directory (e.g., test/e2e/patterns/categories)"
    )
    parser.add_argument(
        "--falco-log", required=True,
        help="Falco output log file (JSON lines)"
    )
    parser.add_argument(
        "--test-ids", required=True,
        help="Test IDs file from inject_patterns.sh"
    )
    parser.add_argument(
        "--output", required=True,
        help="Output path for test-results.json"
    )
    parser.add_argument(
        "--summary-output", required=True,
        help="Output path for summary.json"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose output"
    )
    args = parser.parse_args()

    is_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    min_detection_rate = float(
        os.environ.get("MIN_DETECTION_RATE", str(DEFAULT_MIN_DETECTION_RATE))
    )

    # Initialize analyzer
    analyzer = BatchAnalyzer(args.patterns, verbose=args.verbose)

    # Load test IDs
    try:
        with open(args.test_ids, "r") as f:
            test_ids = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error: Failed to load test-ids: {e}", file=sys.stderr)
        sys.exit(1)

    # Parse Falco log
    detections = analyzer.parse_falco_log(args.falco_log)

    # Match patterns with detections
    results = analyzer.match_patterns(detections, test_ids)

    # Generate summary
    summary = analyzer.generate_summary(results)

    # Write outputs
    output_dir = Path(args.output).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    with open(args.summary_output, "w") as f:
        json.dump(summary, f, indent=2)

    # Print summary
    pos = summary["positive_patterns"]
    neg = summary["negative_patterns"]
    edge = summary["edge_case_patterns"]
    comp = summary["composite_patterns"]
    plain = summary["plaintext_patterns"]
    lat = summary["latency"]

    total_passed = sum(1 for r in results if r["status"] == "passed")
    total_failed = sum(1 for r in results if r["status"] == "failed")

    prefix = "" if is_ci else ""
    print(f"\n{prefix}=== OpenClaw E2E Test Results ===")
    print(f"  Total patterns: {len(results)} (passed: {total_passed}, failed: {total_failed})")
    print(f"  Detection rate: {pos['detection_rate']:.1%} ({pos['detected']}/{pos['total']})")
    print(f"  False positive rate: {neg['fp_rate']:.1%} ({neg['false_positives']}/{neg['total']})")
    print(f"  Edge cases: {edge['passed']}/{edge['total']} passed")
    print(f"  Composite: {comp['passed']}/{comp['total']} passed")
    print(f"  Plaintext: {plain['passed']}/{plain['total']} passed")
    if lat["avg_ms"] > 0:
        print(f"  Latency: avg={lat['avg_ms']}ms min={lat['min_ms']}ms max={lat['max_ms']}ms")
    print(f"  Results: {args.output}")
    print(f"  Summary: {args.summary_output}")

    # Check detection rate threshold
    if pos["detection_rate"] < min_detection_rate:
        print(f"\nFAILED: Detection rate {pos['detection_rate']:.1%} "
              f"< threshold {min_detection_rate:.1%}", file=sys.stderr)
        sys.exit(1)

    # Print failures if any
    if total_failed > 0:
        print(f"\n--- Failed patterns ({total_failed}) ---")
        for r in results:
            if r["status"] == "failed":
                print(f"  {r['pattern_id']} ({r['category']}): "
                      f"detected={r['detected']}, "
                      f"expected={r['expected_rule']}, "
                      f"matched={r['matched_rule']}")

    print(f"\n{prefix}Analysis complete.")


if __name__ == "__main__":
    main()
