#!/usr/bin/env python3
"""
Canonical Onboarding Pathway Scanner

Scans local artifacts to determine integration readiness along two ordered
pathways (PRODUCER and CONSUMER). Each pathway has 8 dependency-ordered
checkpoints. Outputs a dated readiness report with exact next-step commands.

Zero external dependencies — stdlib only.

Usage:
    python3 scan_pathway.py --role CONSUMER \
        --discovery-result discovery.json \
        --signal-sample signals.json \
        --trust-eval trust.json \
        --acceptance-report acceptance.json \
        --activity-feed feed.json \
        --verification-report verification.json \
        --health-report health.json \
        -o consumer_pathway_report.json

    python3 scan_pathway.py --role PRODUCER \
        --signal-sample signals.json \
        --proof-surface proof.json \
        --health-report health.json \
        --trust-eval trust.json \
        --activity-feed feed.json \
        --discovery-result discovery.json \
        -o producer_pathway_report.json
"""

import argparse
import copy
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCANNER_VERSION = "1.0.0"
GENERATOR_VERSION = "1.0.0"

# Consumer pathway: 8 ordered checkpoints with dependency DAG
CONSUMER_CHECKPOINTS = [
    {
        "checkpoint_id": "C-DISCOVERY",
        "checkpoint_name": "Discovery Protocol",
        "order": 1,
        "depends_on": [],
        "protocol": "pf-discovery-protocol",
        "description": "Locate and register with available signal producers via discovery protocol"
    },
    {
        "checkpoint_id": "C-SCHEMA",
        "checkpoint_name": "Schema Compliance",
        "order": 2,
        "depends_on": ["C-DISCOVERY"],
        "protocol": "pf-signal-schema",
        "description": "Validate that discovered producer signals conform to canonical signal schema"
    },
    {
        "checkpoint_id": "C-ROUTING",
        "checkpoint_name": "Routing Configuration",
        "order": 3,
        "depends_on": ["C-SCHEMA"],
        "protocol": "pf-routing-protocol",
        "description": "Configure signal routing with preflight filters, VOI gates, and duration limits"
    },
    {
        "checkpoint_id": "C-TRUST",
        "checkpoint_name": "Trust Evaluation",
        "order": 4,
        "depends_on": ["C-ROUTING"],
        "protocol": "pf-trust-gateway",
        "description": "Evaluate producer trustworthiness across 5 dimensions before consuming signals"
    },
    {
        "checkpoint_id": "C-ACCEPTANCE",
        "checkpoint_name": "Acceptance Testing",
        "order": 5,
        "depends_on": ["C-TRUST"],
        "protocol": "pf-acceptance-test",
        "description": "Run 7-check acceptance test to validate integration readiness"
    },
    {
        "checkpoint_id": "C-CONSUMPTION",
        "checkpoint_name": "Signal Consumption",
        "order": 6,
        "depends_on": ["C-ACCEPTANCE"],
        "protocol": "pf-consumer-activity-feed",
        "description": "Begin consuming signals and generating activity feed with run tracking"
    },
    {
        "checkpoint_id": "C-VERIFICATION",
        "checkpoint_name": "Consumption Verification",
        "order": 7,
        "depends_on": ["C-CONSUMPTION"],
        "protocol": "pf-consumer-verification",
        "description": "Verify consumption with replay runner and dated attestation"
    },
    {
        "checkpoint_id": "C-MONITORING",
        "checkpoint_name": "Health Monitoring",
        "order": 8,
        "depends_on": ["C-VERIFICATION"],
        "protocol": "pf-health-monitor",
        "description": "Establish ongoing health monitoring with 6-dimension scoring and alerting"
    }
]

# Producer pathway: 8 ordered checkpoints with dependency DAG
PRODUCER_CHECKPOINTS = [
    {
        "checkpoint_id": "P-SCHEMA",
        "checkpoint_name": "Schema Compliance",
        "order": 1,
        "depends_on": [],
        "protocol": "pf-signal-schema",
        "description": "Ensure signals conform to canonical signal schema with required fields and valid enums"
    },
    {
        "checkpoint_id": "P-DELIVERY",
        "checkpoint_name": "Signal Delivery",
        "order": 2,
        "depends_on": ["P-SCHEMA"],
        "protocol": "pf-signal-schema",
        "description": "Demonstrate reliable signal delivery with consistent cadence and valid timestamps"
    },
    {
        "checkpoint_id": "P-RESOLUTION",
        "checkpoint_name": "Resolution Protocol",
        "order": 3,
        "depends_on": ["P-DELIVERY"],
        "protocol": "pf-resolution-protocol",
        "description": "Resolve signals against market outcomes with reputation formula and karma tracking"
    },
    {
        "checkpoint_id": "P-PROOF",
        "checkpoint_name": "Proof Surface",
        "order": 4,
        "depends_on": ["P-RESOLUTION"],
        "protocol": "pf-proof-protocol",
        "description": "Maintain proof surface with CUSUM drift detection, rolling windows, and freshness grading"
    },
    {
        "checkpoint_id": "P-DISCOVERY",
        "checkpoint_name": "Discovery Registration",
        "order": 5,
        "depends_on": ["P-PROOF"],
        "protocol": "pf-discovery-protocol",
        "description": "Register as discoverable producer with liveness grading and metadata"
    },
    {
        "checkpoint_id": "P-HEALTH",
        "checkpoint_name": "Health Reporting",
        "order": 6,
        "depends_on": ["P-DISCOVERY"],
        "protocol": "pf-health-monitor",
        "description": "Generate health reports with 6-dimension scoring for consumer visibility"
    },
    {
        "checkpoint_id": "P-TRUST",
        "checkpoint_name": "Trust Readiness",
        "order": 7,
        "depends_on": ["P-HEALTH"],
        "protocol": "pf-trust-gateway",
        "description": "Achieve trust evaluation readiness with ADOPT or ADOPT_WITH_CAVEATS verdict"
    },
    {
        "checkpoint_id": "P-ACTIVITY",
        "checkpoint_name": "Activity Feed",
        "order": 8,
        "depends_on": ["P-TRUST"],
        "protocol": "pf-consumer-activity-feed",
        "description": "Publish consumer activity feed showing downstream consumption and error rates"
    }
]

# Next-step command templates per checkpoint
NEXT_STEP_COMMANDS = {
    # Consumer
    "C-DISCOVERY": "python3 discover_producers.py --registry-url <REGISTRY_URL> --output discovery_result.json",
    "C-SCHEMA": "python3 -c \"from schema_validator import SchemaValidator; v=SchemaValidator(); print(v.validate_signal(signal))\"",
    "C-ROUTING": "python3 preflight_filter.py --signal-file signals.json --policy routing_policy.json --output routed.json",
    "C-TRUST": "python3 evaluate_trust.py --proof-surface proof_surface.json --health-report health.json --activity-feed feed.json --output trust_eval.json",
    "C-ACCEPTANCE": "python3 acceptance_test.py --signal-sample signals.json --proof-surface proof_surface.json --trust-eval trust.json --output acceptance.json",
    "C-CONSUMPTION": "python3 generate_feed.py --signal-log signal_log.json --proof-surface proof_surface.json --output activity_feed.json",
    "C-VERIFICATION": "python3 replay_runner.py --signal-log signal_log.json --proof-surface proof_surface.json --adapter-manifest adapter.json --output verification.json",
    "C-MONITORING": "python3 check_health.py --proof-surface proof_surface.json --activity-feed feed.json --output health_report.json",
    # Producer
    "P-SCHEMA": "python3 -c \"from schema_validator import SchemaValidator; v=SchemaValidator(); print(v.conformance_report(signals))\"",
    "P-DELIVERY": "python3 generate_test_signals.py --count 100 --symbols BTC,ETH,SOL,LINK --output test_signals.json",
    "P-RESOLUTION": "python3 resolve_signals.py --signals signals.json --prices prices.json --output resolved.json",
    "P-PROOF": "python3 maintain_proof.py --resolved resolved.json --output proof_surface.json",
    "P-DISCOVERY": "python3 register_producer.py --registry-url <REGISTRY_URL> --proof-surface proof_surface.json --producer-id <ID>",
    "P-HEALTH": "python3 check_health.py --proof-surface proof_surface.json --activity-feed feed.json --output health_report.json",
    "P-TRUST": "python3 evaluate_trust.py --proof-surface proof_surface.json --health-report health.json --output trust_eval.json",
    "P-ACTIVITY": "python3 generate_feed.py --signal-log signal_log.json --proof-surface proof_surface.json --output activity_feed.json"
}

# Next-step action descriptions
NEXT_STEP_ACTIONS = {
    "C-DISCOVERY": "Run discovery protocol to locate available signal producers",
    "C-SCHEMA": "Validate discovered signals against canonical schema",
    "C-ROUTING": "Configure preflight filters and routing policy for signal intake",
    "C-TRUST": "Evaluate producer trust across 5 dimensions before consuming signals",
    "C-ACCEPTANCE": "Run 7-check acceptance test to validate integration readiness",
    "C-CONSUMPTION": "Begin consuming signals and generate activity feed",
    "C-VERIFICATION": "Verify consumption with replay runner and generate attestation",
    "C-MONITORING": "Set up ongoing health monitoring with 6-dimension scoring",
    "P-SCHEMA": "Validate signal output against canonical schema conformance",
    "P-DELIVERY": "Generate and deliver test signals with consistent cadence",
    "P-RESOLUTION": "Resolve signals against market outcomes with reputation formula",
    "P-PROOF": "Build and maintain proof surface with drift detection",
    "P-DISCOVERY": "Register as discoverable producer in protocol registry",
    "P-HEALTH": "Generate health report with 6-dimension scoring",
    "P-TRUST": "Achieve trust-ready status with ADOPT verdict",
    "P-ACTIVITY": "Publish activity feed showing downstream consumption"
}

# Limitations
LIMITATIONS = [
    {
        "id": "LIM-001",
        "description": "Scanner validates artifact structure but cannot verify live network connectivity or real-time producer availability",
        "bias_direction": "OVERSTATED_READINESS",
        "bias_magnitude": "MEDIUM"
    },
    {
        "id": "LIM-002",
        "description": "Checkpoint validators check JSON structure and key fields but do not re-run full protocol validation pipelines",
        "bias_direction": "OVERSTATED_READINESS",
        "bias_magnitude": "LOW"
    },
    {
        "id": "LIM-003",
        "description": "Dependency propagation uses strict BLOCKED status which may understate readiness when partial progress exists on blocked checkpoints",
        "bias_direction": "UNDERSTATED_READINESS",
        "bias_magnitude": "LOW"
    },
    {
        "id": "LIM-004",
        "description": "Scanner does not validate temporal consistency between artifacts — a stale proof surface may pass structural checks",
        "bias_direction": "OVERSTATED_READINESS",
        "bias_magnitude": "MEDIUM"
    },
    {
        "id": "LIM-005",
        "description": "Next-step commands use template paths that may not match the users actual file layout",
        "bias_direction": "INDETERMINATE",
        "bias_magnitude": "LOW"
    },
    {
        "id": "LIM-006",
        "description": "Hash chain previous_report_hash is null on first scan — chain integrity verification requires multiple scans over time",
        "bias_direction": "INDETERMINATE",
        "bias_magnitude": "LOW"
    }
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_json(path):
    """Load JSON file, return None if not found or invalid."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def sha256_dict(d):
    """Deterministic SHA-256 of a dict."""
    raw = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def safe_get(d, *keys, default=None):
    """Nested dict getter."""
    current = d
    for k in keys:
        if isinstance(current, dict) and k in current:
            current = current[k]
        else:
            return default
    return current


def score_to_grade(rate):
    """Convert 0-1 completion rate to letter grade."""
    if rate >= 1.0:
        return "A"
    if rate >= 0.75:
        return "B"
    if rate >= 0.50:
        return "C"
    if rate >= 0.25:
        return "D"
    return "F"


def compute_readiness(completed, total, has_blocked):
    """Compute readiness enum from counts."""
    if has_blocked:
        return "BLOCKED"
    if completed == total:
        return "READY"
    if completed >= 6:
        return "NEARLY_READY"
    if completed >= 1:
        return "IN_PROGRESS"
    return "NOT_STARTED"


def make_check(name, passed, detail):
    """Create a single check result dict."""
    return {"check_name": name, "passed": passed, "detail": detail}


# ---------------------------------------------------------------------------
# Consumer checkpoint validators
# ---------------------------------------------------------------------------
def validate_c_discovery(artifacts):
    """C-DISCOVERY: Validate discovery result artifact."""
    checks = []
    data = artifacts.get("discovery_result")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No discovery result artifact provided"))
        return checks

    checks.append(make_check("artifact_exists", True, "Discovery result artifact found"))

    # Check for basic structure
    if isinstance(data, dict):
        checks.append(make_check("is_dict", True, "Discovery result is a dict"))
    else:
        checks.append(make_check("is_dict", False, "Discovery result is not a dict"))
        return checks

    # Check for producers field
    producers = data.get("producers", data.get("results", data.get("registry", [])))
    if isinstance(producers, list) and len(producers) > 0:
        checks.append(make_check("has_producers", True, f"Found {len(producers)} producer(s)"))
    elif isinstance(producers, dict) and len(producers) > 0:
        checks.append(make_check("has_producers", True, f"Found producer registry with {len(producers)} entries"))
    else:
        checks.append(make_check("has_producers", False, "No producers found in discovery result"))

    # Check for metadata/version
    has_version = "version" in data or "protocol_version" in data or "scanner_version" in data or "discovery_version" in data
    checks.append(make_check("has_version", has_version,
                             "Version field present" if has_version else "No version field found"))

    # Check for timestamp
    has_ts = any(k in data for k in ("generated_at", "timestamp", "discovered_at", "scan_date", "meta"))
    checks.append(make_check("has_timestamp", has_ts,
                             "Timestamp field present" if has_ts else "No timestamp field found"))

    return checks


def validate_c_schema(artifacts):
    """C-SCHEMA: Validate signal sample for schema compliance."""
    checks = []
    data = artifacts.get("signal_sample")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No signal sample artifact provided"))
        return checks

    checks.append(make_check("artifact_exists", True, "Signal sample artifact found"))

    # Determine signal list
    if isinstance(data, list):
        signals = data
    elif isinstance(data, dict):
        raw = data.get("signals", [data])
        signals = raw if isinstance(raw, list) else []
    else:
        signals = []

    if len(signals) == 0:
        checks.append(make_check("has_signals", False, "No signals found in sample"))
        return checks

    checks.append(make_check("has_signals", True, f"Found {len(signals)} signal(s)"))

    # Check first signal for required fields
    required = ["signal_id", "symbol", "direction", "confidence"]
    sig = signals[0] if isinstance(signals[0], dict) else {}
    for field in required:
        present = field in sig
        checks.append(make_check(f"signal_has_{field}", present,
                                 f"Signal has {field}" if present else f"Signal missing {field}"))

    # Direction enum check
    direction = sig.get("direction", "")
    valid_dirs = ("bullish", "bearish")
    dir_ok = direction in valid_dirs
    checks.append(make_check("direction_valid", dir_ok,
                             f"Direction '{direction}' is valid" if dir_ok else f"Direction '{direction}' not in {valid_dirs}"))

    # Confidence bounds
    conf = sig.get("confidence", -1)
    conf_ok = isinstance(conf, (int, float)) and 0 <= conf <= 1
    checks.append(make_check("confidence_bounds", conf_ok,
                             f"Confidence {conf} in [0,1]" if conf_ok else f"Confidence {conf} out of bounds"))

    return checks


def validate_c_routing(artifacts):
    """C-ROUTING: Validate routing configuration."""
    checks = []
    # Routing is validated by having valid signals + proof of routing awareness
    data = artifacts.get("signal_sample")
    if data is None:
        checks.append(make_check("signal_sample_exists", False, "No signal sample for routing validation"))
        return checks

    checks.append(make_check("signal_sample_exists", True, "Signal sample available for routing validation"))

    signals = data if isinstance(data, list) else data.get("signals", [data]) if isinstance(data, dict) else []

    # Check for routing-relevant fields
    if len(signals) > 0:
        sig = signals[0] if isinstance(signals[0], dict) else {}

        # Duration/horizon
        has_horizon = "horizon_hours" in sig or "duration" in sig or "horizon" in sig
        checks.append(make_check("has_horizon", has_horizon,
                                 "Horizon/duration field present" if has_horizon else "No horizon/duration field"))

        # Symbol field for routing
        has_symbol = "symbol" in sig
        checks.append(make_check("has_symbol", has_symbol,
                                 "Symbol field present for routing" if has_symbol else "No symbol field"))

        # Confidence for VOI gate
        has_conf = "confidence" in sig
        checks.append(make_check("has_confidence", has_conf,
                                 "Confidence field present for VOI gate" if has_conf else "No confidence field"))

        # Check for regime awareness
        has_regime = any(k in sig for k in ("regime", "action", "market_regime"))
        checks.append(make_check("has_regime", has_regime,
                                 "Regime field present for routing decisions" if has_regime else "No regime field found"))
    else:
        checks.append(make_check("has_signals", False, "No signals to validate routing"))

    return checks


def validate_c_trust(artifacts):
    """C-TRUST: Validate trust evaluation artifact."""
    checks = []
    data = artifacts.get("trust_eval")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No trust evaluation artifact provided"))
        return checks

    checks.append(make_check("artifact_exists", True, "Trust evaluation artifact found"))

    if not isinstance(data, dict):
        checks.append(make_check("is_dict", False, "Trust evaluation is not a dict"))
        return checks

    checks.append(make_check("is_dict", True, "Trust evaluation is a dict"))

    # Check for verdict
    verdict = safe_get(data, "verdict") or safe_get(data, "trust_verdict") or safe_get(data, "evaluation", "verdict")
    if verdict is not None:
        checks.append(make_check("has_verdict", True, f"Trust verdict present: {verdict}"))
        # Check verdict value
        valid_verdicts = ("ADOPT", "ADOPT_WITH_CAVEATS", "WAIT", "AVOID")
        if isinstance(verdict, dict):
            v = verdict.get("readiness", verdict.get("recommendation", ""))
        else:
            v = str(verdict)
        is_valid = v in valid_verdicts
        checks.append(make_check("verdict_valid", is_valid,
                                 f"Verdict '{v}' is valid" if is_valid else f"Verdict '{v}' not in {valid_verdicts}"))
    else:
        checks.append(make_check("has_verdict", False, "No trust verdict found"))
        checks.append(make_check("verdict_valid", False, "Cannot validate missing verdict"))

    # Check for trust dimensions
    dimensions = safe_get(data, "dimensions") or safe_get(data, "trust_dimensions")
    if dimensions is not None:
        checks.append(make_check("has_dimensions", True, "Trust dimensions present"))
    else:
        checks.append(make_check("has_dimensions", False, "No trust dimensions found"))

    return checks


def validate_c_acceptance(artifacts):
    """C-ACCEPTANCE: Validate acceptance test report."""
    checks = []
    data = artifacts.get("acceptance_report")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No acceptance report artifact provided"))
        return checks

    checks.append(make_check("artifact_exists", True, "Acceptance report artifact found"))

    if not isinstance(data, dict):
        checks.append(make_check("is_dict", False, "Acceptance report is not a dict"))
        return checks

    checks.append(make_check("is_dict", True, "Acceptance report is a dict"))

    # Check for verdict
    verdict = safe_get(data, "verdict") or safe_get(data, "acceptance_verdict")
    if verdict is not None:
        checks.append(make_check("has_verdict", True, f"Acceptance verdict present"))
        if isinstance(verdict, dict):
            readiness = verdict.get("readiness", "")
        else:
            readiness = str(verdict)
        valid = ("READY", "NOT_READY", "PARTIAL")
        is_valid = readiness in valid
        checks.append(make_check("verdict_valid", is_valid,
                                 f"Readiness '{readiness}' is valid" if is_valid else f"Readiness '{readiness}' not in {valid}"))
    else:
        checks.append(make_check("has_verdict", False, "No acceptance verdict found"))

    # Check for checks array
    check_results = safe_get(data, "checks") or safe_get(data, "test_results") or safe_get(data, "acceptance_checks")
    if isinstance(check_results, list):
        checks.append(make_check("has_checks", True, f"Found {len(check_results)} acceptance check(s)"))
    else:
        checks.append(make_check("has_checks", False, "No acceptance checks found"))

    # Check for grade
    grade = safe_get(data, "verdict", "grade") or safe_get(data, "grade")
    if grade is not None:
        checks.append(make_check("has_grade", True, f"Grade: {grade}"))
    else:
        checks.append(make_check("has_grade", False, "No grade found in acceptance report"))

    return checks


def validate_c_consumption(artifacts):
    """C-CONSUMPTION: Validate activity feed artifact."""
    checks = []
    data = artifacts.get("activity_feed")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No activity feed artifact provided"))
        return checks

    checks.append(make_check("artifact_exists", True, "Activity feed artifact found"))

    if not isinstance(data, dict):
        checks.append(make_check("is_dict", False, "Activity feed is not a dict"))
        return checks

    checks.append(make_check("is_dict", True, "Activity feed is a dict"))

    # Check for runs/signals counts
    summary = safe_get(data, "consumption_summary") or safe_get(data, "summary") or data
    total_runs = safe_get(summary, "total_runs", default=0)
    total_signals = safe_get(summary, "total_signals", default=safe_get(summary, "signals_consumed", default=0))

    checks.append(make_check("has_runs", total_runs > 0,
                             f"Total runs: {total_runs}" if total_runs > 0 else "No consumption runs recorded"))
    checks.append(make_check("has_signals", total_signals > 0,
                             f"Total signals consumed: {total_signals}" if total_signals > 0 else "No signals consumed"))

    # Check for error tracking
    errors = safe_get(summary, "total_errors", default=safe_get(summary, "errors", default=None))
    if errors is not None:
        checks.append(make_check("has_error_tracking", True, f"Error tracking present: {errors} errors"))
    else:
        checks.append(make_check("has_error_tracking", False, "No error tracking found"))

    # Check for uptime/streak
    uptime = safe_get(summary, "uptime_pct", default=safe_get(summary, "uptime", default=None))
    streak = safe_get(summary, "consecutive_days", default=safe_get(summary, "streak_days", default=None))
    has_continuity = uptime is not None or streak is not None
    checks.append(make_check("has_continuity", has_continuity,
                             f"Continuity tracking present (uptime={uptime}, streak={streak})" if has_continuity
                             else "No continuity tracking found"))

    return checks


def validate_c_verification(artifacts):
    """C-VERIFICATION: Validate verification report."""
    checks = []
    data = artifacts.get("verification_report")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No verification report artifact provided"))
        return checks

    checks.append(make_check("artifact_exists", True, "Verification report artifact found"))

    if not isinstance(data, dict):
        checks.append(make_check("is_dict", False, "Verification report is not a dict"))
        return checks

    checks.append(make_check("is_dict", True, "Verification report is a dict"))

    # Check for verdict
    verdict = safe_get(data, "verdict") or safe_get(data, "verification_verdict")
    if verdict is not None:
        checks.append(make_check("has_verdict", True, "Verification verdict present"))
        if isinstance(verdict, dict):
            status = verdict.get("status", verdict.get("result", ""))
        else:
            status = str(verdict)
        checks.append(make_check("verdict_status", status in ("VERIFIED", "PASSED", "PARTIAL", "FAILED"),
                                 f"Verdict status: {status}"))
    else:
        checks.append(make_check("has_verdict", False, "No verification verdict found"))

    # Check for attestation
    attestation = safe_get(data, "attestation") or safe_get(data, "dated_attestation")
    checks.append(make_check("has_attestation", attestation is not None,
                             "Dated attestation present" if attestation else "No attestation found"))

    return checks


def validate_c_monitoring(artifacts):
    """C-MONITORING: Validate health report artifact for monitoring."""
    checks = []
    data = artifacts.get("health_report")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No health report artifact provided"))
        return checks

    checks.append(make_check("artifact_exists", True, "Health report artifact found"))

    if not isinstance(data, dict):
        checks.append(make_check("is_dict", False, "Health report is not a dict"))
        return checks

    checks.append(make_check("is_dict", True, "Health report is a dict"))

    # Check for health dimensions
    dimensions = safe_get(data, "dimensions") or safe_get(data, "health_dimensions") or safe_get(data, "scores")
    if dimensions is not None:
        checks.append(make_check("has_dimensions", True, "Health dimensions present"))
        if isinstance(dimensions, (dict, list)):
            count = len(dimensions)
            checks.append(make_check("dimension_count", count >= 4,
                                     f"Found {count} health dimensions" if count >= 4 else f"Only {count} dimensions (expected 4+)"))
    else:
        checks.append(make_check("has_dimensions", False, "No health dimensions found"))

    # Check for composite score
    composite = safe_get(data, "composite_score") or safe_get(data, "overall_score") or safe_get(data, "verdict", "score")
    checks.append(make_check("has_composite", composite is not None,
                             f"Composite score: {composite}" if composite is not None else "No composite score found"))

    # Check for grade
    grade = safe_get(data, "grade") or safe_get(data, "verdict", "grade")
    checks.append(make_check("has_grade", grade is not None,
                             f"Grade: {grade}" if grade else "No grade found"))

    return checks


# ---------------------------------------------------------------------------
# Producer checkpoint validators
# ---------------------------------------------------------------------------
def validate_p_schema(artifacts):
    """P-SCHEMA: Validate signal sample for producer schema compliance."""
    checks = []
    data = artifacts.get("signal_sample")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No signal sample artifact provided"))
        return checks

    checks.append(make_check("artifact_exists", True, "Signal sample artifact found"))

    signals = data if isinstance(data, list) else data.get("signals", [data]) if isinstance(data, dict) else []
    if len(signals) == 0:
        checks.append(make_check("has_signals", False, "No signals in sample"))
        return checks

    checks.append(make_check("has_signals", True, f"Found {len(signals)} signal(s)"))

    # Check required fields in first signal
    required = ["signal_id", "producer_id", "timestamp", "symbol", "direction", "confidence"]
    sig = signals[0] if isinstance(signals[0], dict) else {}
    missing = [f for f in required if f not in sig]
    checks.append(make_check("required_fields", len(missing) == 0,
                             "All required fields present" if not missing else f"Missing: {', '.join(missing)}"))

    # Validate schema version
    sv = sig.get("schema_version", "")
    sv_ok = bool(re.match(r"^\d+\.\d+\.\d+$", str(sv))) if sv else False
    checks.append(make_check("schema_version", sv_ok,
                             f"Schema version: {sv}" if sv_ok else "No valid schema_version"))

    # Symbol format
    symbol = sig.get("symbol", "")
    sym_ok = bool(re.match(r"^[A-Z]{2,10}$", str(symbol)))
    checks.append(make_check("symbol_format", sym_ok,
                             f"Symbol '{symbol}' valid" if sym_ok else f"Symbol '{symbol}' invalid format"))

    return checks


def validate_p_delivery(artifacts):
    """P-DELIVERY: Validate signal delivery cadence."""
    checks = []
    data = artifacts.get("signal_sample")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No signal sample for delivery validation"))
        return checks

    checks.append(make_check("artifact_exists", True, "Signal sample available"))

    signals = data if isinstance(data, list) else data.get("signals", [data]) if isinstance(data, dict) else []

    # Check signal count (need multiple for cadence)
    checks.append(make_check("sufficient_signals", len(signals) >= 2,
                             f"{len(signals)} signals (sufficient for cadence)" if len(signals) >= 2
                             else f"Only {len(signals)} signal(s) — need 2+ for cadence"))

    # Check timestamps present and parseable
    if len(signals) >= 2:
        ts_fields = []
        for s in signals[:10]:  # Check first 10
            if isinstance(s, dict):
                ts = s.get("timestamp", s.get("generated_at", ""))
                ts_fields.append(ts)

        valid_ts = sum(1 for t in ts_fields if t and isinstance(t, str) and len(t) > 10)
        checks.append(make_check("timestamps_valid", valid_ts >= 2,
                                 f"{valid_ts}/{len(ts_fields)} timestamps valid" if valid_ts >= 2
                                 else "Insufficient valid timestamps"))

        # Check for multiple symbols
        symbols = set()
        for s in signals:
            if isinstance(s, dict) and "symbol" in s:
                symbols.add(s["symbol"])
        checks.append(make_check("multi_symbol", len(symbols) >= 2,
                                 f"Delivers {len(symbols)} symbols: {', '.join(sorted(symbols))}" if len(symbols) >= 2
                                 else f"Only {len(symbols)} symbol(s)"))

    return checks


def validate_p_resolution(artifacts):
    """P-RESOLUTION: Validate resolution / proof surface for resolved signals."""
    checks = []
    data = artifacts.get("proof_surface")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No proof surface artifact for resolution validation"))
        return checks

    checks.append(make_check("artifact_exists", True, "Proof surface artifact found"))

    if not isinstance(data, dict):
        checks.append(make_check("is_dict", False, "Proof surface is not a dict"))
        return checks

    checks.append(make_check("is_dict", True, "Proof surface is a dict"))

    # Check for resolved signal counts
    summary = safe_get(data, "summary") or safe_get(data, "resolution_summary") or data
    total = safe_get(summary, "total_signals", default=safe_get(summary, "total_resolved", default=0))
    resolved = safe_get(summary, "resolved", default=safe_get(summary, "resolved_count", default=total))

    checks.append(make_check("has_resolved", resolved > 0,
                             f"Resolved signals: {resolved}" if resolved > 0 else "No resolved signals found"))

    # Check for accuracy/karma
    accuracy = safe_get(summary, "accuracy", default=safe_get(summary, "hit_rate", default=None))
    checks.append(make_check("has_accuracy", accuracy is not None,
                             f"Accuracy: {accuracy}" if accuracy is not None else "No accuracy metric found"))

    karma = safe_get(summary, "karma", default=safe_get(summary, "total_karma", default=None))
    checks.append(make_check("has_karma", karma is not None,
                             f"Karma: {karma}" if karma is not None else "No karma metric found"))

    return checks


def validate_p_proof(artifacts):
    """P-PROOF: Validate proof surface artifact."""
    checks = []
    data = artifacts.get("proof_surface")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No proof surface artifact provided"))
        return checks

    checks.append(make_check("artifact_exists", True, "Proof surface artifact found"))

    if not isinstance(data, dict):
        checks.append(make_check("is_dict", False, "Proof surface is not a dict"))
        return checks

    checks.append(make_check("is_dict", True, "Proof surface is a dict"))

    # Check for content hash
    content_hash = safe_get(data, "content_hash") or safe_get(data, "hash") or safe_get(data, "meta", "content_hash")
    checks.append(make_check("has_hash", content_hash is not None,
                             "Content hash present" if content_hash else "No content hash found"))

    # Check for drift detection / freshness
    freshness = safe_get(data, "freshness") or safe_get(data, "freshness_grade") or safe_get(data, "drift")
    checks.append(make_check("has_freshness", freshness is not None,
                             f"Freshness/drift data present" if freshness else "No freshness/drift data found"))

    # Check for rolling windows
    windows = safe_get(data, "rolling_windows") or safe_get(data, "windows")
    checks.append(make_check("has_windows", windows is not None,
                             "Rolling windows present" if windows else "No rolling windows found"))

    return checks


def validate_p_discovery(artifacts):
    """P-DISCOVERY: Validate producer is discoverable."""
    checks = []
    data = artifacts.get("discovery_result")
    if data is None:
        checks.append(make_check("artifact_exists", False, "No discovery result artifact — producer may not be registered"))
        return checks

    checks.append(make_check("artifact_exists", True, "Discovery result artifact found"))

    if not isinstance(data, dict):
        checks.append(make_check("is_dict", False, "Discovery result is not a dict"))
        return checks

    checks.append(make_check("is_dict", True, "Discovery result is a dict"))

    # Check for producer registration
    producers = data.get("producers", data.get("results", data.get("registry", [])))
    if isinstance(producers, list):
        checks.append(make_check("has_producers", len(producers) > 0,
                                 f"Found {len(producers)} registered producer(s)" if producers else "No producers registered"))
    elif isinstance(producers, dict):
        checks.append(make_check("has_producers", len(producers) > 0,
                                 f"Found {len(producers)} registered producer(s)" if producers else "No producers registered"))
    else:
        checks.append(make_check("has_producers", False, "No producer registry found"))

    # Check for liveness
    liveness = safe_get(data, "liveness") or safe_get(data, "liveness_grade")
    checks.append(make_check("has_liveness", liveness is not None,
                             f"Liveness data present" if liveness else "No liveness grading found"))

    return checks


def validate_p_health(artifacts):
    """P-HEALTH: Validate health report for producer."""
    return validate_c_monitoring(artifacts)  # Same validation logic


def validate_p_trust(artifacts):
    """P-TRUST: Validate trust evaluation for producer."""
    return validate_c_trust(artifacts)  # Same validation logic


def validate_p_activity(artifacts):
    """P-ACTIVITY: Validate activity feed for producer."""
    return validate_c_consumption(artifacts)  # Same validation logic


# ---------------------------------------------------------------------------
# Validator dispatch
# ---------------------------------------------------------------------------
VALIDATORS = {
    "C-DISCOVERY": validate_c_discovery,
    "C-SCHEMA": validate_c_schema,
    "C-ROUTING": validate_c_routing,
    "C-TRUST": validate_c_trust,
    "C-ACCEPTANCE": validate_c_acceptance,
    "C-CONSUMPTION": validate_c_consumption,
    "C-VERIFICATION": validate_c_verification,
    "C-MONITORING": validate_c_monitoring,
    "P-SCHEMA": validate_p_schema,
    "P-DELIVERY": validate_p_delivery,
    "P-RESOLUTION": validate_p_resolution,
    "P-PROOF": validate_p_proof,
    "P-DISCOVERY": validate_p_discovery,
    "P-HEALTH": validate_p_health,
    "P-TRUST": validate_p_trust,
    "P-ACTIVITY": validate_p_activity,
}


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------
def build_report(role, artifacts, previous_hash=None):
    """Build complete pathway report for the given role."""
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%dT%H%M%SZ")
    iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    scan_date = now.strftime("%Y-%m-%d")

    # Select checkpoint definitions
    if role == "CONSUMER":
        defs = copy.deepcopy(CONSUMER_CHECKPOINTS)
    else:
        defs = copy.deepcopy(PRODUCER_CHECKPOINTS)

    # Run validators and build checkpoint results
    checkpoints = []
    status_map = {}  # checkpoint_id -> status

    for cp_def in defs:
        cp_id = cp_def["checkpoint_id"]
        validator = VALIDATORS[cp_id]
        check_results = validator(artifacts)

        total = len(check_results)
        passed = sum(1 for c in check_results if c["passed"])
        failed = total - passed
        pass_rate = passed / total if total > 0 else 0.0

        # Determine status before dependency check
        if total == 0:
            raw_status = "PENDING"
        elif passed == total:
            raw_status = "COMPLETED"
        else:
            # If artifact exists but checks fail, still PENDING (not enough to complete)
            artifact_exists = any(c["check_name"] == "artifact_exists" and c["passed"] for c in check_results)
            raw_status = "PENDING" if artifact_exists else "PENDING"

        status_map[cp_id] = raw_status

        checkpoints.append({
            "checkpoint_id": cp_id,
            "checkpoint_name": cp_def["checkpoint_name"],
            "order": cp_def["order"],
            "status": raw_status,
            "validation": {
                "checks_run": total,
                "checks_passed": passed,
                "checks_failed": failed,
                "pass_rate": round(pass_rate, 4),
                "details": check_results
            },
            "depends_on": cp_def["depends_on"],
            "blocked_by": []
        })

    # Dependency propagation pass
    for cp in checkpoints:
        blocked_by = []
        for dep_id in cp["depends_on"]:
            if status_map.get(dep_id) != "COMPLETED":
                blocked_by.append(dep_id)

        if blocked_by:
            cp["status"] = "BLOCKED"
            cp["blocked_by"] = blocked_by
            status_map[cp["checkpoint_id"]] = "BLOCKED"

    # Progress summary
    completed = sum(1 for cp in checkpoints if cp["status"] == "COMPLETED")
    pending = sum(1 for cp in checkpoints if cp["status"] == "PENDING")
    blocked = sum(1 for cp in checkpoints if cp["status"] == "BLOCKED")
    skipped = sum(1 for cp in checkpoints if cp["status"] == "SKIPPED")
    total = len(checkpoints)
    completion_rate = round(completed / total, 4)
    readiness = compute_readiness(completed, total, blocked > 0)

    progress = {
        "total_checkpoints": total,
        "completed": completed,
        "pending": pending,
        "blocked": blocked,
        "skipped": skipped,
        "completion_rate": completion_rate,
        "readiness": readiness
    }

    # Next steps for non-COMPLETED checkpoints
    next_steps = []
    step_num = 0
    for cp in checkpoints:
        if cp["status"] != "COMPLETED":
            step_num += 1
            cp_id = cp["checkpoint_id"]
            priority = "CRITICAL" if cp["status"] == "PENDING" and cp["order"] <= 2 else \
                       "HIGH" if cp["status"] == "PENDING" else \
                       "MEDIUM" if cp["status"] == "BLOCKED" else "LOW"
            # For BLOCKED items, priority is MEDIUM since deps must be resolved first
            if cp["blocked_by"]:
                priority = "MEDIUM"

            next_steps.append({
                "step_number": step_num,
                "checkpoint_id": cp_id,
                "action": NEXT_STEP_ACTIONS.get(cp_id, f"Complete {cp['checkpoint_name']}"),
                "command": NEXT_STEP_COMMANDS.get(cp_id, f"# See {cp['checkpoint_name']} documentation"),
                "priority": priority
            })

    # Verdict
    grade = score_to_grade(completion_rate)
    if readiness == "READY":
        rationale = f"All {total} checkpoints completed. {role} integration is fully ready."
        recommendation = f"Proceed with production {role.lower()} operations. Continue monitoring health metrics."
    elif readiness == "NEARLY_READY":
        rationale = f"{completed}/{total} checkpoints completed. {total - completed} remaining checkpoint(s) to finish."
        recommendation = f"Complete remaining {total - completed} checkpoint(s): {', '.join(cp['checkpoint_id'] for cp in checkpoints if cp['status'] != 'COMPLETED')}."
    elif readiness == "BLOCKED":
        first_blocked = [cp["checkpoint_id"] for cp in checkpoints if cp["status"] == "BLOCKED"]
        rationale = f"{completed}/{total} checkpoints completed. {blocked} checkpoint(s) blocked by unmet dependencies."
        recommendation = f"Resolve blocking dependencies first. Blocked checkpoints: {', '.join(first_blocked)}."
    elif readiness == "IN_PROGRESS":
        rationale = f"{completed}/{total} checkpoints completed. Integration is in progress."
        recommendation = f"Continue through the pathway in order. Next: {next_steps[0]['checkpoint_id'] if next_steps else 'N/A'}."
    else:
        rationale = f"No checkpoints completed. {role} integration has not started."
        recommendation = f"Begin with the first checkpoint: {defs[0]['checkpoint_id']} ({defs[0]['checkpoint_name']})."

    verdict = {
        "readiness": readiness,
        "grade": grade,
        "completion_rate": completion_rate,
        "rationale": rationale,
        "recommendation": recommendation
    }

    # Build report without hash_chain for content hashing
    report = {
        "scanner_version": SCANNER_VERSION,
        "meta": {
            "report_id": f"PATH-{role}-{ts}",
            "generated_at": iso,
            "generator_version": GENERATOR_VERSION,
            "content_hash": "",  # placeholder
            "role": role,
            "scan_date": scan_date
        },
        "pathway_config": {
            "role": role,
            "checkpoint_count": total,
            "checkpoint_definitions": defs
        },
        "checkpoints": checkpoints,
        "progress_summary": progress,
        "next_steps": next_steps,
        "verdict": verdict,
        "hash_chain": {
            "algorithm": "SHA-256",
            "report_hash": "",
            "previous_report_hash": previous_hash
        },
        "limitations": {
            "count": len(LIMITATIONS),
            "items": copy.deepcopy(LIMITATIONS)
        }
    }

    # Compute content hash (exclude hash_chain, use placeholder for content_hash)
    report["meta"]["content_hash"] = "0" * 64  # stable placeholder
    hashable = {k: v for k, v in report.items() if k != "hash_chain"}
    content_hash = sha256_dict(hashable)
    report["meta"]["content_hash"] = content_hash

    # Report hash (full report including hash_chain)
    report["hash_chain"]["report_hash"] = "0" * 64  # placeholder
    report["hash_chain"]["report_hash"] = sha256_dict(report)

    return report


def print_summary(report):
    """Print human-readable summary to stderr."""
    meta = report["meta"]
    progress = report["progress_summary"]
    verdict = report["verdict"]

    lines = [
        f"Onboarding Pathway Report: {meta['role']}",
        f"Date: {meta['scan_date']}  |  Report ID: {meta['report_id']}",
        f"",
        f"Progress: {progress['completed']}/{progress['total_checkpoints']} checkpoints completed",
        f"  Completed: {progress['completed']}  |  Pending: {progress['pending']}  |  Blocked: {progress['blocked']}  |  Skipped: {progress['skipped']}",
        f"  Completion Rate: {progress['completion_rate']:.1%}",
        f"  Readiness: {progress['readiness']}",
        f"",
        f"Checkpoints:",
    ]

    status_icons = {"COMPLETED": "[OK]", "PENDING": "[..] ", "BLOCKED": "[XX]", "SKIPPED": "[--]"}
    for cp in report["checkpoints"]:
        icon = status_icons.get(cp["status"], "[??]")
        v = cp["validation"]
        blocked = f" (blocked by: {', '.join(cp['blocked_by'])})" if cp["blocked_by"] else ""
        lines.append(f"  {icon} {cp['order']}. {cp['checkpoint_id']}: {cp['checkpoint_name']} "
                     f"({v['checks_passed']}/{v['checks_run']} checks){blocked}")

    lines.extend([
        f"",
        f"Verdict: {verdict['readiness']} (Grade {verdict['grade']}, {verdict['completion_rate']:.1%})",
        f"  {verdict['rationale']}",
        f"  {verdict['recommendation']}",
    ])

    if report["next_steps"]:
        lines.extend([f"", f"Next Steps:"])
        for step in report["next_steps"][:5]:
            lines.append(f"  {step['step_number']}. [{step['priority']}] {step['checkpoint_id']}: {step['action']}")
            lines.append(f"     $ {step['command']}")

    sys.stderr.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Canonical Onboarding Pathway Scanner — scans artifacts to determine integration readiness"
    )
    parser.add_argument("--role", required=True, choices=["CONSUMER", "PRODUCER"],
                        help="Integration role to scan")
    parser.add_argument("--signal-sample", help="Path to signal sample JSON")
    parser.add_argument("--proof-surface", help="Path to proof surface JSON")
    parser.add_argument("--health-report", help="Path to health report JSON")
    parser.add_argument("--trust-eval", help="Path to trust evaluation JSON")
    parser.add_argument("--activity-feed", help="Path to activity feed JSON")
    parser.add_argument("--discovery-result", help="Path to discovery result JSON")
    parser.add_argument("--acceptance-report", help="Path to acceptance report JSON")
    parser.add_argument("--verification-report", help="Path to verification report JSON")
    parser.add_argument("--previous-hash", help="Hash of previous report for chain integrity")
    parser.add_argument("-o", "--output", help="Output file path (default: stdout)")
    parser.add_argument("--json", action="store_true", default=True, help="Output as JSON (default)")
    parser.add_argument("--summary", action="store_true", help="Print human-readable summary to stderr")

    args = parser.parse_args()

    # Load artifacts
    artifacts = {
        "signal_sample": load_json(args.signal_sample),
        "proof_surface": load_json(args.proof_surface),
        "health_report": load_json(args.health_report),
        "trust_eval": load_json(args.trust_eval),
        "activity_feed": load_json(args.activity_feed),
        "discovery_result": load_json(args.discovery_result),
        "acceptance_report": load_json(args.acceptance_report),
        "verification_report": load_json(args.verification_report),
    }

    # Build report
    report = build_report(args.role, artifacts, previous_hash=args.previous_hash)

    # Output
    output_str = json.dumps(report, indent=2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_str + "\n")
        sys.stderr.write(f"Report written to {args.output}\n")
    else:
        print(output_str)

    if args.summary:
        print_summary(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
